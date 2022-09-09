# IPA OAuth2 bridge

IPA OAuth2 bridge is an OAuth2 server implementation that integrates with Kerberos
infrastructure provided by FreeIPA. OAuth2 clients can use their Kerberos credentials
to dynamically register themselves against IPA OAuth bridge.

IPA OAuth2 bridge's primary goal is to enable OAuth2 clients on the systems enrolled
into IPA to delegate authorization and authentication of IPA users to the central authority.
In case IPA users are backed by an external authority, IPA OAuth2 bridge will federate
the task to that authority.

## IPA OAuth2 bridge use cases

IPA OAuth2 bridge is required to enable the following use cases which currently aren't possible within FreeIPA:

- login to IPA Web UI with the following passwordless authentication methods: FIDO2 tokens, external IdP, RADIUS proxy;
- managing FIDO2 tokens to IPA users is not possible in Web UI;
- login to Cockpit and other web-based apps is not possible for IPA user accounts that have enabled passwordless authentication methods and haven't obtained Kerberos credentials in advance;
- for IPA to IPA trust there is a need to handle passwordless authentication methods of the domain to be trusted prior to establishing the trust itself. To make passwordless methods work properly, a bulk of information from the trusted domain's side is required. This information is complex or prone to errors to obtain manually (CA chains, etc.).

OAuth2 IdP integration within IPA is a way to solve all these problems:

- we can provide a standard API to issue tokens to third-party apps (Cockpit, Satellite, etc);
- we can federate to remote IdPs for external IdP and trusted domain users' use cases;
- we can switch IPA Web UI to use OAuth2 APIs to authorize access and move authentication to a single point, same as any third-party apps;
- we can implement exchange of data for IPA-IPA trust establishment as an OAuth2-enabled app.

## IPA OAuth2 client registration

IPA OAuth2 clients can be defined statically by IPA administrators or registered dynamically
with the help of [RFC7591](https://datatracker.ietf.org/doc/html/rfc7591)-compatible flow.
For the latter, the clients have to present an initial access token obtained via a valid
`ipa_session` cookie issued in the name of IPA Kerberos service they represent.

An `ipa_session` cookie can be obtained by negotiating GSS-SPNEGO against
/ipa/session/cookie end-point on IPA server. For example, the following shell
session produces an `ipa_session` cookie with the value starting with
MagBearerToken:

```
     # kinit -k
     # curl -s -c - -u: --negotiate \
           --referer https://`hostname`/ipa \
           https://`hostname`/ipa/session/cookie |\
           grep /ipa | cut -f7-

     MagBearerToken=QblW1NCwF6Wp0hYE9uWagNhYVhIBDA76XpKaUQOLmCyzMnX%2fw1tk2gqB3vvI3J......
```

This cookie then can be URL-quoted and provided as a `client_secret`
parameter in body of the OAuth2 authorization request sent to the same IPA
server:

```
    POST /ipa/oauth/authorize HTTP/1.1
    Host: ipa.example.test
    Content-Type: application/x-www-form-urlencoded

    code=4%2FEi4UjaDc5rNnV2U8Ie8MJVFm-zIQs3ysoQ
    &client_id=host/client.example.test@EXAMPLE.TEST
    &client_secret=<url-quoted-cookie>
    &redirect_uri=https%3A%2F%2Fclient.example.test%3A9090%2Flogin%2F
    &grant_type=authorization_code
```

IPA OAuth bridge would validate client ID, client secret and redirect URI
before proceeding with the authorization request. Redirect URI must be on the
same host that Kerberos principal is issued for. Optionally, a redirect URI
might be set in the Kerberos principal entry.

This approach reduces a security attack surface:

- `ipa_session` cookie is time-limited (default 30 minutes)
- `ipa_session` cookie can only be obtained with the Kerberos keytab in
  possession
- `ipa_session` cookie is encrypted by each IPA server individually and cannot
  be reused against a different IPA server
- client ID is bound to the Kerberos principal inside encrypted (and opaque to
  third parties) cookie
- redirect URI can only point to the same host Kerberos service principal is
  issued for

The obtained access token can be used as an initial access token to dynamically
register OAuth2 client as per [RFC7591] section 3.1.

## Verification of OAuth2 client credentials

The initial client access token will be validated by the OAuth2 client registration endpoint.

Registration endpoint will only accept confidential OAuth clients which use their
Kerberos principal as their client name and a valid `ipa_session` cookie as their
client secret.

Internally IPA OAuth bridge would do a subrequest to `/ipa/session/json` with
`whoami` IPA API command to validate the passed cookie. In case the cookie is
correct, JSON-formatted response will contain details about the principal used
to obtain the cookie:

```bash
    # kinit -k -t /var/lib/ipa/gssproxy/http.keytab HTTP/`hostname`
    # curl -s -c cookie.jar -u: --negotiate --referer https://`hostname`/ipa https://`hostname`/ipa/session/cookie
    # cat whoami.json
    {"id": 0, "method": "whoami/1", "params": [[], {"version": "2.247"}]}
    # curl -b cookie.jar --json @whoami.json --referer https://`hostname`/ipa https://`hostname`/ipa/session/json
    {"result": {"object": "service", "command": "service_show/1", "arguments": ["HTTP/master.ipa.test@IPA.TEST"]},
     "error": null, "id": 0, "principal": "HTTP/master.ipa.test@IPA.TEST", "version": "4.11.0.dev202209061337+git6d6428acf"}
```

Any non-successful answer is considered a failure.

The Kerberos principal returned by the `whoami` command is cross-verified
against OAuth client name specified during the registration. The same will be done
for the object type: only hosts and services would be allowed to perform OAuth2
client registration operations. In addition, the redirect URI, if specified, will
be matched against the Kerberos principal's host component.

## User authorization and authentication

IPA OAuth2 bridge serves as a generic login page for OAuth2-enabled web
applications in IPA deployment. The bridge would display a login page for the
user and ask it to authenticate. For users with authentication information
present in IPA, internal Kerberos authentication would be performed. For users
with authentication information in external IdP a federation request to an
external IdP would be performed.

## External IdP support

For users registered with an external IdP, IPA OAuth2 bridge would issue a
separate OAuth2 authorization grant flow request against that external IdP.

A current-in-process authorization request is stored along with a state
indicator that should include current IPA server name.

Upon completion of the request, external IdP would redirect the user's browser
back to an URI associated with IPA OAuth client registered with external IdP.

This redirect would be a generic one and any IPA server might respond to it,
not only the original IPA server. It means there should be a mechanism to allow
one IPA server to redirect the user's browser to the original IPA server if
required. This will be done by embedding a reference to the original IPA server
in the `state` value of the authorization request issued by the original IPA
server. An IPA server receiving the redirect would re-issue it to the original
IPA server by parsing the state variable.

On the original IPA server a state is parsed and a current-in-process
authorization request is picked up from the local store. A result of the
authorization against an external IdP is analyzed. A token end-point request is
issued against an external IdP to retrieve an access token and do a final
comparison of the registered user identity.

## Access token issuance

When all checks performed as a part of IPA OAuth authorization end-point done,
a final HTTP redirect is issued back to the original OAuth application running on
IPA client. The data returned will contain an authorization code generated by
the IPA OAuth bridge which then can be used by the OAuth application to request
an access token against the same server.

No refresh token support is provided.

Access token would contain information associated with a user as known by IPA
server.


## Implementation details

`python-oauthlib` package can be used to handle the bulk of implementation of OAuth2 spec.
It provides server side classes that need to be extended with an implementation of
a data storage and processing of the OAuth clients/tokens. The database itself can be
separate from IPA LDAP datastore used for Kerberos principals. IPA integrated custodia
mechanism can be used to request exchange of the OAuth2 client data across IPA replicas.

One fundamental problem we need to solve is the appearance of a single frontend view exposed
by OAuth2 parties. OAuth2 authorization grant flow assumes that an OAuth2 client has a fixed
frontend URI registered with the OAuth2 authorization server and after successful authentication
of the user and successful granting of the access to user’s data to this OAuth2 client, a redirect
is performed to the known URL registered with the client.

For OAuth2 federation IPA OAuth2 bridge itself will be an OAuth2 client to that external OAuth2 IdP.
It means we have to have a single URL to redirect back to us and at that point we have to be able
to find out which original IPA OAuth2 bridge server initiated this request, to redirect back to it,
to redirect back to the original OAuth2 client. This is all needed to avoid sharing OAuth2 tokens
information across all IPA OAuth2 servers as otherwise OAuth2 bridge will be required to create a
near-instant replication of those tokens. The latter is hard and would inevitably force to add more
databases and replication as we cannot rely on LDAP replication here.

Eventually all IPA servers will be the OAuth2 authorization servers and will issue OAuth2 tokens
that can be used to grant access to user data. These tokens need to be accepted by all IPA servers.
Without a distributed DB that can be queried by all IPA servers, we have to find out a way to turn
tokens into information we can validate properly. Use of mod_auth_gssapi-produced cookie (with a
common session key) that backs the OAuth2 token internally could help here. However, validating the
presented OAuth2 token remains somewhat problematic unless we can quickly find out what cookie backs it.

An implementation could start with a single OAuth server (one IPA server), using standard IPA
mod_auth_gssapi-protected endpoint to gather the cookie and store this cookie in a sqlite database locally.
