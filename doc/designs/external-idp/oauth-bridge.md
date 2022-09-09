IPA OAuth bridge is an OAuth2 end-point to authorize IPA users for OAuth
applications which already represented in IPA as Kerberos services. In case IPA
users have their authentication handled by an external IdP, IPA OAuth bridge
performs a federation to an external IdP and relays authorization request to IPA
OAuth clients.

IPA OAuth clients are confidential OAuth2 clients and should use OAuth2
Authorization Grant Flow. The clients have no explicit client secret registered
with IPA system. Instead, a confidential client would demonstrate a valid
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

Verification of OAuth client credentials
----------------------------------------

IPA OAuth bridge only accepts confidential OAuth clients which use their
Kerberos principal as their client ID and a valid `ipa_session` cookie as their
client secret.

Internally IPA OAuth bridge would do a subrequest to /ipa/session/json with
`whoami` IPA API command to validate the passed cookie. In case the cookie is
correct, JSON-formatted response will contain details about the principal used to obtain the cookie:

```
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
against OAuth client ID. The same will be done for the object type: only hosts
and services would be allowed to perform OAuth operations. In addition,
redirect URI, if specified, will be matched against the Kerberos principal's
host component.

User authorization and authentication
-------------------------------------

IPA OAuth bridge serves as a generic login page for OAuth2-enabled web
applications in IPA deployment. The bridge would display a login page for the
user and ask it to authenticate. For users with authentication information
present in IPA, internal Kerberos authentication would be performed. For users
with authentication information in external IdP a federation request to an
external IdP would be performed.

External IdP support
--------------------

For users registered with an external IdP, IPA OAuth bridge would issue a
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

Access token issuance
---------------------

When all checks performed as a part of IPA OAuth authorization end-point done,
a final HTTP redirect is issued back to the original OAuth application running on
IPA client. The data returned will contain an authorization code generated by
the IPA OAuth bridge which then can be used by the OAuth application to request
an access token against the same server.

No refresh token support is provided.

Access token would contain information associated with a user as known by IPA
server.


