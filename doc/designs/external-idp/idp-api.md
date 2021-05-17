# IPA and an external identity provider integration - idp objects

[TOC]

IPA needs to store and manage IdP references. This includes the following
tasks:
* creation of an LDAP object class and LDAP attribute types used to store IdP
information
* creation of a new IPA API managing the IdP references
* definition of access control lists protecting access to the IdP references
* upgrade and backward compatibility

## LDAP Schema

### New attribute types

The idp object needs to contain the following information:
* name (string)
* device authorization endpoint (URI mapped as a case-sensitive string),
for instance https://oauth2.googleapis.com/device/code
* token endpoint (URI mapped as a case-sensitive string),
for instance https://oauth2.googleapis.com/token
* client_id (case-sensitive string)
* client_secret (optional, may be an empty string, must be protected as
a password)
* scope (case sensitive string)

This translates into the following attribute type definitions:
```text
attributeTypes: (2.16.840.1.113730.3.8.23.15 NAME 'ipaIdpAuthEndpoint' DESC 'Identity Provider Device Authorization Endpoint' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.16 NAME 'ipaIdpTokenEndpoint' DESC 'Identity Provider Token Endpoint' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.17 NAME 'ipaIdpClientId' DESC 'Identity Provider Client Identifier' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.18 NAME 'ipaIdpClientSecret' DESC 'Identity Provider Client Secret' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.19 NAME 'ipaIdpScope' DESC 'Identity Provider Scope' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
```

### New objectclass for idp

```text
objectClasses: (2.16.840.1.113730.3.8.24.6 NAME 'ipaIdP' SUP top STRUCTURAL DESC 'Identity Provider Configuration' MUST ( cn $ ipaIdpAuthEndpoint $ ipaIdpTokenEndpoint $ ipaIdpClientId) MAY ( ipaIdpClientSecret $ ipaIdpScope ) X-ORIGIN 'IPA v4.9' )
```

### LDAP indices

Indices need to be defined for all the attributes that can be used in
`ipa idp-find` command.
- The `cn` attribute is already indexed.
- The `ipaidpauthendpoint`, `idaidptokenendpoint` and `idpidpscope` attributes
need indices (equality and substring indices).


## IdP reference API

### Command Line Interface
```
 idp-add   Add new external IdP server.
 idp-del   Delete an external IdP server.
 idp-find  Search for external IdP servers.
 idp-mod   Modify an external IdP server.
 idp-show  Display information about an external IdP server.
```

Common options:
* NAME: the name of the External IdP, will be used as cn
* --client_id=ID: client identifier issued to IPA by the IdP during its
registration
* --secret: Prompt to set the client secret
* --auth-uri=URI: device authorization endpoint
* --token-uri=URI: token endpoint
* --scope=SCOPE: scope of the access request
* --provider=PROVIDER: one of [google,github,microsoft]

In order to ease the creation of idp, IPA can pre-populate a set of
well-known IdP so that the user does not need to provide the device
authorization endpoint and token endpoint.
For instance, for google:
```
ipa idp-add MyGoogleIdP --provider google --client_id nZ8JDrV8Hklf3JumewRl2ke3ovPZn5Ho --scope "profile email"
```
would be equivalent to calling
```
ipa idp-add MyGoogleIdP --auth-uri https://oauth2.googleapis.com/device/code --token-uri https://oauth2.googleapis.com/token --client_id nZ8JDrV8Hklf3JumewRl2ke3ovPZn5Ho --scope "profile email"
```

As a consequence, the options --provider and --auth-uri|--token-uri are
mutually exclusive, and either --provider or --auth-uri --token-uri must be
provided.

The scope is optional, and the client_id is mandatory.
The client_secret must not be displayed by idp-find or idp-show
commands.

List of pre-populated idp types:
* google (https://oauth2.googleapis.com/device/code and https://oauth2.googleapis.com/token)
* github (https://github.com/login/device and https://github.com/login/oauth/access_token)
* microsoft-common (https://login.microsoftonline.com/common/oauth2/v2.0/devicecode and https://login.microsoftonline.com/common/oauth2/v2.0/token)
* microsoft-consumer (https://login.microsoftonline.com/consumer/oauth2/v2.0/devicecode and https://login.microsoftonline.com/consumer/oauth2/v2.0/token)
* microsoft-organizations (https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode and https://login.microsoftonline.com/organizations/oauth2/v2.0/token)
* ...


### WebUI

The IdP objects need to be accessible in the WebUI. A new tab for
IdP will be created in the "Authentication" section, similar to
the existing _RADIUS servers_ tab. It will contain a table with the
list of IdP objects, enabling to add or delete an object.
Each object must be clickable in order to be edited.

In the _settings_ page for IdP objects, all the properties must be editable
but the client secret must not be displayed.
In order to change the client secret, the admin will click on
_Actions:Reset secret_.

## Access control

Specific permissions need to be created to protect access to the IdP objects:
* System: Add External IdP
* System: Read External IdP (does not provide access to the client secret)
* System: Modify External IdP
* System: Delete External IdP
* System: Read External IdP client secret

Specific Privileges:
* External IdP Administrator: all the permissions related to external idp
except _System: Read External IdP client secret_

Any user who is a member of the admins group will be able to manage the
Idp objects.

## Upgrade and backward compatibility

As the new object class and attribute types are added in the LDAP schema, there
is no need for a specific upgrade task.
Upon normal upgrade, the new schema is applied and replicated to the other
servers, even if they are installed with a version which does not define the
new object class / attribute types.

In a mixed topology containing old and new servers, the new API is provided
only by the new servers.
