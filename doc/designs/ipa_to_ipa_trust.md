# Create trust between separate IPA deployments

## Overview

FreeIPA provides a way to deploy centrally managed environments where users and
groups can be used to allow access to machines enrolled in the same
environment. Individual applications are hosted on these enrolled machines and
can have Kerberos principals, TLS certificates and other resources associated
with them. HBAC rules can be used to define authorization to access those
applications that use PAM stack. SUDO is one of those applications.  SUDO rules
can be defined to allow transition and execution of individual commands across
multiple sessions for users across those machines.

FreeIPA allows integration with Active Directory environments. The integration
process forms a so-called ‘trust’ relationship: IPA servers trust
authentication decisions made by Active Directory domain controllers of the
trusted forest while those domain controllers allow IPA servers to look up
identity information present in Active Directory. As a result, IPA servers can
also add AD users and groups to local HBAC and SUDO rules and those AD users
can login to machines enrolled in IPA deployment. Kerberos authentication plays
a key role in the trust to Active Directory implementation.

There is no similar solution for two independently deployed IPA environments.
The purpose of this design is to define a way to have two separate IPA
environments to trust each other and provide at least similar level of
functionality as the one existing with Active Directory.


## High level expectations

The aim with trust between two IPA deployments is for it to behave similarly to
trust to Active Directory in day to day operations. As IPA itself provides a
wider feature set than Active Directory in many areas that matter for Linux
systems, we have to take care of more details. However, overall experience
would be similar: once trust is established, users and groups from trusted IPA
deployments will be resolved on the systems belonging to the trusting IPA
deployment, while SUDO and HBAC rules can reference those users and groups
similarly to users and groups from trusted Active Directory forests.


## High level requirements

As IPA deployment A administrator, I would like to be able to establish trust
with another IPA deployment B so that:

* Users from IPA deployment B can be resolved on the machines enrolled in the IPA deployment A by SSSD
* Groups from IPA deployment B can be resolved on the machines enrolled in the IPA deployment A by SSSD
* Users from IPA deployment B can be added to external groups in the IPA deployment A via IPA API
* Groups from IPA deployment B can be added to external groups in the IPA deployment A via IPA API
* Users from IPA deployment B can be added to ID overrides in the IPA deployment A via IPA API
* Groups from IPA deployment B can be added to ID overrides in the IPA deployment A via IPA API
* Users from IPA deployment B can use Kerberos tickets to authenticate to services in the IPA deployment A
* Users from IPA deployment B can manage resources in the IPA deployment A via IPA API

When establishing trust between IPA deployments, the following details should
be taken care of:

* Creating trust information should work with a type of authentication employed
  by the IPA deployment B if this type is supported by the Kerberos
  infrastructure in the IPA deployment A. Namely, passwordless authentication
  methods should be usable for admin users on both sides.
* Information about the IPA deployment B should be discovered automatically given access to the environment with administrative privileges
    * CA chain from IPA deployment B should be made available to IPA deployment
      A to allow secure TLS connections and PKINIT operations
    * ID ranges from IPA deployment B should be made available to IPA
      deployment A to allow selection and filtering at the trust creation time
* It should be possible to establish bi-directional and single-directional trusts.


## High level design

Trust between two IPA deployments will rely on the infrastructure built for
establishing trust between IPA and Active Directory. Key points of this
infrastructure are:

* LDAP server which stores users and groups, along with the details required for MS-PAC issuance
* SSSD daemon with two separate modes for IPA client and IPA server operations
* SSSD support for a set of trusted domains being presented as ‘subdomains’ of the primary IPA domain
* Custom LDAP control to relay user/group resolution requests from SSSD on IPA client to SSSD on IPA server
* Kerberos KDC with ability to issue MS-PAC authorization data in Kerberos tickets

Additionally, in trust between IPA and Active Directory deployments Samba is
utilized to provide DCE RPC services expected by the Active Directory domain
controllers. Since IPA environments don’t require use of DCE RPC services for
their operations, trust between two IPA environments will not require presence
and configuration of Samba as a domain controller on an IPA server.


### LDAP server

IPA utilizes LDAP server to store all information about users, groups,
machines, and other objects presented in IPA environments. LDAP server is
present on each IPA server and the information is replicated across them. IPA
associates a number of attributes with each account, including security
identifier (SID) and POSIX attributes.

Each IPA LDAP server runs the same base set of plugins that, altogether,
implement semantics expected by the SSSD IPA provider. One of these plugins,
ipa-pwd-extop, is used to relay user/group resolution requests between SSSD on
an IPA client and SSSD on an IPA server. When a client needs to resolve a user
or group information from the trusted domain, SSSD will issue an LDAP request
to the IPA LDAP server. This LDAP search has special control operation
information that allows relaying the request to a SSSD instance running on the
IPA server. In turn, an SSSD instance on the IPA server will perform an LDAP
lookup against one of the domain controllers of the trusted domain in question.
Returned information is then relayed back to the LDAP client (SSSD on the IPA
client).


### SSSD on the IPA server

SSSD on the IPA server uses trusted domain object credentials to authenticate
to the domain controllers in a trusted domain. A trusted domain object (TDO)
effectively is an object in the trusted domain that has enough rights to query
information about users and groups. Access to TDO object’s credentials is
protected and is only given to SSSD on the IPA servers via their host object
principals.

Each trusted domain is represented by the SSSD as a subdomain of the primary
IPA domain. This mechanism allows a uniform presentation of all trust
agreements regardless of their type. Both trust to Active Directory and trust
to other IPA deployments will be seen as separate ‘subdomains’ because each
individual IPA or Active Directory deployment has a unique domain suffix.

SSSD presentation of the ‘subdomains’ of the primary IPA domain will need to
change. Currently, SSSD assumes only Active Directory trusts can be represented
as subdomains of the primary IPA domain. This means the internal structure of
that subdomain is always considered the same and is tied to the internal LDAP
schema and directory information tree (DIT) structure of the Active Directory.
In order to represent both AD and IPA subdomains, SSSD code needs to be
modified.

### Kerberos KDC

Kerberos KDC is responsible for issuing tickets. For communication between two
trusted domains, a set of Kerberos principals is created on both sides. These
Kerberos principals have the form of
krbtgt/[TRUSTED.REALM@TRUSTING.REALM](mailto:TRUSTED.REALM@TRUSTING.REALM)
(with TRUSTING.REALM and TRUSTED.REALM interchanged on both sides). A trusted
realm’s domain controller issues a cross-realm ticket granting ticket (TGT)
using this Kerberos principal. Since the principals exist on both sides with
the same key, the resulting ticket can be decrypted by the trusting realm’s
domain controller.

IPA Kerberos KDC performs a number of consistency checks over Kerberos tickets
issued by the trusted realm’s domain controllers. For Active Directory trust, a
requirement is that Kerberos tickets contain MS-PAC authorization data
information. The MS-PAC details allow to match properly both Kerberos and
identity information between POSIX and non-POSIX (Active Directory)
environments.

For the trust between two IPA deployments, the same approach will be taken. IPA
deployments also associate additional identity information with each Kerberos
principal and issues MS-PAC authorization data in the tickets. As a result, no
changes needed to be done to handle trust between two IPA deployments at
Kerberos level in comparison to trust between IPA and Active Directory forests.

### Trust establishment process

#### Active Directory case

For a trust between IPA and Active Directory deployments, IPA servers must run
enough compatible services so that Active Directory domain controllers can
communicate with them as with domain controllers of an Active Directory
deployment. Since IPA LDAP schema and DIT are different from Active Directory,
it was not possible to expose the LDAP server directly to Active Directory.
Instead, a path to represent IPA deployment as a separate Active Directory
forest was chosen. Together with focus on the one-way trust this allowed to
dramatically reduce a need for compatibility in required domain controller
services. IPA servers only need to run Samba to handle DCE RPC services on top
of existing IPA services.

For a trust to an Active Directory forest, only operations over DCE RPC,
authenticated with Kerberos tickets, are required. This also simplified the
process of establishing the trust between IPA and Active Directory. Since
Active Directory LDAP servers support authentication with GSSAPI Kerberos
mechanism with full encryption and data verification, no need to enforce TLS
certificates during the trust establishment process was also required.

#### IPA to IPA case

Contrary to that, use of IPA API is required to communicate with a
trusted-to-be IPA domain controller. IPA API is available over HTTPS end-point
and requires two artifacts:

* TLS certificate chain, in order to verify and trust the remote end-point and
  to be able to handle Kerberos FAST channel against the remote Kerberos KDCs

* Successful authentication as a remote IPA deployment’s user allowed to
  perform administrative operations

To perform authentication as a remote IPA deployment’s user against that remote
IPA domain controller, either the user's password or its active Kerberos ticket
is needed. A system in question also needs to be able to communicate with
remote Kerberos KDC from the remote IPA realm.

FreeIPA provides a number of passwordless authentication methods through
Kerberos: OTP, RADIUS, external IdP authentication, FIDO2 passkeys, and smart
card authentication (PKINIT). All methods but the PKINIT one require use of an
existing Kerberos ticket to create a FAST channel. Typically, either a machine
account credential or an Anonymous PKINIT service is used for this purpose. If
Kerberos realms aren’t trusting each other yet, one cannot reuse the existing
own realm’s PKINIT infrastructure to obtain a local FAST channel.


