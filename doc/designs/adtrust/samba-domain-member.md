TODO: rewrite as a proper design page. See below the notes for a starting part
of the design document.

## Notes about Samba domain member work

Samba domain member is currently not supported in IPA domain. I'm working on
making that possible and have a number of patches developed so far but I need
to get them rearranged into a shape acceptable for upstream contribution. Even
running samba shares on IPA master is limited right now as you can see from the
list below.

See https://lists.samba.org/archive/samba-technical/2018-November/131274.html
for one part that should explain failures with 'did we join?' message in the
logs.

There are more issues I'm tracking. Below is the current list, most of
the entries on it are still open.

- We need to create cifs/... principal in a particular way
  - has to be a posix account to get recognized by SSSD when Samba on
    IPA DC asks for a user with this name (cifs/...)
  - needs to have SID assigned
  - needs to have uid set to NetBIOS name of the machine to allow Samba
    use NAME$ to request a TGT

- We need add ACI to cn=services,cn=accounts,$BASEDN to allow SSSD to
  look up posix account information about this machine account
  (cifs/...) when Samba on IPA DC asks for a user with this name.

  Perhaps, allowing a read,search,compare to IPA DC is enough unless we
  want to allow machine accounts to login into SMB services on IPA
  clients

- We need to solve an issue with netr_ServerAuthenticate3 requiring
  access to the machine account of the IPA client SMB service on IPA DC
  to complete the call:

[2018/12/30 23:17:09.063754,  0, pid=694, effective(1536000104, 1536000104), real(1536000104, 0), class=rpc_srv] ../source3/rpc_server/netlogon/srv_netlog_nt.c:989(_netr_ServerAuthenticate3)
  _netr_ServerAuthenticate3: failed to get machine password for account RAUP$: NT_STATUS_NONE_MAPPED

- first, SMB service has to have uid:RAUP$ in addition to uid:cifs/...
  - second, we need to fix ipasam (below)
  - domain computers (RID 515) need to be mapped to a group?

 - fix ipasam:
  [x] - init_sam_from_ldap() should differentiate flags for accounts
  between ACB_NORMAL and ACB_WSTRUST for machine account

  [x] - init_sam_from_ldap() should be smarter for multi-valued 'uid'
  (should pick one with $ for machine account)

  [x] - add getsampwsid() callback to look up an entry by SID

  - ipaNTHash regen fails with UNWILLING_TO_PERFORM when asked to
    generate ipaNTHash of a machine account even if it is already a
    kerberos service due to lack of RC4 keys in Kerberos (see below)

 - RC4 support in Kerberos on IPA DC and IPA clients
   - By default new Fedora crypto policy disables RC4 use in Kerberos
   - For IPA DC and IPA clients running Samba it has to be re-enabled to
     allow retrieval of NT hashes from Kerberos hashes on demand.
     Alternative is to use negative enctype IDs on both client
     (ipa-getkeytab and ipasam) and server (IPA KDB and ipa-pwdextop) to
     communicate a need to use RC4 while not allowing RC4 to be
     available in Kerberos tickets. cifs/.. principals must have an RC4
     material available for netr_ServerAuthenticate3 to work because
     domain member communication to domain controller is using RC4 of
     the shared secret derivation in 'MS-NRPC 3.1.4.3.1 AES Session-Key'

 - Samba DCE RPC client calls for LSA pipe with Kerberos are done
   against host/IPA DC@REALM. This is hard-coded in IDL definitions and
   thus Samba DCE RPC services need access to host/.. principal. Since
   they are running under root, gssproxy is not an option.

 - Samba needs to implement 'net ads offlinejoin' call to allow setting
   up a machine account and SID without actually joining the machine via
   DCE RPC (for IPA or VAS or other join types).

 - SMB attributes added to IPA users aren't readable because ACI needs to be
   added to allow reading them

 - SMB attributes need to be shown in Web UI only if the user has
   ipaNTSecurityIdentifier attribute set on the object


# Support Samba as a domain member on IPA client

## Introduction

[Samba] is a free software that implements various aspects of SMB protocol and
Active Directory infrastructure. Apart from the networking file system that SMB
is well known for, Samba provides services to resolve user and group identities
for resources accessible via SMB. SMB protocol identity model is based on a
Windows NT concept of security identifiers (SIDs) and access control lists
(ACLs) which is not directly compatible with a concept of identities employed
in POSIX environment model. Thus, Samba suite does serve as a translation layer
between the two environments.

Active Directory is an extension of Windows NT identity model where identity
information is stored in a database exposed to the world via a combination of
LDAP and SMB protocols, with authentication provided with both password
(NTLMSSP) and Kerberos methods. Systems in Active Directory are organized into
logical groups, domains, where some nodes, domain controllers, are used to
store domain-specific information and others, domain members, are utilizing the
information via SMB, LDAP, and Kerberos protocols.

SMB protocol has a mechanism for encapsulating and channeling through itself
other types of requests, expressed as an access to "files" over a specialized
share `IPC$`. There are multiple interfaces provided by a typical domain
controller and domain member servers, most well-known ones are LSA (local
security authority, documented in [MS-LSAD] and [MS-LSAT]) and NETLOGON remote
protocol (documented in [MS-NRPC]). LSA remote procedure calls are used, among
other needs, for retrieving identity information about SIDs and their
relationship to other objects. NETLOGON, as its name suggests, is utilized for
authentication in a domain environment, across domains, and across forests of
domains.

In a traditional domain member set up, the member machine has no possession of
a particular user credentials. Instead, it relies on its own connection to its
own domain controller to identify a user and to proxy a user's authentication
to the domain controller of the domain a user belongs to. In case a user is
performing a remote authentication using Kerberos, a remote system has to
present a Kerberos ticket to the domain member's SMB service, like with any
other Kerberos services.

To operate as a domain member in a FreeIPA domain, thus, Samba needs a FreeIPA
master to be configured as a domain controller and a FreeIPA client needs to be
configured in a specific way to allow Samba to talk to a domain controller.
This document overviews a set of implementation tasks to achieve the domain
member operation. Most of these tasks are related to FreeIPA components but
some of changes required do belong to Samba itself.

## Domain member configuration overview

Samba suite, when running as a domain member, starts two daemons:

- `smbd`, the main process which handles network connections, file system
  operations, and remote procedure calls like LSA and NETLOGON. Each connection
is handled by a separate `smbd` child;

- `winbindd`, a process to perform identity resolution for all configured and
  known domains. Each domain is handled by a separate `winbindd` child.
`winbindd` processes connect to domain controllers and perform required LSA and
NETLOGON operations against them.

Both `smbd` and `winbindd` daemons rely on a number of pluggable components to
abstract out various aspects of their operations. For `smbd`, there are
pluggable modules to represent file system operations. It also uses so-called
PASSDB interface to convert SIDs to POSIX identities and back --- this
interface might be optional on a domain member. In some special cases `smbd`
also directly resolves a name of a user associated with the authenticated
connection using standard POSIX API for name resolution (getpwnam() and similar
calls). All other identity resolution operations it delegates to `winbindd`.

`winbindd` uses a set of identity mapping modules collectively called 'idmap
modules' in Samba terminology. Each `idmap` module represents a strategy to map
SIDs to corresponding POSIX IDs. Since SID name space in Active Directory is
common for all kind of objects and POSIX ID name space is separate for users
and groups, with both POSIX ID name spaces being smaller than a common SID name
space, there exist multiple approaches to perform the translation. A choice of
a translation method is tightly connected with a specific deployment
configuration. ID mapping module should be coordinated with a PASSDB module (if
one is defined) and with the way how an operating system represents the POSIX
users and groups.

To communicate with its domain controller, Samba needs to know own machine
account information. Machine account is an account in Active Directory has its
name derived from a NetBIOS machine name (due to Windows NT past) post-fixed
with a `$` sign, e.g. `MY-MACHINE$`. Password for the machine account is the
same as the one used to derive Kerberos keys for the `host/..` and `cifs/..`
principals of the same host. In Active Directory all Kerberos principals
associated with the host (service principal names, SPNs) share the same
Kerberos keys. Thus, Samba needs to known a clear text password for the machine
account and it can derive all Kerberos keys for itself based on that knowledge.

The knowledge of the machine account password is recorded in a special
database, `secrets.tdb`, during the process of a machine join to the domain.
For FreeIPA client the join process is different from the one Samba uses for
Active Directory, thus we need to seed the machine account password separately
to enrolling FreeIPA client. Note that FreeIPA machine enrollment does not
allow to share clear text machine account password as it is not recorded
anywhere.



## Domain controller side configuration overview

FreeIPA master can be configured to perform as a 'trust controller' with the
help of `ipa-adtrust-intall` tool. The tool creates required subtrees and
objects in LDAP, configures Samba to use an `ipasam` PASSDB module which knows
how to deal with FreeIPA LDAP schema for Samba-specific attributes and supports
storing and retrieving information about trusted domains from LDAP. The tool
also makes sure certain 389-ds plugins provided by FreeIPA are enabled and
initialized.

As a result of the configuration, Samba considers itself a domain controller
for a traditional (Windows NT) domain type. Such traditional domain controller
is not capable to serve as a fully-fledged Active Directory domain controller
due to few important limitations:

- Samba traditional domain controller role is not implementing AD DC itself

- LDAP schema used by FreeIPA is different from Active Directory LDAP schema

- LDAP directory information tree (DIT) is different from what Active Directory
  clients expect from an AD DC

- No Global Catalog service is provided

Additionally, `ipasam` PASSDB module is not capable to create machine accounts
for requests coming from Samba. This means `net rpc join` will not work when
issued from FreeIPA domain members. Also, traditional (Windows NT) domain
controller role in Samba is not able to create machine accounts on request from
`net ads join`, a procedure to join machine to an Active Directory.

The limitations above are fine for FreeIPA environment because FreeIPA clients
perform its own enrollment process via IPA API and a special LDAP control
extension.

When a domain member establishes a secure channel connection to a domain
controller, following is considered on the domain controller side:

- DCE RPC connection is negotiated and authenticated. As part of
  authentication, either NTLMSSP or Kerberos token is processed and converted
into a local NT token.

- Local NT token represents a remote user (machine account) on the domain
  controller. The information includes POSIX attributes as well as NT
attributes since Samba will spawn a process to handle the connection under
local POSIX user identity. Each machine account, thus, requires associated
POSIX attributes.


## Changes required on domain member

## Changes required on domain controller

### Changes to FreeIPA framework

### Changes to LDAP storage

### Changes to LDAP plugins

### Changes to Kerberos KDC driver

### Changes to Samba PASSDB driver


[Samba]: https://www.samba.org/
[MS-NRPC]: https://msdn.microsoft.com/en-us/library/cc237008.aspx
[MS-LSAD]: https://msdn.microsoft.com/en-us/library/cc234225.aspx
[MS-LSAT]: https://msdn.microsoft.com/en-us/library/cc234420.aspx


Supporting material:

Configuring Samba on FreeIPA client
====

Depending on how new is your FreeIPA client, there are simple and not so simple
ways to configure Samba file server on FreeIPA client. In practice, on recent
RHEL 7.5+ or CentOS and Fedora one can use the following guide. These
instructions should work for Samba 4.8.2+ and 4.9+.

0. Make sure at least one of your IPA masters is configured as a trust
   controller using ipa-adtrust-install. This is required to enable a hybrid
   SMB domain where a domain controller would understand Samba domain members
   enrolled via IPA tools but will not be able to enroll them any other way.

1. Enroll a host to IPA, make sure you are doing this with a fully-qualified
   hostname. Below let's assume that IPA's kerberos realm is IPA.REALM and its
   NetBIOS name is 'IPA'.

2. Next steps should be performed on the client itself. I'm using here
   credentials of the host (`host/<hostname>`) because they have enough default
   privileges to achieve what we need:

3. Add and retrieve a Kerberos key for `cifs/<hostname>` service using
   pre-defined password for the key. Remember the password, we'll need it later
   for Samba:

```
# kinit -k
# ipa service-add cifs/<hostname>
# ipa-getkeytab -p cifs/<hostname> -k /etc/samba/samba.keytab -P
```

4. Retrieve information about Security Identifier and NetBIOS name of the IPA
   domain:

```
# kinit -k
# ipa trustconfig-show --raw
  cn: ipa.realm
  ipantsecurityidentifier: S-1-5-21-570121326-3336757064-1157332047
  ipantflatname: ipa
  ipantdomainguid: be06e132-876a-4f9c-aed4-ef2dc1de8118
  ipantfallbackprimarygroup: cn=Default SMB Group,cn=groups,cn=accounts,dc=ipa,dc=realm
```

In the output above, `cn` value is our IPA.REALM (in lower case),
`ipantsecurityidentifier` is our IPA domain's SID (security identifier),
`ipaflatname` is our domain's NetBIOS name (flat name in Active Directory).
Below I refer to these values by their LDAP attribute names (like `${cn}`), you
need to substitute the names by actual values.

5. Retrieve ID range information for the IPA domain:

```
# ipa idrange-show ${cn}_id_range --raw
  cn: IPA.REALM_id_range
  ipabaseid: 1536000000
  ipaidrangesize: 200000
  ipabaserid: 1000
  ipasecondarybaserid: 100000000
  iparangetype: ipa-local
```

From this output we are interested in `ipabaseid` and `ipaidrangesize`, these
are the values that you'd need to use when defining ranges for Samba
configuration. Samba requires to have IDMAP ranges set for specific domains,
more on that later.

6. Create samba config as /etc/samba/smb.conf on the client:

```
# Global parameters
[global]
	dedicated keytab file = FILE:/etc/samba/samba.keytab
	kerberos method = dedicated keytab
	log file = /var/log/samba/log.%m
	realm = IPA.REALM
	server role = member server
	workgroup = IPA
	idmap config IPA : range = 1536000000-1536200000
	idmap config IPA : backend = sss
	idmap config * : range = 10000-20000
	idmap config * : backend = tdb
```

In the config above we defined two IDMAP configurations:
* for IPA domain we used range from `ipabaseid` to `ipabaseid + ipaidrangesize`
  and said that this range is served by SSSD, using `idmap_sss` module.
  `idmap_sss` module is provided by `sssd-winbind-idmap` package.

* for all unknown domains we use local 'tdb' IDMAP backend and a range that
  doesn't conflict with our IPA domain. In fact, this has to be choosen
  carefully, especially if your IPA setup already integrates with Active
  Directory and you have other ranges defined for AD domains. In such case you'll
  need to define separate `idmap config FOO : range` and `idmap config FOO :
  backend` options per each AD domain that is served through IPA the same way as
  we defined them for `idmap config IPA`. The values there should come from the
  corresponding ID ranges for AD domains.

7. Defining access to specific shares can be done with a normal Samba `write
   list` option. An example below grants access to share `shared` to everyone
in IPA `admins` group. The group membership resolution will be done by SSSD. It
is recommended to use POSIX ACLs tools to set up access controls on the local
file system instead of directly setting them in the Samba configuration as this
gives more flexibility. Also, one need to make sure that the POSIX path
specified in the share actually allows write access to the users or groups from
the `write list`:

```
[shared]
	path = /srv/shared
	read only = No
	write list = @admins

[homes]
        browsable = no
        writable = yes

```

8. Now the tricky part. We need to make sure to set up Samba to use the same
   Security Identifier for the domain as is used by the IPA domain controller.
Remember SID from the `ipa trustconfig-show` step? Use it here:

```
# net setdomainsid S-1-5-21-570121326-3336757064-1157332047
```

9. Finally, we should map `BUILTIN\Guests` group to a local nobody group. This
   is required in all recent Samba releases:

```
# net groupmap add sid=S-1-5-32-546 unixgroup=nobody type=builtin
```

TODO: deal with the lack of a plain text password in the secrets.tdb. Without
it nothing will work.

```
# net changesecretpw -f
Enter machine password: 
secrets_prepare_password_change: secrets_fetch_or_upgrade_domain_info(IPA) failed
Unable to write the machine account password in the secrets database
```
Since there is no machine account set in Samba, `secrets_fetch_or_upgrade_domain_info()` fails and is unable to re-set the machine account to a new value. We need to fix this before anything would work start working.

-------------------------
From Sumit Bose ('AD' below is NetBIOS name of IPA domain):

about 'net changesecretpw -f' the tdbtool work-around is
imcomplete for Samba-4.9. It looks like somewhere it is ecpected that the tdb
data is 0-terminated. So using 
```
tdbtool /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_LAST_CHANGE_TIME/AD '2\00'
```

 and

```
tdbtool /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_PASSWORD/AD '2\00'
```

made it work for me in RHEL-8 with Samba-4.9.
------------------------

10. Start Samba services. You need at least `smb` and `winbind` because Samba
    cannot function without both of them in newer releases. `winbindd` daemon
    is an integral part of Samba and all fallback code for the cases when
    `winbindd` was not running in some configurations was removed from `smbd`
    daemon in newer Samba releases.

```
# systemctl start smb winbind
```

Now we can access a Samba share as a user from IPA domain:
```
[ab@raup ~]$ id
uid=1536000001(ab) gid=1536000001(ab) groups=1536000001(ab),1536000038(enterprise),1536000060(myfoo) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[ab@raup ~]$ kinit ab
Password for ab@IPA.REALM: 
[ab@raup ~]$ 
[ab@raup ~]$ klist
Ticket cache: KEYRING:persistent:1536000001:1536000001
Default principal: ab@IPA.REALM

Valid starting       Expires              Service principal
11/19/2018 17:28:47  11/20/2018 17:28:43  krbtgt/IPA.REALM@IPA.REALM
[ab@raup ~]$ smbclient -k -L `hostname`

	Sharename       Type      Comment
	---------       ----      -------
	shared          Disk      
	IPC$            IPC       IPC Service (Samba 4.8.6)
	ab              Disk      Home directory of ab
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
[ab@raup ~]$ smbclient -k //`hostname`/ab
Try "help" to get a list of possible commands.
smb: \> mkdir test
smb: \> ls test
  test                                D        0  Mon Nov 19 17:30:13 2018

		20510332 blocks of size 1024. 14621464 blocks available
smb: \> exit
[ab@raup ~]$ ls -la test
total 8
drwxr-xr-x. 2 ab ab 4096 Nov 19 17:30 .
drwx------. 3 ab ab 4096 Nov 19 17:30 ..
```

Using `smbclient` above we accessed a home share for the user `ab`. Note that this user is not a member of `admins` group so it should not be able to access `shared` share:
```
....
```



