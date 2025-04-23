# LDAP system accounts

## Overview

Two important FreeIPA components are LDAP server and Kerberos infrastructure. When Kerberos protocol is used for authentication in FreeIPA deployments, context of the original authentication is preserved. This allows applications to inspect it and make decisions based not only on user identity but also how the original authentication has happened. For applications that do not support integration with Kerberos, a traditional LDAP bind is used. In this case, the original authentication context is lost and the application can only see the identity of the user that has authenticated.

Applications which do not support Kerberos authentication also need to authenticate to the LDAP server. This is typically done using an LDAP system account. They are not used in the POSIX environment and are not associated with any user. System accounts are typically used by applications to authenticate to the LDAP server and perform operations on behalf of the application.

This document describes the design of the system accounts in FreeIPA.

## Use Cases

### Use Case 1: Legacy Application authentication

A legacy application that does not support Kerberos authentication needs to authenticate to the LDAP server. The application uses an LDAP system account to authenticate to the LDAP server. After successful authentication, the application can perform operations on behalf of the system account.

### Use Case 2: External account password rotation

An external system controls the passwords of user accounts in FreeIPA. The external system uses an LDAP system account to authenticate to the LDAP server and change the password of a user account. The change of the user account's password should not trigger the password policy reset for the user account.

## How to Use

LDAP system account is addressed by its LDAP DN. An application can bind to LDAP by presenting both LDAP DN of the object to bind as and its password. The password is stored in the `userPassword` attribute of the system account object.

Typical LDAP authentication operation with the system account would look like this:

```
$ ldapsearch -D "uid=systemaccount,cn=sysaccounts,cn=etc,dc=example,dc=com" -W -b "dc=example,dc=com" -s sub "(objectclass=*)"
```

In the `ldapsearch` command above, the system account `uid=systemaccount,cn=sysaccounts,cn=etc,dc=example,dc=com` is used to authenticate to the LDAP server. Its password is not provided directly but `ldapsearch` command will prompt for it due to `-W` option.

If the system account is used to perform LDAP operations, the system account should have the necessary permissions to perform the operation. The permissions are granted using the LDAP access controls (ACIs).

## Design

### System Account LDAP Object

System account object is a regular LDAP entry with at least two object classes defined: `account` and `simpleSecurityObject`. The object is stored in the `cn=sysaccounts,cn=etc` container. In order to allow membership in groups and roles, object class `nsMemberOf` can be used. The object has the following attributes:

- `uid`: The unique identifier of the system account.
- `userPassword`: The password of the system account.
- `description`: A human-readable description of the system account.
- `memberOf`: The groups and roles the system account is a member of, in case the `nsMemberOf` object class is used.

Other attributes can be added to the system account object as needed but they aren't used by the system account itself.

### LDAP BIND Operation

FreeIPA provides a number of plugins that alter the behavior of the LDAP server. One of these plugins is the `ipa_pwd_extop` plugin. This plugin is used to intercept the LDAP BIND operation and perform additional checks and operations. In particular, this plugin enforces two-factor authentication for the user accounts if `EnforceLDAPOTP` global option is set or LDAP client enforced the check through an LDAP control.

When `EnforceLDAPOTP` mode is enabled, any LDAP bind must be performed with a user account that has two-factor authentication enabled. This would break LDAP binds with system accounts as they do not have two-factor authentication enabled. `ipa_pwd_extop` plugin accounts for this by checking that the LDAP object pointed by the LDAP bind has `simpleSecurityObject` object class. If the object does have this object class, the plugin allows the bind to proceed.

### Password modifications using system accounts

FreeIPA implements a password change policy that ensures only users can keep the passwords they changed. If a password change came from any other source, it will be marked for a change next time it is used. For example, an administrator may reset a user's password but this password will have to be changed next time user authenticates to the system. This is enforced through both LDAP and Kerberos authentication flows.

In order to allow external systems to synchronize passwords without triggering the password reset, FreeIPA implements two exceptions:
- `cn=Directory Manager` can change passwords without marking them for a change.
- LDAP objects whose DNs are stored in the `passSyncManagersDNs` attribute of the `cn=ipa_pwd_extop,cn=plugins,cn=config` can change passwords without marking them for a change.

The latter exception is used internally by the FreeIPA replication system to synchronize data from Windows domain controllers with the help of PassSync plugin. The system accounts can be added to the `passSyncManagersDNs` attribute to allow them to change passwords without marking them for a change.

In order to simplify management of the passSyncManagersDNs attribute, FreeIPA provides two permissions:
- `Modify PassSync Managers Configuration` permission allows adding and removing DNs to and from the `passSyncManagersDNs` attribute.
- `Read PassSync Managers Configuration` permission allows reading the `passSyncManagersDNs` attribute.

By default, both these permissions are granted to the `Replication Administrators` privilege and, through that privilege, to the `Security Architect` role.
