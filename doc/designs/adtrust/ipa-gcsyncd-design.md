# Global Catalog Synchronization Service for FreeIPA

Synchronization service is an external application (daemon) that runs
independently on IPA masters. The daemon is connected to the primary FreeIPA
LDAP instance over LDAPI socket and listens for changes with SYNCREPL mechanism.
Upon an arrival of an update, it determines whether this update should be
translated into Global Catalog's change. If the change is required, a
transformation is performed by the daemon.

In order to write to Global Catalog instance, the daemon connects to it over
LDAPI socket and binds with SASL EXTERNAL. Global Catalog is configured to
auto-bind such connection from the daemon identity to a special LDAP object that
has permissions to write to Global Catalog trees. As result, only updates
performed by this identity are allowed in Global Catalog.

## Overview of the synchronization mechanism

The synchronization daemon is using syncrepl to get notifications of updates
applied to the primary FreeIPA LDAP instance.

The syncrepl API allows to register callbacks that are triggered by the
addition, modification or deletion of entries in the LDAP server. After each
callback, a cookie is updated, that allows to resume at the same point if
the synchronization service is stopped and restarted.

### Initialization of the Global Catalog content

During its first run, the Synchronization Service is run without any cookie.
It initializes a SyncreplConsumer instance with an empty cookie, which
corresponds to a request to get the initial content of the LDAP server
followed by a second phase listening to changes.
In the first phase, for each entry satisfying the search filter, the callback
*syncrepl_entry* is executed. The callback provides a unique id, a DN and the
list of attributes with their values. The unique id, DN, objectclass and cn
values are kept in an internal dict for later use.

For each user and group found in the LDAP server, the Synchronization Service
creates a corresponding entry in the Global Catalog by applying the
appropriate transformations.

In the second phase (the persist stage), any entry addition, modification or
deletion triggers callbacks.

An entry deletion triggers the callback *syncrepl_delete*, that provides a list
of unique ids.
By using the internal dict, it is possible to map the unique id to the DN
of an entry already seen and trigger the deletion of the corresponding
Global Catalog entry.

An entry addition or modification triggers the callback *syncrepl_entry*,
that provides the dn, list of attributes and unique id. Using the internal dict,
it is possible to check if the change is corresponding to a ADD or a MOD
(ADD if the unique id has not been seen yet, MOD otherwise),
and the Synchronization Service can choose the right path. For entry addition,
a new Global Catalog entry can be created, while for modification the Service
needs to update an existing entry. In order to simplify the code, the
service deletes the existing entry and creates a new one, instead of
comparing the content and updating only the attributes that have changed.

### Shutdown of the Synchronization Service and restart

When the Synchronization Service is stopped, the last registered cookie is
saved and written in a persistent file in */var/lib/ipa/gc_cookie*.
Upon next restart, the cookie is read and passed to the SyncreplConsumer
in order to resume at the same point and avoid re-reading the whole LDAP
server.
As the callbacks depend on the content of the internal dict to determine
whether a change is a ADD or a MODIFY, the Synchronization Service also needs
to rebuild the internal dict when it's starting up with a cookie.
This is achieved by reading the content of the Global Catalog:
- the *DN* of the originating entry is easy to build from the attributes of the
GC entry
- idem for the *objectClass*
- idem for the *cn*
- the unique id of the corresponding LDAP server entry is stored in an
operational attribute *gcuuid* (new attribute type defined in the GC), that is
not displayed by default as it is operational.

## Transformations applied to the entries

The Global Catalog entries differ from the LDAP server entries in multiple
ways:
- the container for users and groups is different
- the naming pattern is different
- the GC entries contain only a subset of attributes, the ones that are
required by Active Directory
- the GC entries must contain attributes that do not exist in the LDAP server
but are needed by AD, and can be built from the LDAP entry content
(for instance the *objectSid*).

### User entries

In the LDAP server, the user entries are stored below
*cn=users,cn=accounts,$BASEDN*
but in the Global Catalog they are stored below
*CN=Users,$BASEDN*

The LDAP user entries have a naming pattern *uid=$UID* while the GC entries
are named *cn=$CN*.

Some attributes on GC side are single-valued while they can be multi-valued
in the LDAP server. From these attributes (*cn, sn, givenname, mail, uidnumber,
gid, homedirectory*) the Synchronization Service is using the first value.

The user entries on GC side must also contain:
- *name, sAMAccountName*: built from *cn*
- *userPrincipalName*: built from *krbcanonicalname* or the first val of
*krbprincipalname*

### Group entries

In the LDAP server, the group entries are stored below
*cn=groups,cn=accounts,$BASEDN*
but in the Global Catalog they are stored below
*CN=Users,$BASEDN*

The naming pattern is identical i.e. *cn=$CN.*

Inside the Global Catalog, the group must contain a *groupType* attribute. The
Synchronization Service is performing the following mapping:
- posix groups are mapped to security groups as global groups
 (GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP)
- external groups are mapped to security groups as domain-local groups
  (GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_RESOURCE_GROUP)
- other groups (non-posix, non-external groups) are mapped to distribution
  groups as global groups (GROUP_TYPE_ACCOUNT_GROUP)

The group entries on GC side must contain *cn, name, sAMAccountName* built from
the *cn* value.

### The member and memberof attributes

As the DNs are not identical on the primary LDAP server and on the GC, all
the attributes that contain DN values need to be adapted.
In a group entry, the *member* attribute value needs to be transformed.
In a group or a user entry, the *memberof* attribute value also needs to be
transformed.

### The objectSid attribute

Posix groups and users contain an *ipantsecurityidentifier* that is used to
build the *objectSid* value.
For non-posix groups (that do not contain the *ipantsecurityidentifier*),
a special SID is computed from the *ipauniqueid* and a
special SID prefix S-1-738065-.

### The objectguid attribute

The value is built from the content of *ipauniqueid* attribute.

## Fault tolerance

When the LDAP connection to the Global Catalog instance fails (for instance
after a restart of the GC process), the Synchronization Service is able to
automatically reconnect. It is internally using a *ReconnectLDAPObject* that
allows to retry retry_max times and wait for retry_delay before retrying
to connect.
If a synchronous operation fails on this *ReconnectLDAPObject*, it is replayed
when the connection is re-established.

When the LDAP connection to the primary LDAP server instance fails, the daemon
exits after saving the last processed cookie. The service is then automatically
restarted after 60s (as configured in its systemd unit) and resumes with the
last cookie, ensuring that no operation is lost.
