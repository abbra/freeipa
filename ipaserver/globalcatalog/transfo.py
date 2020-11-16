import base64
from jinja2 import Environment, PackageLoader
from samba.dcerpc import security
from samba.ndr import ndr_pack
import struct
import uuid

from ipalib import api
from ipalib.constants import IPA_SID_FAMILY_PREFIX
from ipapython.dn import DN

GROUP_TYPE_ACCOUNT_GROUP = 0x00000002
GROUP_TYPE_RESOURCE_GROUP = 0x00000004
GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008
GROUP_TYPE_SECURITY_ENABLED = 0x80000000
GROUP_TYPE_OFFSET = 0x100000000


def transform_sid_value(sid):
    """Transforms a SID from a string to an AD-compatible format."""
    return base64.b64encode(ndr_pack(security.dom_sid(sid))).decode('utf-8')


def transform_sid(entry):
    """Transforms a SID from a entry to an AD-compatible format

    If the entry contains ipantsecurityidentifier, the attr value is used as
    input.
    For instance input: (string) S-1-5-21-290024825-4011531429-1633689518-500
    output: (string) AQUAAAAAAAUVAAAAeW1JEaUcG++uH2Bh7QMAAA==

    If the entry doesn't have any ipantsecurityidentifier attribute, a special
    SID is computed from the ipauniqueid and a special SID prefix S-1-738065-.
    For instance input: (ipauniqueid) 7d976a62-0703-11ea-89b6-001a4a2312ca
    output: (string) 'S-1-738065-2107075170-117641706-2310406170-1243812554'
    """
    try:
        sid = entry.single_value['ipantsecurityidentifier']
    except KeyError:
        # The entry doesn't contain ipantsecurityidentifier
        # Compute the SID from ipauniqueid instead
        # Note that this should be done only if the entry is a
        # nonposix group
        objectclasses = set(oc.lower() for oc in entry['objectclass'])
        if 'groupofnames' in objectclasses and \
           'posixgroup' not in objectclasses:
            uniqueid = entry.single_value['ipauniqueid']
            sid = IPA_SID_FAMILY_PREFIX + '-'.join(
                str(x)
                for x in struct.unpack('!IIII', uuid.UUID(uniqueid).bytes))
        else:
            raise ValueError("Unable to create SID, missing data")
    return transform_sid_value(sid)


def transform_gid(uniqueid):
    """Transforms an id from a string format to an AD-compatible format

    For instance input: (string) 7d976a62-0703-11ea-89b6-001a4a2312ca
    output (string): fZdqYgcDEeqJtgAaSiMSyg==
    """
    return base64.b64encode(uuid.UUID(uniqueid).bytes).decode('utf-8')


def rename_dn(api, dn, conn):
    """Fix the DN value that is representing a DN on DS side.

    In IdM the users are below cn=users,cn=accounts,$suffix
    and they have a dn: uid=%uid%
    but in the Global Catalog they are in CN=Users,$suffix
    and they have a dn: Cn=%cn%

    If the entry is in the container for users, we assume it's a user DN
    and need to perform an internal search based on the cn to find
    the entry on GC side.
    If the entry is in the container for groups, we assume it's a group DN
    and simply need to build a new dn from CN=..,CN=users,$suffix.
    """
    users_dn = DN(api.env.container_user, api.env.basedn)
    groups_dn = DN(api.env.container_group, api.env.basedn)

    if dn.find(users_dn) == 1:
        # The member value is right below the user container
        # Need to find the CN single_value
        user = conn.get_entry(
            dn, ["cn"], time_limit=0, size_limit=-1)
        user_cn = user.single_value['cn']
        return 'cn={},cn=users,{}'.format(user_cn, api.env.basedn)
    if dn.find(groups_dn) == 1:
        # The member value is right below the group container
        return '{},cn=users,{}'.format(dn[0], api.env.basedn)
    # Unable to find a corresponding member
    raise ValueError


def rename_group_members(api, group, conn):
    """Fix the member attribute of a group entry."""
    new_member_attr = []
    for memberDN in group.get('member', []):
        try:
            gc_dn = rename_dn(api, memberDN, conn)
            new_member_attr.append(DN(gc_dn))
        except ValueError:
            # Unable to rename DN of the member, keep as-is
            new_member_attr.append(memberDN)

    # If the group is an external group, it also contains ipaexternalmember
    # they are transformed into member: cn=SID,CN=ForeignSecurityPrincipals,..
    for memberSid in group.get('ipaexternalmember', []):
        memberDN = DN(
            ('cn', memberSid), api.env.container_fsp, api.env.basedn)
        new_member_attr.append(memberDN)
        # TODO
        # We also need to create the entry memberDN if it does not exist
    group['member'] = new_member_attr


def get_groupType(group):
    """Get the groupType for the provided groups

    If the group is a posixGroup, it is mapped to a security group (ie with
    the GROUP_TYPE_SECURITY_ENABLED flag), as a global group (ie with the
    GROUP_TYPE_ACCOUNT_GROUP flag).
    If the group is an external group, it is mapped to a security group, as
    a domain-local group (ie with the GROUP_TYPE_RESOURCE_GROUP flag).
    Other groups (non posix, non-external) are mapped to distribution groups
    as a global group.
    """
    objectclasses = set(oc.lower() for oc in group['objectclass'])
    if 'posixgroup' in objectclasses:
        groupType = GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP
    elif 'ipaexternalgroup' in objectclasses:
        groupType = GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_RESOURCE_GROUP
    else:
        groupType = GROUP_TYPE_ACCOUNT_GROUP

    # Make sure the signed value is used
    if groupType >= GROUP_TYPE_SECURITY_ENABLED:
        groupType -= GROUP_TYPE_OFFSET
    return groupType


def rename_group_dn(api, group_dn):
    """Transform a group DN from 389 side to Global Catalog side.

    In 389-ds the group entry looks like cn=...,cn=groups,cn=accounts,$base
    but in the Global Catalog it is
    CN=..,CN=Users,$base

    group_dn: DN value
    return: a DN value
    """
    groups_dn = DN(api.env.container_group, api.env.basedn)
    if group_dn.find(groups_dn) != 1:
        raise ValueError
    # The memberof value is right below the group container
    # rename and return
    return DN(group_dn[0], 'cn=users', api.env.basedn)


def rename_memberof(api, user):
    """Fix the memberof attribute of a user/group entry

    In IdM the groups are below cn=groups,cn=accounts,$suffix but in
    the Global Catalog they are in CN=Users,$suffix
    """
    new_memberof_attr = []
    for groupDN in user.get('memberof', []):
        try:
            gc_groupDN = rename_group_dn(api, groupDN)
            new_memberof_attr.append(gc_groupDN)
            continue
        except ValueError:
            # The memberof is not in the group container, keep as-is
            new_memberof_attr.append(groupDN)

    user['memberof'] = new_memberof_attr


def get_dn_from_cn(api, cn):
    """Create an entry DN in GC format, from the value of the cn attribute.

    In 389-ds the user entry looks like uid=..,cn=users,cn=accounts,$base
    but in the Global Catalog it is
    CN=..,CN=Users,$base.
    In 389-ds the group entry looks like cn=..,cn=groups,cn=accounts,$base
    but in the Global Catalog it is
    CN=..,CN=Users,$base
    It's easy to build the GC DN from a cn value.
    """
    return DN("cn={},cn=users,{}".format(cn, api.env.basedn))


class GCTransformer:
    def __init__(self, api, conn):
        loader = PackageLoader('ipaserver', 'globalcatalog/templates')
        jinja_env = Environment(loader=loader)
        self.user_template = jinja_env.get_template('gc_user_template.tmpl')
        self.group_template = jinja_env.get_template('gc_group_template.tmpl')
        self.fsp_template = jinja_env.get_template('gc_fsp_template.tmpl')
        self.api = api
        self.ldap_conn = conn

    def create_ldif_user(self, uuid, entry):
        """Creates a LDIF allowing to add the entry

        entry: the input user entry
        """
        # the uid value is multivalued, extract the right one as primary key
        # (i.e. the one from the DN)
        pkey = entry.dn[0][0].value
        sid = transform_sid(entry)
        guid = transform_gid(entry.single_value['ipauniqueid'])
        rename_memberof(api, entry)
        ldif_add = self.user_template.render(
            entry=entry, pkey=pkey, sid=sid, guid=guid,
            suffix=api.env.basedn,
            entryuuid=uuid)
        return ldif_add

    def create_ldif_group(self, uuid, entry):
        """Creates a LDIF allowing to add the group entry

        entry: the input group entry
        """
        # the cn value is multivalued, extract the right one as primary key
        # (i.e. the one from the DN)
        pkey = entry.dn[0][0].value
        sid = transform_sid(entry)
        guid = transform_gid(entry.single_value['ipauniqueid'])
        groupType = get_groupType(entry)
        rename_group_members(self.api, entry, conn=self.ldap_conn)
        rename_memberof(api, entry)
        ldif_add = self.group_template.render(
            entry=entry, pkey=pkey, guid=guid,
            sid=sid, suffix=api.env.basedn, groupType=groupType,
            entryuuid=uuid)
        return ldif_add

    def create_ldif_foreignsecurityprincipal(self, sidstring):
        """Creates a LDIF allowing to add a ForeignSecurityPrincipal entry

        sidstring: the sid using a string format, for instance
        S-1-5-21-704000768-2575068322-3001777647-1109
        """
        sid = transform_sid_value(sidstring)
        ldif_add = self.fsp_template.render(
            sidstring=sidstring, sid=sid,
            suffix=api.env.basedn)
        return ldif_add
