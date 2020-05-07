#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import json
import ldap
import logging
from io import StringIO
from ldap.cidict import cidict
from ldap.ldapobject import ReconnectLDAPObject
from ldap.syncrepl import SyncreplConsumer
from ldif import LDIFParser

from ipalib import constants, errors
from ipaplatform.paths import paths
from ipapython import ipaldap
from ipapython.dn import DN
from ipaserver.globalcatalog.transfo import GCTransformer
from ipaserver.globalcatalog.transfo import get_dn_from_cn
from ipaserver.globalcatalog.transfo import rename_group_dn

logger = logging.getLogger(__name__)

OBJCLASS_ATTR = 'objectClass'


class ReconnectLDAPClient(ipaldap.LDAPClient):
    """LDAPClient able to reconnect in case of server failure.

    In case of server failure (ldap.SERVER_DOWN) the implementations
    of all synchronous operation methods (search_s() etc.) are doing
    an automatic reconnect and rebind and will retry the very same
    operation.
    """
    def __init__(self, ldap_uri, start_tls=False, force_schema_updates=False,
                 no_schema=False, decode_attrs=True, cacert=None,
                 sasl_nocanon=True, retry_max=1, retry_delay=60):
        self.retry_max = retry_max
        self.retry_delay = retry_delay
        ipaldap.LDAPClient.__init__(
            self,
            ldap_uri=ldap_uri, start_tls=start_tls,
            force_schema_updates=force_schema_updates,
            no_schema=no_schema, decode_attrs=decode_attrs, cacert=cacert,
            sasl_nocanon=sasl_nocanon)

    def _connect(self):
        with self.error_handler():
            conn = ldap.ldapobject.ReconnectLDAPObject(
                self.ldap_uri,
                retry_max=self.retry_max, retry_delay=self.retry_delay)
            # SASL_NOCANON is set to ON in Fedora's default ldap.conf and
            # in the ldap_initialize() function.
            if not self._sasl_nocanon:
                conn.set_option(ldap.OPT_X_SASL_NOCANON, ldap.OPT_OFF)

            if self._start_tls and self.protocol == 'ldap':
                # STARTTLS applies only to ldap:// connections
                conn.start_tls_s()

        return conn


class AddLDIF(LDIFParser):
    def __init__(self, input, conn):
        LDIFParser.__init__(self, StringIO(input))
        self._conn = conn

    def handle(self, dn, entry):
        try:
            newentry = self._conn.make_entry(DN(dn), entry)
            self._conn.add_entry(newentry)
        except errors.DuplicateEntry:
            logger.error("Entry %s already exists", dn)


class GCSyncer(ReconnectLDAPObject, SyncreplConsumer):
    def __init__(self, *args, **kwargs):
        self.api = kwargs['ipa_api']
        del kwargs['ipa_api']

        # Initialise the LDAP Connection first
        ldap.ldapobject.ReconnectLDAPObject.__init__(self, *args, **kwargs)
        # Now prepare the data store
        self.__data = dict()
        self.__data['uuids'] = dict()
        # We need this for later internal use
        self.__presentUUIDs = dict()

        self.users_dn = DN(self.api.env.container_user, self.api.env.basedn)
        self.groups_dn = DN(self.api.env.container_group, self.api.env.basedn)

        ldapuri_ds = ipaldap.get_ldap_uri(realm=self.api.env.realm,
                                          protocol='ldapi')
        self.ds_conn = ipaldap.LDAPClient(ldapuri_ds)
        self.ds_conn.external_bind()

        ldap_uri_gc = ipaldap.get_ldap_uri(realm=constants.GC_REALM_NAME,
                                           protocol='ldapi')
        self.gc_conn = ReconnectLDAPClient(ldap_uri_gc)
        self.gc_conn.external_bind()

        self.gc = GCTransformer(self.api, self.ds_conn)
        self.init_done = False

        self._init_data()

        self.application_add = {b'person': self.user_add,
                                b'groupofnames': self.group_add}
        self.application_mod = {b'person': self.user_mod,
                                b'groupofnames': self.group_mod}
        self.application_del = {b'person': self.user_del,
                                b'groupofnames': self.group_del}

    def _init_data(self):
        """Initialize the internal data from the content of GC.

        Read the user and groups in Global Catalog in order to build
        the initial __data and __presentUUIDs structures.
        They are needed to properly process the syncrepl callbacks.
        """
        # Read user and group entries from GC
        gc_objects = {
            'user': {
                'filter': "(objectclass=person)",
                'objclass': b'person',
                'orig_dn_format': "uid={},{}",
                'orig_dn_container': self.users_dn,
                'orig_dn_attr': 'uid',
            },
            'group': {
                'filter': "(objectclass=group)",
                'objclass': b'groupofnames',
                'orig_dn_format': 'cn={},{}',
                'orig_dn_container': self.groups_dn,
                'orig_dn_attr': 'cn',
            }
        }
        for object in gc_objects.values():
            try:
                entries, _truncated = self.gc_conn.find_entries(
                    filter=object['filter'],
                    attrs_list=['gcuuid', 'cn', 'uid'],
                    base_dn=DN("cn=users", self.api.env.basedn),
                    scope=ldap.SCOPE_SUBTREE, time_limit=None, size_limit=None)

                for entry in entries:
                    entry_dict = dict()
                    entry_dict['objectclass'] = object['objclass']
                    # Set the originating DN on DS side
                    entry_dict['dn'] = object['orig_dn_format'].format(
                        entry[object['orig_dn_attr']][0],
                        object['orig_dn_container'])
                    entry_dict['cn'] = entry['cn'][0]
                    uuid = entry['gcuuid'][0]
                    self.__data['uuids'][uuid] = entry_dict
                    self.__presentUUIDs[uuid] = True
            except errors.EmptyResult:
                # At the first run, there is no entry, start with an empty dict
                pass

        # Read the last cookie that was processed before shutdown
        cookie = self._get_saved_cookie()
        self.syncrepl_set_cookie(cookie)

    def shutdown(self):
        """Properly stop the syncer.

        Save the last known cookie to a persistent file.
        """
        logger.debug("save cookie")
        cookie = self.syncrepl_get_cookie()
        if cookie:
            with open(paths.GC_COOKIE, 'w') as f:
                f.write(cookie)

    def _get_saved_cookie(self):
        """Get the last known cookie from a persistent file.

        Returns None if the file does not exist or is empty.
        """
        logger.debug("get_saved_cookie")
        cookie = None
        try:
            with open(paths.GC_COOKIE) as f:
                content = f.read()
            # if the content is an empty string, simply return None
            if content:
                cookie = content
                logger.debug("Read cookie %s", cookie)
        except FileNotFoundError:
            # It's ok if no cookie was saved, it may be the first run
            pass
        return cookie

    def _get_objclass(self, attrs):
        """Get object class.

        Given the set of attributes, find the principal object class.
        The attrs may contain for instance: top, groupofnames, nestedgroup,
        ipausergroup, ... In this case the most relevant objectclass is
        groupofnames.
        For a user, the attrs may contain top, person. organizationalperson,
        inetorgperson, inetuser, posixaccount, ... and the most relevant
        objectclass is person.
        """
        supported_objclasses = {b'person', b'groupofnames'}
        present_objclasses = set(
            o.lower() for o in attrs[OBJCLASS_ATTR]
        ).intersection(
            supported_objclasses
        )
        # Because the persistent search is done with the filter
        # (|(objectclass=person)(objectclass=groupofnames)),
        # the objectclass can be one or the other but nothing else
        assert len(present_objclasses) == 1, attrs[OBJCLASS_ATTR]
        return present_objclasses.pop()

    def _create_entry_from_attrs(self, dn, attrlist):
        """Create a LDAPEntry from a dn and list of attributes."""
        entry = ipaldap.LDAPEntry(self.ds_conn, dn)
        for attr, original_values in attrlist.items():
            if attr == 'dn':
                continue
            entry.raw[attr] = original_values
        entry.reset_modlist()
        return entry

    # ------------------
    # syncrepl methods
    # ------------------
    def syncrepl_get_cookie(self):
        if 'cookie' in self.__data:
            cookie = self.__data['cookie']
            logger.debug('Current cookie is: %s', cookie)
            return cookie
        else:
            logger.debug('Current cookie is: None (not received yet)')
            return None

    def syncrepl_set_cookie(self, cookie):
        logger.debug('New cookie is: %s', cookie)
        self.__data['cookie'] = cookie

    def syncrepl_entry(self, dn, attributes, uuid):
        attributes = cidict(attributes)
        # First we filter entries that are not interesting for us
        # meaning users outside of the users container
        # or groups outside of the groups container
        objclass = self._get_objclass(attributes)
        entry_dn = DN(dn)
        if objclass == b'person':
            if entry_dn.find(self.users_dn) != 1:
                logger.debug("Dropping syncrepl_entry for user %s", dn)
                return
        elif objclass == b'groupofnames':
            if entry_dn.find(self.groups_dn) != 1:
                logger.debug("Dropping syncrepl_entry for user %s", dn)
                return
        else:
            logger.debug("Dropping syncrepl_entry for %s", dn)
            return

        attrs = dict()
        attrs['objectclass'] = objclass
        # First we determine the type of change we have here
        # (and store away the previous data for later if needed)
        previous_attrs = dict()
        if uuid in self.__data['uuids']:
            change_type = 'modify'
            previous_attrs = self.__data['uuids'][uuid]
        else:
            change_type = 'add'
        # Now we store our knowledge of the existence of this entry
        # (including the DN as an attribute for convenience)
        attrs['dn'] = dn
        attrs['cn'] = attributes['cn'][0].decode('utf-8')
        self.__data['uuids'][uuid] = attrs
        # Debugging
        logger.debug('Detected %s of entry: %s %s', change_type, dn, uuid)
        if change_type == 'modify':
            self.application_mod[objclass](uuid, dn, attributes,
                                           previous_attrs)
        else:
            self.application_add[objclass](uuid, dn, attributes)

    def syncrepl_delete(self, uuids):
        # Make sure we know about the UUID being deleted, just in case...
        uuids = [uuid for uuid in uuids if uuid in self.__data['uuids']]
        # Delete all the UUID values we know of
        for uuid in uuids:
            attributes = self.__data['uuids'][uuid]
            dn = attributes['dn']
            objclass = attributes['objectclass']
            logger.debug('Detected deletion of entry: %s %s', dn, uuid)
            self.application_del[objclass](uuid, dn, attributes)
            del self.__data['uuids'][uuid]

    def syncrepl_present(self, uuids, refreshDeletes=False):
        # If we have not been given any UUID values,
        # then we have received all the present controls...
        if uuids is None:
            # We only do things if refreshDeletes is false
            # as the syncrepl extension will call syncrepl_delete instead
            # when it detects a delete notice
            if refreshDeletes is False:
                deletedEntries = [uuid for uuid in self.__data['uuids'].keys()
                                  if uuid not in self.__presentUUIDs]
                self.syncrepl_delete(deletedEntries)
            # Phase is now completed, reset the list
            self.__presentUUIDs = {}
        else:
            # Note down all the UUIDs we have been sent
            for uuid in uuids:
                self.__presentUUIDs[uuid] = True

    def syncrepl_refreshdone(self):
        """Callback triggered when the initial dump of DS content is done."""
        logger.info('Initial LDAP dump is done, now synchronizing with GC')
        self.init_done = True

    # ---------------
    # User operations
    # ---------------
    def user_add(self, uuid, entry_dn, newattrs):
        """Add a new user in the Global Catalog."""
        logger.debug("user_add %s", entry_dn)
        dn = DN(entry_dn)

        # Create a new user entry from the attributes read in DS,
        # transform this entry to suit Global Catalog
        # (rename DN, member attributes, create SID ...)
        # and add the transformed entry in the GC
        entry = self._create_entry_from_attrs(dn, newattrs)
        try:
            ldif_add = self.gc.create_ldif_user(uuid, entry)
        except ValueError as e:
            logger.error("Failed to create GC entry based on %s (%s)",
                         entry_dn, e)
            return
        logger.debug("Adding user to the Global Catalog %s", ldif_add)
        parser = AddLDIF(ldif_add, self.gc_conn)
        parser.parse()

    def user_del(self, uuid, entry_dn, oldattrs):
        """Remove an existing user from the Global Catalog."""
        logger.debug("user_del %s", entry_dn)
        dn = DN(entry_dn)

        # The corresponding GC entry must also be deleted but its GC-side DN
        # must be evaluated first by using the cn value.
        old_cn = oldattrs['cn']
        gc_dn = get_dn_from_cn(self.api, old_cn)

        logger.debug("Deleting user from the Global Catalog %s", gc_dn)
        try:
            self.gc_conn.delete_entry(gc_dn)
        except errors.NotFound:
            logger.warning("User entry already deleted %s", gc_dn)

    def user_mod(self, uuid, entry_dn, newattrs, oldattrs):
        """Modify an existing user in the Global Catalog."""
        logger.debug("user_sync %s", entry_dn)
        olddn = DN(oldattrs['dn'])
        newdn = DN(entry_dn)

        # As we are only monitoring leaf entries, it is easier
        # to simply del the previous one and create a new one instead
        # of checking each attribute that was changed
        logger.debug("Syncing user in the Global Catalog (del+add)")
        self.user_del(uuid, oldattrs['dn'], oldattrs)
        self.user_add(uuid, entry_dn, newattrs)

        # Warning: if the updated attribute is cn, we need to also update
        # all the groups that contain this user as the DN of this entry
        # has changed on GC side, but not on DS side
        if oldattrs['cn'] != newattrs['cn'][0].decode('utf-8'):
            logger.debug("Need to update member: attribute in groups")
            old_member = get_dn_from_cn(self.api, oldattrs['cn'])
            new_member = get_dn_from_cn(self.api,
                                        newattrs['cn'][0].decode('utf-8'))
            for group in newattrs.get('memberof', []):
                gc_group_dn = rename_group_dn(self.api,
                                              DN(group.decode('utf-8')))
                mods = [(ldap.MOD_DELETE, 'member', old_member),
                        (ldap.MOD_ADD, 'member', new_member)]
                self.gc_conn.modify_s(gc_group_dn, mods)

    # ----------------
    # Group operations
    # ----------------
    def group_add(self, uuid, entry_dn, newattrs):
        """Add a new group in the Global Catalog."""
        logger.debug("group_add %s", entry_dn)
        dn = DN(entry_dn)

        # Create a new group entry from the attributes read in DS,
        # transform this entry to suit Global Catalog
        # (rename DN, member attributes, create SID ...)
        # and add the transformed entry in the GC
        entry = self._create_entry_from_attrs(dn, newattrs)
        try:
            ldif_add = self.gc.create_ldif_group(uuid, entry)
        except ValueError as e:
            logger.error("Failed to create GC entry based on %s (%s)",
                         entry_dn, e)
            return
        logger.debug("Adding group to the Global Catalog %s", ldif_add)
        parser = AddLDIF(ldif_add, self.gc_conn)
        parser.parse()

    def group_del(self, uuid, entry_dn, oldattrs):
        """Remove an existing group from the Global Catalog."""
        logger.debug("group_del %s", entry_dn)
        dn = DN(entry_dn)

        # The corresponding GC entry must also be deleted but its GC-side DN
        # must be evaluated first by using the cn value.
        old_cn = oldattrs['cn']
        gc_dn = get_dn_from_cn(self.api, old_cn)

        logger.debug("Deleting group from the Global Catalog %s", gc_dn)
        try:
            self.gc_conn.delete_entry(gc_dn)
        except errors.NotFound:
            logger.debug("Group entry already deleted %s", gc_dn)

    def group_mod(self, uuid, entry_dn, newattrs, oldattrs):
        """Modify an existing group in the Global Catalog."""
        logger.debug("group_sync %s", entry_dn)
        olddn = DN(oldattrs['dn'])
        newdn = DN(entry_dn)

        # As we are only monitoring leaf entries, it is easier
        # to simply del the previous one and create a new one instead
        # of checking each attribute that was changed
        logger.debug("Syncing group in the Global Catalog (del+add)")
        self.group_del(uuid, oldattrs['dn'], oldattrs)
        self.group_add(uuid, entry_dn, newattrs)
