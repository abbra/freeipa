
# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information

import logging

from ipalib import api, errors
from ipalib import Str
from ipalib.plugable import Registry
from .baseldap import (
    pkey_to_value,
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPQuery)
from ipalib import _, ngettext
from ipalib import constants
from ipalib import output
from ipapython.dn import DN

__doc__ = _("""
System accounts

System accounts designed to allow applications to query LDAP database.
Unlike IPA users, system accounts have no POSIX properties and cannot be
resolved as 'users' in a POSIX environment.

System accounts are stored in cn=sysaccounts,cn=etc LDAP subtree. Some of
system accounts are special to IPA's own operations and cannot be removed.

EXAMPLES:

 Add a new system account:
   ipa sysaccount-add my-app

 Delete a system account:
   ipa sysaccount-del my-app

 Find all system accounts:
   ipa sysaccount-find

 Disable the system account:
   ipa sysaccount-disable my-app

""")

logger = logging.getLogger(__name__)

register = Registry()

required_system_accounts = [
    'passsync',
    'sudo',
]


@register()
class sysaccount(LDAPObject):
    """
    System account object.
    """
    container_dn = api.env.container_sysaccounts
    object_name = _('system account')
    object_name_plural = _('system accounts')
    object_class = [
        'account', 'simplesecurityobject'
    ]
    possible_objectclasses = ['ipaallowedoperations', 'nsmemberof']
    permission_filter_objectclasses = ['simplesecurityobject']
    search_attributes = ['uid']
    default_attributes = [
        'uid', 'memberof', 'ipaallowedtoperform']
    uuid_attribute = ''
    attribute_members = {
        'memberof': ['role'],
    }
    bindable = True
    relationships = {
        'managedby': ('Managed by', 'man_by_', 'not_man_by_'),
    }
    password_attributes = [('userpassword', 'has_password'),
                           ('krbprincipalkey', 'has_keytab')]
    managed_permissions = {
        'System: Read System Accounts': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass',
                'uid', 'memberof',
            },
        },
        'System: Add System Accounts': {
            'ipapermright': {'add'},
            'default_privileges': {'System Accounts Administrators'},
        },
        'System: Modify System Accounts': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'userpassword'},
            'default_privileges': {'System Accounts Administrators'},
        },
        'System: Remove System Accounts': {
            'ipapermright': {'delete'},
            'default_privileges': {'System Accounts Administrators'},
        },
    }

    label = _('System Accounts')
    label_singular = _('System Account')

    takes_params = (
        Str('uid',
            pattern=constants.PATTERN_GROUPUSER_NAME,
            pattern_errmsg=constants.ERRMSG_GROUPUSER_NAME.format('user'),
            maxlength=255,
            cli_name='id',
            label=_('System account ID'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
            ),
    )

    def get_dn(self, *keys, **kwargs):
        key = keys[0]

        parent_dn = DN(self.container_dn, self.api.env.basedn)
        true_rdn = 'uid'

        return self.backend.make_dn_from_attr(
            true_rdn, key, parent_dn
        )

    def get_primary_key_from_dn(self, dn):
        """
        If the entry has krbcanonicalname set return the value of the
        attribute. If the attribute is not found, assume old-style entry which
        should have only single value of krbprincipalname and return it.

        Otherwise return input DN.
        """
        assert isinstance(dn, DN)

        try:
            entry_attrs = self.backend.get_entry(
                dn, [self.primary_key.name]
            )
            try:
                return entry_attrs[self.primary_key.name][0]
            except (KeyError, IndexError):
                return ''
        except errors.NotFound:
            pass

        try:
            return dn['krbprincipalname']
        except KeyError:
            return str(dn)

    def populate_krbcanonicalname(self, entry_attrs, options):
        if options.get('raw', False):
            return
        entry_attrs.setdefault(
            'krbcanonicalname', entry_attrs['krbprincipalname'])


@register()
class sysaccount_add(LDAPCreate):
    __doc__ = _('Add a new IPA system account.')
    msg_summary = _('Added system account "%(value)s"')


@register()
class sysaccount_del(LDAPDelete):
    __doc__ = _('Delete an IPA system account.')
    msg_summary = _('Deleted system account "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)

        sysaccount = keys[-1]
        if sysaccount.lower() in required_system_accounts:
            raise errors.ValidationError(
                name='system account',
                error=_('{} is required by the IPA master').format(sysaccount)
            )

        return dn


@register()
class sysaccount_mod(LDAPUpdate):
    __doc__ = _('Modify an existing IPA system account.')

    msg_summary = _('Modified service "%(value)s"')


@register()
class sysaccount_find(LDAPSearch):
    __doc__ = _('Search for IPA system accounts.')

    msg_summary = ngettext(
        '%(count)d system account matched',
        '%(count)d system accounts matched', 0
    )
    sort_result_entries = False

    takes_options = LDAPSearch.takes_options

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope,
                     *args, **options):
        assert isinstance(base_dn, DN)
        # lisp style!

        custom_filter = '(objectclass=simplesecurityobject)'
        if options.get('pkey_only', False):
            attrs_list.append('uid')

        custom_base_dn = self.api.env.container_sysaccounts + base_dn

        return (
            ldap.combine_filters((custom_filter, filter),
                                 rules=ldap.MATCH_ALL),
            custom_base_dn, scope
        )

    def post_callback(self, ldap, entries, truncated, *args, **options):
        # we have to sort entries manually instead of relying on inherited
        # mechanisms
        def sort_key(x):
            if 'krbcanonicalname' in x:
                return x['krbcanonicalname'][0]
            else:
                return x['krbprincipalname'][0]

        entries.sort(key=sort_key)

        if options.get('pkey_only', False):
            return truncated
        for entry_attrs in entries:
            self.obj.get_password_attributes(ldap, entry_attrs.dn, entry_attrs)
            principal = entry_attrs.get('krbprincipalname',
                                        entry_attrs.get('uid'))
            if isinstance(principal, (tuple, list)):
                principal = principal[0]

        return truncated


@register()
class sysaccount_show(LDAPRetrieve):
    __doc__ = _('Display information about an IPA system account.')

    member_attributes = ['managedby']

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)

        principal = entry_attrs.get('krbprincipalname', entry_attrs.get('uid'))
        if isinstance(principal, (tuple, list)):
            principal = principal[0]

        return dn


@register()
class sysaccount_disable(LDAPQuery):
    __doc__ = _('Disable the system account.')

    has_output = output.standard_value
    msg_summary = _('Disabled system account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        entry_attrs = ldap.get_entry(dn, ['*'])
        done_work = False

        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        ldap.deactivate_entry(dn)
        if entry_attrs['has_keytab']:
            ldap.remove_principal_key(dn)
            done_work = True

        if not done_work:
            raise errors.AlreadyInactive()

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class sysaccount_enable(LDAPQuery):
    __doc__ = _('Enable a system account.')

    has_output = output.standard_value
    msg_summary = _('Enabled system account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        ldap.activate_entry(dn)

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )
