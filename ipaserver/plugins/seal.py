# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

from datetime import datetime, timezone
import json
import os
import tempfile

from ipalib import _, api, errors, ngettext, output
from ipalib.parameters import Str
from ipalib.plugable import Registry
from ipalib.request import context
from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.dn import DN
from .baseldap import (
    LDAPObject, LDAPQuery, LDAPRetrieve, LDAPSearch, LDAPUpdate)
from .host import kuipa_enrollment_string

__doc__ = _("""
Seals

Manage kuipa seals and realm-wide seal limits.

A seal controls access to encrypted files kept by their owner. Users create
and manage their own seals and encrypt or open files with the kuipa tool.
The IPA seal commands let authorized administrators find and inspect seal
metadata or revoke a seal; they do not create seals or store plaintext files.

The KUIPA Seal Administrators privilege grants access to these IPA commands
and to realm-wide seal limits. The admins group has this privilege by default;
it can also be granted through an IPA role.

EXAMPLES:

 Create a seal that requires the owner's Kerberos ticket:
   kinit alice
   kuipa seal create personal --require ticket

 List your seals:
   kuipa seal list

 Seal a file and later open it:
   kuipa seal file personal secret.txt
   kuipa seal open secret.txt.sealed --out restored.txt

 Find a user's seals and inspect one by its Seal ID:
   ipa seal-find --owner=alice@EXAMPLE.COM
   ipa seal-show <seal-id>

 Show the original LDAP policy JSON for scripts:
   ipa seal-show <seal-id> --raw

 Revoke a seal:
   ipa seal-revoke <seal-id>

 Show or change realm-wide limits (the new value is a complete JSON object):
   ipa sealconfig-show
   ipa sealconfig-mod --limits='{"max_lifetime":34560000,"max_seals":16,
       "max_devices":8,"max_reauth":43200,"without_device":true,
       "descriptor_age":2592000}'

 Restore the default realm-wide limits:
   ipa sealconfig-mod --limits=

Revocation prevents future server releases and is recorded in the kuipa
transparency log. It cannot recall keys or plaintext already released.
See 'ipa help sealconfig-mod' for changing limits and 'kuipa seal --help'
for user seal operations.
""")

register = Registry()

_SEALS = DN(('cn', 'seals'), ('cn', 'kuipa'), ('cn', 'etc'))
_LIMITS = DN(('cn', 'seal-limits'), ('cn', 'kuipa'), ('cn', 'etc'))
_PRIVILEGE = 'KUIPA Seal Administrators'
_NUMBERS = {'max_lifetime', 'max_unlocks', 'max_seals', 'max_devices',
            'max_members', 'max_deposits', 'max_reauth', 'descriptor_age'}
_REQUIRED = {'max_lifetime', 'max_seals', 'max_devices', 'max_reauth',
             'without_device', 'descriptor_age'}
_FIELDS = _NUMBERS | {'offline_sessions', 'without_device', 'factors'}

_POLICY_FIELDS = (
    ('sealpolicyfactors', _('Opening needs')),
    ('sealpolicydelegation', _('Delegated tickets')),
    ('sealpolicyleased', _('Host ticket restriction')),
    ('sealpolicyexpires', _('Expires')),
    ('sealpolicyunlocks', _('Unlocks allowed')),
    ('sealpolicysealing', _('Sealing mode')),
    ('sealpolicyreauth', _('Longest session (seconds)')),
    ('sealpolicyoffline', _('Offline session (seconds)')),
    ('sealpolicyepoch', _('Session key epoch (seconds)')),
    ('sealpolicyapprovals', _('Approvals required')),
    ('sealpolicyapprovers', _('Approvers')),
    ('sealpolicywindow', _('Approval window (seconds)')),
    ('sealpolicyuses', _('Releases per approval')),
)


def format_policy(entry, raw=False):
    if raw or not entry.get('ipakusealpolicy'):
        return
    try:
        policy = json.loads(entry['ipakusealpolicy'][0])
        if not isinstance(policy, dict):
            return
        factors = policy.get('factors')
        sessions = policy.get('sessions', {})
        approvals = policy.get('approvals')
        if not isinstance(factors, dict) or not isinstance(sessions, dict):
            return
        if approvals is not None and not isinstance(approvals, dict):
            return
        if any(type(factors.get(key, False)) is not bool
               for key in ('ticket', 'passkey')):
            return
        if (factors.get('device') is not None
                and not isinstance(factors['device'], str)):
            return
        if ('ticket_leased' in policy
                and type(policy['ticket_leased']) is not bool):
            return
        for obj, keys in (
            (policy, ('not_after', 'max_unlocks')),
            (sessions, ('reauth', 'offline', 'epoch')),
            (approvals or {}, ('m', 'window', 'uses')),
        ):
            if any(obj.get(key) is not None and type(obj[key]) is not int
                   for key in keys):
                return
        if (policy.get('sealing') is not None
                and not isinstance(policy['sealing'], str)):
            return
        out = {}
        needs = []
        if factors.get('device') is not None:
            needs.append(_('device (%(level)s)') % {'level': factors['device']})
        if factors.get('ticket'):
            needs.append(str(_('Kerberos ticket')))
        if factors.get('passkey'):
            needs.append(str(_('passkey')))
        out['sealpolicyfactors'] = ', '.join(needs) or str(_('none'))
        delegation = policy.get('ticket_delegation')
        if isinstance(delegation, dict) and set(delegation) == {'via'}:
            delegation = _('via %(services)s') % {
                'services': ', '.join(delegation['via'])}
        if delegation is not None and not isinstance(delegation, str):
            return
        if delegation is not None:
            out['sealpolicydelegation'] = str(delegation)
        if policy.get('ticket_leased'):
            out['sealpolicyleased'] = str(_('leased hosts only'))
        if policy.get('not_after') is not None:
            timestamp = policy['not_after']
            try:
                out['sealpolicyexpires'] = datetime.fromtimestamp(
                    timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            except (OverflowError, OSError, ValueError, TypeError):
                out['sealpolicyexpires'] = str(timestamp)
        for key, attr in (
            ('max_unlocks', 'sealpolicyunlocks'),
            ('sealing', 'sealpolicysealing'),
        ):
            if policy.get(key) is not None:
                out[attr] = str(policy[key])
        for key, attr in (
            ('reauth', 'sealpolicyreauth'), ('offline', 'sealpolicyoffline'),
            ('epoch', 'sealpolicyepoch'),
        ):
            if sessions.get(key) is not None:
                out[attr] = str(sessions[key])
        if approvals is not None:
            for key, attr in (
                ('m', 'sealpolicyapprovals'), ('window', 'sealpolicywindow'),
                ('uses', 'sealpolicyuses'),
            ):
                if approvals.get(key) is not None:
                    out[attr] = str(approvals[key])
            members = approvals.get('from', {})
            if not isinstance(members, dict):
                return
            people = [
                '{}: {}'.format(kind, ', '.join(members.get(kind, [])))
                for kind in ('users', 'groups', 'hosts', 'services')
                if members.get(kind)
            ]
            if people:
                out['sealpolicyapprovers'] = '; '.join(people)
        known = {'factors', 'ticket_delegation', 'ticket_leased', 'not_after',
                 'max_unlocks', 'sealing', 'sessions', 'approvals'}
        extra = policy.keys() - known or factors.keys() - \
            {'device', 'ticket', 'passkey'}
        extra = extra or sessions.keys() - {'reauth', 'offline', 'epoch'}
        if approvals is not None:
            extra = extra or approvals.keys() - {'m', 'from', 'window', 'uses'}
            extra = extra or members.keys(
            ) - {'users', 'groups', 'hosts', 'services'}
        entry.update(out)
        if not extra:
            del entry['ipakusealpolicy']
    except (ValueError, TypeError, KeyError):
        return


def validate_limits(_ugettext, value):
    """Reject policies kuipad cannot deserialize, such as misspelled fields."""
    try:
        obj = json.loads(value)
        if not isinstance(obj, dict) or not _REQUIRED <= obj.keys():
            raise ValueError('missing required limit fields')

        def validate_fields(fields, group=False):
            allowed = _FIELDS | ({'group', 'priority'} if group else {'groups'})
            if fields.keys() - allowed:
                raise ValueError('unknown limit fields')
            for name in _NUMBERS & fields.keys():
                n = fields[name]
                if n is None and name == 'max_unlocks':
                    continue
                if type(n) is not int or not 0 <= n < 2**64:
                    raise ValueError('limits must be nonnegative integers')
            for name in {'offline_sessions', 'without_device'} & fields.keys():
                if type(fields[name]) is not bool:
                    raise ValueError('boolean limit required')
            if 'factors' in fields:
                if not isinstance(fields['factors'], list):
                    raise ValueError('factors must be an array')
                for factor in fields['factors']:
                    if (not isinstance(factor, dict)
                            or factor.keys() - {'device', 'ticket', 'passkey'}):
                        raise ValueError('invalid factors')
                    if factor.get('device') not in (
                            None, 'any', 'hardware-wrapped',
                            'hardware-bound'):
                        raise ValueError('invalid device level')
                    if any(type(factor[k]) is not bool
                           for k in {'ticket', 'passkey'} & factor.keys()):
                        raise ValueError('factor flags must be boolean')

        validate_fields(obj)
        groups = obj.get('groups', [])
        if not isinstance(groups, list):
            raise ValueError('groups must be an array')
        for group in groups:
            if (not isinstance(group, dict)
                    or not isinstance(group.get('group'), str)
                    or not group['group']):
                raise ValueError('group name required')
            if (type(group.get('priority')) is not int
                    or not 0 <= group['priority'] < 2**32):
                raise ValueError(
                    'group priority must be an unsigned 32-bit integer')
            validate_fields(group, group=True)
    except (ValueError, TypeError) as e:
        return _('Invalid kuipa seal limits: %(error)s') % {'error': str(e)}
    return None


@register()
class seal(LDAPObject):
    object_name = _('kuipa seal')
    object_name_plural = _('kuipa seals')
    container_dn = _SEALS
    object_class = ['ipaKUSeal']
    permission_filter_objectclasses = ['ipaKUSeal']
    default_attributes = ['cn', 'ipaKUSealOwner', 'ipaKUSealName',
                          'ipaKUSealState', 'ipaKUSealPolicy']
    search_attributes = ['cn', 'ipaKUSealOwner',
                         'ipaKUSealName', 'ipaKUSealState']
    label = _('kuipa seals')
    label_singular = _('kuipa seal')
    takes_params = (
        Str('cn', cli_name='id', primary_key=True, label=_('Seal ID')),
        Str('ipakusealowner?', cli_name='owner', label=_('Owner')),
        Str('ipakusealname?', cli_name='name', label=_('Seal name')),
        Str('ipakusealstate?', cli_name='state', label=_('State')),
        Str('ipakusealpolicy?', cli_name='policy', label=_('Policy')),
        *(Str(name + '?', label=label,
              flags={'virtual_attribute', 'no_create', 'no_update',
                     'no_search'})
          for name, label in _POLICY_FIELDS),
    )
    managed_permissions = {
        'System: Read kuipa Seals': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermlocation': DN(_SEALS, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=ipaKUSeal)'},
            'ipapermdefaultattr': {'cn', 'objectclass', 'ipakusealowner',
                                   'ipakusealname', 'ipakusealstate',
                                   'ipakusealpolicy'},
            'default_privileges': {_PRIVILEGE},
        },
    }


@register()
class seal_find(LDAPSearch):
    __doc__ = _('Search for kuipa seals.')
    msg_summary = ngettext('%(count)d seal matched',
                           '%(count)d seals matched', 0)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry in entries:
            format_policy(entry, raw=options.get('raw', False))
        return truncated


@register()
class seal_show(LDAPRetrieve):
    __doc__ = _('Show a kuipa seal.')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        format_policy(entry_attrs, raw=options.get('raw', False))
        return dn


@register()
class seal_revoke(LDAPQuery):
    __doc__ = _('Revoke a kuipa seal through the audited kuipa service.')
    has_output = output.standard_value
    msg_summary = _('Revoked kuipa seal "%(value)s"')

    def execute(self, cn, **options):
        ldap = self.obj.backend
        try:
            entry = ldap.get_entry(self.obj.get_dn(
                cn), ['ipakusealowner', 'ipakusealname'])
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)
        credential = getattr(context, 'ccache_name', None)
        anchor = kuipa_enrollment_string(self.api.env.realm)
        if not credential or not anchor:
            raise errors.ExecutionError(
                message=_('kuipa delegated credentials or local anchor '
                          'unavailable'))
        with tempfile.TemporaryDirectory(prefix='ipa-kuipa-') as root:
            etc = os.path.join(root, 'etc', 'ipa')
            public_dir = os.path.join(etc, 'ku')
            os.makedirs(public_dir)
            with open(os.path.join(etc, 'ku-anchors'), 'w') as f:
                f.write(anchor.split(':')[2] + '\n')
            os.symlink(paths.IPA_CA_CRT, os.path.join(etc, 'ca.crt'))
            with open(os.path.join(public_dir, 'realm.json'), 'w') as f:
                json.dump({'realm': self.api.env.realm,
                           'fqdn': self.api.env.host,
                           'servers': [self.api.env.host]}, f)
            env = os.environ.copy()
            env.update(KRB5CCNAME=credential, GSS_USE_PROXY='1',
                       KUIPA_ROOT=root,
                       KUIPA_USER_DIR=os.path.join(root, 'user'))
            result = ipautil.run(
                [paths.KUIPA, 'seal', 'admin-revoke',
                 entry.single_value['ipakusealowner'],
                 entry.single_value['ipakusealname']],
                env=env, raiseonerr=False, capture_output=True,
                capture_error=True)
            if result.returncode:
                raise errors.ExecutionError(
                    message=_('Audited kuipa revocation failed: '
                              '%(error)s') % {'error': result.error_log})
        return dict(result=True, value=cn)


@register()
class sealconfig(LDAPObject):
    object_name = _('kuipa seal configuration')
    container_dn = _LIMITS
    default_attributes = ['ipakuseallimits']
    permission_filter_objectclasses = ['ipaKURealmConfig']
    label = _('kuipa seal configuration')
    label_singular = _('kuipa seal configuration')
    takes_params = (Str('ipakuseallimits?', validate_limits, cli_name='limits',
                        label=_('Seal limits (JSON)')),)
    managed_permissions = {
        'System: Read kuipa Seal Limits': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermlocation': DN(_LIMITS, api.env.basedn),
            'ipapermdefaultattr': {'cn', 'objectclass', 'ipakuseallimits'},
            'default_privileges': {_PRIVILEGE},
        },
        'System: Modify kuipa Seal Limits': {
            'ipapermright': {'write'},
            'ipapermlocation': DN(_LIMITS, api.env.basedn),
            'ipapermdefaultattr': {'ipakuseallimits'},
            'default_privileges': {_PRIVILEGE},
        },
    }

    def get_dn(self, *keys, **kwargs):
        return DN(self.container_dn, self.api.env.basedn)


@register()
class sealconfig_show(LDAPRetrieve):
    __doc__ = _('Show kuipa realm seal limits.')


@register()
class sealconfig_mod(LDAPUpdate):
    __doc__ = _('Set kuipa realm seal limits.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        value = entry_attrs.single_value.get('ipakuseallimits')
        if value:
            error = validate_limits(_, value)
            if error:
                raise errors.ValidationError(name='limits', error=error)
        return dn
