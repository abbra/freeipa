# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

import base64
import json
import os
import secrets

from ipalib import _, api, errors, ngettext, output
from ipalib.parameters import Str
from ipalib.plugable import Registry
from ipalib.request import context
from ipapython.dn import DN
from .baseldap import (
    LDAPObject, LDAPQuery, LDAPRetrieve, LDAPSearch)
from .seal import kuipa_session

__doc__ = _("""
Approvals

Pending requests that wait for M of N approvers of a kuipa seal.

A workflow that needs approval (certificate issuance is the first) seals its
request to a kuipa seal whose policy has approvals, and stores the pending
request here: its kind, its requester, the seal, kuipa's release request and
the workflow's own data as JSON. Approvers inspect requests with
"ipa approval-find" and "ipa approval-show", and decide with
"ipa approval-approve" or "ipa approval-deny". The requester then repeats
the workflow's own command with the approval ID, and the workflow proceeds
only with exactly what was approved.

EXAMPLES:

 List the pending requests of a kind and approve one:
   ipa approval-find --kind=cert-request
   ipa approval-approve 4c1f...
""")

register = Registry()

_SEALS = DN(('cn', 'seals'), ('cn', 'kuipa'), ('cn', 'etc'))
_STORE = DN(('cn', 'approvals'), ('cn', 'kuipa'), ('cn', 'etc'))
_ATTRS = ['ipakuapprovalkind', 'ipakuapprovalrequester', 'ipakuapprovalseal',
          'ipakuapprovalrelease', 'ipakuapprovalsealed', 'ipakuapprovaldata']


def canonical_seal(reference):
    """OWNER/NAME with the owner a full principal of this realm or another."""
    owner, _sep, name = reference.rpartition('/')
    if not owner or not name:
        raise errors.ValidationError(
            name='seal', error=_('write the seal OWNER/NAME'))
    if '@' not in owner:
        owner += '@' + api.env.realm
    return '{}/{}'.format(owner, name)


def seal_problem(ldap, seal):
    """Why `seal` (OWNER/NAME) cannot gate a workflow, or None.

    IPA opens the sealed request with the requester's ticket alone, and kuipa
    must be able to count approvals: the seal needs approvals, a ticket
    factor and nothing IPA cannot supply (a device, a passkey), and no
    offline sessions, which release files without a server.
    """
    owner, _sep, name = seal.rpartition('/')
    entries = ldap.get_entries(
        DN(_SEALS, api.env.basedn), ldap.SCOPE_ONELEVEL,
        ldap.make_filter({'ipakusealowner': owner, 'ipakusealname': name},
                         rules=ldap.MATCH_ALL),
        ['ipakusealstate', 'ipakusealpolicy'])
    if not entries:
        return _('seal %s not found, or you may not read it') % seal
    entry = entries[0]
    if entry.single_value.get('ipakusealstate') != 'enabled':
        return _('seal %s is not enabled') % seal
    policy = json.loads(entry.single_value.get('ipakusealpolicy') or '{}')
    factors = policy.get('factors') or {}
    approvals = policy.get('approvals') or {}
    if not approvals.get('m'):
        return _('seal %s requires no approvals') % seal
    if not factors.get('ticket'):
        return _('seal %s does not open with a Kerberos ticket') % seal
    if factors.get('device') or factors.get('passkey'):
        return _('seal %s needs a device or a passkey, which a request '
                 'made through IPA cannot give') % seal
    if (policy.get('sessions') or {}).get('offline'):
        return _('seal %s allows offline sessions, which open without '
                 'approvals') % seal
    return None


def _kuipa(run, *args):
    result = run('--json', *args)
    if result.returncode:
        raise errors.ExecutionError(
            message=_('kuipa %(cmd)s failed: %(error)s') % {
                'cmd': ' '.join(args[:2]), 'error': result.error_log})
    return result.output


def create_request(kind, seal, requester, document, reason):
    """Seal `document` (a string), ask for its release, store the request.

    `reason` (at most 512 bytes) is what approvers see in kuipa. Returns
    the approval ID.
    """
    reason = reason.encode()[:512].decode('utf-8', 'ignore')
    with kuipa_session() as (root, run):
        plain = os.path.join(root, 'request.json')
        sealed = plain + '.sealed'
        with open(plain, 'w') as f:
            f.write(document)
        _kuipa(run, 'seal', 'file', seal, plain, '--out', sealed)
        requests = json.loads(_kuipa(
            run, 'seal', 'request', seal, sealed,
            '--reason', reason))['requests']
        with open(sealed, 'rb') as f:
            blob = base64.b64encode(f.read()).decode()
    # the reason names the requester and the request, so it picks ours out
    mine = [r for r in requests if r['reason'] == reason]
    if not mine:
        raise errors.ExecutionError(
            message=_('kuipa did not return the release request'))
    release = max(mine, key=lambda r: r['created'])['id']
    approval_id = secrets.token_hex(16)
    ldap = api.Backend.ldap2
    ldap.add_entry(ldap.make_entry(
        DN(('cn', approval_id), _STORE, api.env.basedn),
        objectclass=['top', 'ipaKUApprovalRequest'], cn=[approval_id],
        ipakuapprovalkind=[kind], ipakuapprovalrequester=[requester],
        ipakuapprovalseal=[seal], ipakuapprovalrelease=[release],
        ipakuapprovalsealed=[blob], ipakuapprovaldata=[document]))
    return approval_id


def redeem_request(approval_id, kind, seal, requester, document):
    """Open the approved request; raise unless it is exactly `document`.

    The entry is writable by anyone, so what approvers saw (the entry's
    data), what was sealed and what the workflow is about to do must all
    agree, and the entry must be for this kind, seal and requester.
    """
    try:
        entry = _load(approval_id)
    except errors.NotFound:
        raise errors.NotFound(
            reason=_('approval request %s not found') % approval_id)
    value = entry.single_value
    if (value.get('ipakuapprovalkind'), value.get('ipakuapprovalseal'),
            value.get('ipakuapprovalrequester'),
            value.get('ipakuapprovaldata')) != (
                kind, seal, requester, document):
        raise errors.ValidationError(
            name='approval_id',
            error=_('approval does not match this request'))
    with kuipa_session() as (root, run):
        sealed = os.path.join(root, 'request.sealed')
        plain = os.path.join(root, 'request.json')
        with open(sealed, 'wb') as f:
            f.write(base64.b64decode(value['ipakuapprovalsealed']))
        _kuipa(run, 'seal', 'open', sealed, '--out', plain,
               '--request', value['ipakuapprovalrelease'])
        with open(plain) as f:
            opened = f.read()
    if opened != document:
        raise errors.ValidationError(
            name='approval_id',
            error=_('approved request differs from this request'))


def _load(approval_id):
    return api.Backend.ldap2.get_entry(
        DN(('cn', approval_id), _STORE, api.env.basedn), _ATTRS)


def gate_seal(dn):
    """The seal gating the entry at `dn`, or None."""
    try:
        entry = api.Backend.ldap2.get_entry(dn, ['ipakuapprovalseal'])
    except errors.NotFound:
        return None
    return entry.single_value.get('ipakuapprovalseal')


def set_gate(ldap, dn, reference):
    """Gate the entry at `dn` by seal `reference` (OWNER/NAME), after
    checking that the seal can do it. Raises NotFound for the entry."""
    entry = ldap.get_entry(dn, ['objectclass'])
    seal = canonical_seal(reference)
    problem = seal_problem(ldap, seal)
    if problem:
        raise errors.ValidationError(name='seal', error=problem)
    if 'ipakuapprovalgated' not in (c.lower() for c in entry['objectclass']):
        entry['objectclass'].append('ipaKUApprovalGated')
    entry['ipakuapprovalseal'] = [seal]
    ldap.update_entry(entry)


def clear_gate(ldap, dn, name):
    """Ungate the entry at `dn`. Raises NotFound or AttrValueNotFound."""
    entry = ldap.get_entry(dn, ['ipakuapprovalseal'])
    if not entry.get('ipakuapprovalseal'):
        raise errors.AttrValueNotFound(attr='ipakuapprovalseal', value=name)
    entry['ipakuapprovalseal'] = []
    ldap.update_entry(entry)


def require_approval(kind, seal, document, approval_id, reason):
    """Let the workflow go on only with an approval of exactly `document`.

    Without `approval_id` a request is made and the call ends with an error
    naming the ID; with one, the approved request is redeemed (an error
    unless it is approved and is this `document` of this caller).
    """
    requester = str(getattr(context, 'principal', None))
    if approval_id:
        redeem_request(approval_id, kind, seal, requester, document)
        return
    approval_id = create_request(kind, seal, requester, document, reason)
    raise errors.ExecutionError(
        message=_('This needs approval. Once approved, repeat the command '
                  'with --approval-id %s') % approval_id)


@register()
class approval(LDAPObject):
    object_name = _('approval request')
    object_name_plural = _('approval requests')
    container_dn = _STORE
    object_class = ['ipaKUApprovalRequest']
    permission_filter_objectclasses = ['ipaKUApprovalRequest']
    default_attributes = ['cn', 'ipaKUApprovalKind',
                          'ipaKUApprovalRequester', 'ipaKUApprovalSeal',
                          'ipaKUApprovalData']
    search_attributes = ['cn', 'ipaKUApprovalKind',
                         'ipaKUApprovalRequester', 'ipaKUApprovalSeal']
    label = _('approval requests')
    label_singular = _('approval request')
    takes_params = (
        Str('cn', cli_name='id', primary_key=True, label=_('Approval ID')),
        Str('ipakuapprovalkind?', cli_name='kind', label=_('Kind'),
            flags={'no_create', 'no_update'}),
        Str('ipakuapprovalrequester?', cli_name='requester',
            label=_('Requester'), flags={'no_create', 'no_update'}),
        Str('ipakuapprovalseal?', cli_name='seal', label=_('Seal'),
            flags={'no_create', 'no_update'}),
        Str('ipakuapprovaldata?', label=_('Request (JSON)'),
            flags={'no_create', 'no_update', 'no_search'}),
    )


@register()
class approval_find(LDAPSearch):
    __doc__ = _('Search for pending approval requests.')
    msg_summary = ngettext('%(count)d request matched',
                           '%(count)d requests matched', 0)


@register()
class approval_show(LDAPRetrieve):
    __doc__ = _('Show an approval request.')


class _approval_decide(LDAPQuery):
    has_output = output.standard_value
    verb = 'approve'

    def execute(self, cn, **options):
        try:
            entry = _load(cn)
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)
        value = entry.single_value
        with kuipa_session() as (_root, run):
            _kuipa(run, 'seal', self.verb, value['ipakuapprovalseal'],
                   value['ipakuapprovalrelease'])
        return dict(result=True, value=cn)


@register()
class approval_approve(_approval_decide):
    __doc__ = _('Approve a request.')
    msg_summary = _('Approved request "%(value)s"')


@register()
class approval_deny(_approval_decide):
    __doc__ = _('Deny a request.')
    msg_summary = _('Denied request "%(value)s"')
    verb = 'deny'
