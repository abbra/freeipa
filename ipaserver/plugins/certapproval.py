# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

import json

from ipalib import _, api, errors, output
from ipalib.parameters import Str
from ipalib.plugable import Registry
from ipapython.dn import DN
from .approval import (
    clear_gate, create_request, gate_seal, redeem_request, require_approval,
    set_gate)
from .baseldap import LDAPQuery

__doc__ = _("""
Certificate approvals

Require M of N approvers before a certificate is issued from a profile.

A profile tied to a kuipa seal with "ipa certprofile-add-approval" needs
approval. The seal's policy has approvals. The first "ipa cert-request" for
such a profile issues nothing: it seals the request to that seal, asks the
seal's approvers to release it and prints the approval ID. Approvers inspect
the request with "ipa approval-show" and decide with "ipa approval-approve"
or "ipa approval-deny" (see "ipa help approval"). Once enough have approved,
the requester repeats the same "ipa cert-request" with "--approval-id ID"
and the certificate is issued.

The seal must open with a Kerberos ticket alone (no device factor), and
every requester must be a member of it. The approvers named in its policy
decide; the requester never counts. ACME and direct Dogtag access are not
covered, so do not offer an approval profile to them.

EXAMPLES:

 Require approval for profile caIPAserviceCert, using an approvals seal
 made with kuipa (ticket-only, requesters are members):
   ipa certprofile-add-approval caIPAserviceCert --seal admin/certs

 Stop requiring it:
   ipa certprofile-del-approval caIPAserviceCert
""")

register = Registry()

KIND = 'cert-request'
REVOKE_KIND = 'cert-revoke'


def approval_seal(profile_id):
    """The seal gating `profile_id`, or None when it needs no approval."""
    return gate_seal(DN(('cn', profile_id), api.env.container_certprofile,
                        api.env.basedn))


def _document(requester, profile, ca_id, principal, csr_pem):
    return json.dumps(
        {'requester': requester, 'profile': profile, 'ca': ca_id,
         'principal': principal, 'csr': csr_pem}, sort_keys=True)


def create_approval(seal, requester, profile, ca_id, principal, csr_pem,
                    subject):
    """Ask for the approval of a certificate request; return its ID."""
    return create_request(
        KIND, seal, requester,
        _document(requester, profile, ca_id, principal, csr_pem),
        'cert %s for %s by %s, subject %s' % (
            profile, principal, requester, subject))


def redeem_approval(approval_id, seal, requester, profile, ca_id, principal,
                    csr_pem):
    """Raise unless the approved request is exactly this certificate."""
    redeem_request(approval_id, KIND, seal, requester,
                   _document(requester, profile, ca_id, principal, csr_pem))


@register()
class certprofile_add_approval(LDAPQuery):
    __doc__ = _('Require approval by a kuipa seal for a certificate profile.')
    has_output = output.standard_value
    msg_summary = _('Certificates of profile "%(value)s" need approval')
    takes_options = (
        Str('seal', cli_name='seal',
            label=_('Seal'),
            doc=_('kuipa approvals seal, OWNER/NAME')),
    )

    def execute(self, cn, **options):
        try:
            set_gate(self.obj.backend, self.obj.get_dn(cn), options['seal'])
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)
        return dict(result=True, value=cn)


@register()
class certprofile_del_approval(LDAPQuery):
    __doc__ = _('Stop requiring approval for a certificate profile.')
    has_output = output.standard_value
    msg_summary = _('Certificates of profile "%(value)s" need no approval')

    def execute(self, cn, **options):
        try:
            clear_gate(self.obj.backend, self.obj.get_dn(cn), cn)
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)
        return dict(result=True, value=cn)


@register()
class ca_add_revoke_approval(LDAPQuery):
    __doc__ = _('Require approval by a kuipa seal to revoke certificates '
                'of a CA.')
    has_output = output.standard_value
    msg_summary = _('Revoking certificates of CA "%(value)s" needs approval')
    takes_options = (
        Str('seal', cli_name='seal',
            label=_('Seal'),
            doc=_('kuipa approvals seal, OWNER/NAME')),
    )

    def execute(self, cn, **options):
        try:
            set_gate(self.obj.backend, self.obj.get_dn(cn), options['seal'])
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)
        return dict(result=True, value=cn)


@register()
class ca_del_revoke_approval(LDAPQuery):
    __doc__ = _('Stop requiring approval to revoke certificates of a CA.')
    has_output = output.standard_value
    msg_summary = _('Revoking certificates of CA "%(value)s" needs no '
                    'approval')

    def execute(self, cn, **options):
        try:
            clear_gate(self.obj.backend, self.obj.get_dn(cn), cn)
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)
        return dict(result=True, value=cn)


def revocation_gate(ca_dn, serial_number, revocation_reason, approval_id):
    """Let a revocation go on only if its CA's seal (if any) approved it."""
    seal = gate_seal(ca_dn)
    if not seal:
        return
    document = json.dumps(
        {'ca': str(ca_dn), 'serial': str(serial_number),
         'reason': revocation_reason}, sort_keys=True)
    require_approval(
        REVOKE_KIND, seal, document, approval_id,
        'revoke certificate %s (reason %s)' % (
            serial_number, revocation_reason))
