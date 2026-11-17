# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

import json
import re

from pytest_sourceorder import ordered

from ipatests.pytest_ipa.integration import tasks

PROFILE = 'caIPAserviceCert'
FIRST, SECOND = 'FirstPass123!', 'SecondPass456!'


class KuipaCertApprovalBase:
    """Helpers: an admin requester, approvers, a service and its CSR."""

    @classmethod
    def prepare(cls):
        master = cls.master
        # per-user kuipa state and files of an earlier run name old seals
        master.run_command('rm -rf /tmp/kuipa-* /tmp/*.sealed /tmp/*.kusig')
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'group-add', 'pki-approvers'])
        tasks.user_add(master, 'appr1', password=FIRST)
        master.run_command(['ipa', 'group-add-member', 'pki-approvers',
                            '--users', 'appr1'])
        master.run_command(
            ['env', 'KRB5CCNAME=FILE:/tmp/appr1.ccache', 'kinit', 'appr1'],
            stdin_text='{0}\n{1}\n{1}\n'.format(FIRST, SECOND))
        master.run_command(
            ['env', 'KRB5CCNAME=FILE:/tmp/admin.ccache', 'kinit', 'admin'],
            stdin_text=master.config.admin_password + '\n')
        cls.service = 'HTTP/app.{}'.format(master.domain.name)
        master.run_command(['ipa', 'host-add',
                            'app.{}'.format(master.domain.name), '--force'])
        master.run_command(['ipa', 'service-add', cls.service, '--force'])
        master.run_command([
            'openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', '/tmp/app.key', '-out', '/tmp/app.csr',
            '-subj', '/CN=app.{}'.format(master.domain.name),
            '-addext', 'subjectAltName=DNS:app.{}'.format(master.domain.name),
        ])

    def kuipa_as(self, user, *args, **kw):
        return self.master.run_command(
            ['env', 'KRB5CCNAME=FILE:/tmp/{}.ccache'.format(user),
             'KUIPA_USER_DIR=/tmp/kuipa-{}'.format(user), *args], **kw)

    def request(self, *extra, csr='/tmp/app.csr'):
        return self.kuipa_as(
            'admin', 'ipa', 'cert-request', csr, '--principal', self.service,
            '--profile-id', PROFILE, *extra, raiseonerr=False)

    def decide(self, user, verb, approval_id):
        return self.kuipa_as(
            user, 'ipa', 'approval-' + verb, approval_id,
            raiseonerr=False)

    def gate(self):
        """Seal with two approvals from pki-approvers; tie the profile."""
        realm = self.master.domain.realm
        # a seal without approvals cannot gate a profile
        self.kuipa_as('admin', 'kuipa', 'seal', 'create', 'plain',
                      '--require', 'ticket')
        tasks.kinit_admin(self.master)
        refused = self.master.run_command([
            'ipa', 'certprofile-add-approval', PROFILE, '--seal',
            'admin/plain'], raiseonerr=False)
        assert refused.returncode != 0
        self.kuipa_as('admin', 'kuipa', 'seal', 'create', 'certs',
                      '--require', 'ticket', '--approvals', '2',
                      '--approver-group', 'pki-approvers')
        self.master.run_command([
            'ipa', 'certprofile-add-approval', PROFILE, '--seal',
            'admin@{}/certs'.format(realm)])

    def issue_with_approvals(self, second):
        """Run the approval flow; `second` is the other approver's ccache
        name (a user of pki-approvers besides appr1)."""
        master = self.master
        self.gate()

        first = self.request()
        assert first.returncode != 0
        match = re.search(r'--approval-id ([0-9a-f]{32})', first.stderr_text)
        assert match, first.stderr_text
        approval_id = match.group(1)

        shown = self.kuipa_as('appr1', 'ipa', 'approval-show',
                              approval_id)
        assert self.service in shown.stdout_text

        # nobody approved yet
        assert self.request('--approval-id', approval_id).returncode != 0
        # the requester is not an approver
        assert self.decide('admin', 'approve', approval_id).returncode != 0
        assert self.decide('appr1', 'approve', approval_id).returncode == 0
        # one of two
        assert self.request('--approval-id', approval_id).returncode != 0

        assert self.decide(second, 'approve', approval_id).returncode == 0
        # an approval is for the request it was made for
        master.run_command([
            'openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', '/tmp/other.key', '-out', '/tmp/other.csr',
            '-subj', '/CN=app.{}'.format(master.domain.name),
            '-addext',
            'subjectAltName=DNS:other.{}'.format(master.domain.name)])
        other = self.request('--approval-id', approval_id,
                             csr='/tmp/other.csr')
        assert other.returncode != 0

        issued = self.request('--approval-id', approval_id)
        assert issued.returncode == 0, issued.stderr_text
        assert 'Certificate:' in issued.stdout_text
        # one issuance per approval
        assert self.request('--approval-id', approval_id).returncode != 0


@ordered
class KuipaCertApprovalTests(KuipaCertApprovalBase):
    """Certificates of a gated profile need two approvals.

    The deployment runs prepare() and adds the appr2 approver.
    """

    def test_issuance_needs_two_approvals(self):
        self.issue_with_approvals('appr2')

    def test_revocation_needs_two_approvals(self):
        master = self.master
        realm = master.domain.realm
        found = master.run_command([
            'ipa', 'cert-find', '--subject',
            'app.{}'.format(master.domain.name)])
        serial = re.search(r'Serial number: (\d+)', found.stdout_text).group(1)
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'ca-add-revoke-approval', 'ipa', '--seal',
                            'admin@{}/certs'.format(realm)])

        def revoke(*extra):
            return self.kuipa_as('admin', 'ipa', 'cert-revoke', serial,
                                 *extra, raiseonerr=False)

        first = revoke()
        assert first.returncode != 0
        approval_id = re.search(r'--approval-id ([0-9a-f]{32})',
                                first.stderr_text).group(1)
        assert revoke('--approval-id', approval_id).returncode != 0
        assert self.decide('appr1', 'approve', approval_id).returncode == 0
        assert self.decide('appr2', 'approve', approval_id).returncode == 0
        # an approval is for this revocation, not another reason
        assert revoke('--approval-id', approval_id,
                      '--revocation-reason', '1').returncode != 0
        done = revoke('--approval-id', approval_id)
        assert done.returncode == 0, done.stderr_text
        shown = master.run_command(['ipa', 'cert-show', serial])
        assert 'Revoked' in shown.stdout_text


@ordered
class KuipaCertApprovalTrustedTests(KuipaCertApprovalBase):
    """An AD user with an ID override in the default trust view approves.

    The deployment (test_kuipa_trust.py) sets up the trust, prepare(), the
    override, the approver membership and the aduser ticket.
    """

    def test_issuance_with_a_trusted_realm_approver(self):
        self.issue_with_approvals('aduser')

    def test_trusted_realm_user_in_other_seal_options(self):
        master = self.master
        realm = master.domain.realm
        basedn = ','.join('dc=' + p for p in master.domain.name.split('.'))
        ad = 'testuser@{}'.format(self.ad.domain.name.upper())
        team = 'admin@{}/team'.format(realm)
        created = self.kuipa_as('admin', 'kuipa', '--json', 'seal', 'create',
                                'team', '--require', 'ticket')
        seal_id = json.loads(created.stdout_text)['seals'][0]['id']

        # a member by name opens what is sealed to the seal ...
        self.kuipa_as('admin', 'kuipa', 'seal', 'share', 'team',
                      '--user', ad)
        master.put_file_contents('/tmp/team.txt', 'team data\n')
        self.kuipa_as('aduser', 'kuipa', 'seal', 'file', team,
                      '/tmp/team.txt')
        opened = self.kuipa_as('aduser', 'kuipa', 'seal', 'open',
                               '/tmp/team.txt.sealed', '--out', '-')
        assert opened.stdout_text == 'team data\n'
        # ... but cannot own one
        denied = self.kuipa_as('aduser', 'kuipa', 'seal', 'create', 'mine',
                               '--require', 'ticket', raiseonerr=False)
        assert denied.returncode != 0
        # as a manager they share with others
        self.kuipa_as('admin', 'kuipa', 'seal', 'share', 'team',
                      '--manager', '--user', ad)
        self.kuipa_as('aduser', 'kuipa', 'seal', 'share', team,
                      '--user', 'appr1')

        # the signing policy: by full name, and never by a bare name of
        # this realm's user
        def policy(users):
            tasks.ldapmodify_dm(master, (
                'dn: cn=sign-policy,cn=kuipa,cn=etc,{}\n'
                'changetype: modify\nreplace: ipaKUSignPolicy\n'
                'ipaKUSignPolicy: {}\n').format(
                    basedn, json.dumps({'purposes': {
                        'ipa-backup': {'groups': ['ipaservers']},
                        'blob': {'users': users}}})))
        master.put_file_contents('/tmp/blob.txt', 'sign me\n')
        policy(['testuser'])
        refused = self.kuipa_as('aduser', 'kuipa', 'sign', 'blob',
                                '/tmp/blob.txt', '--purpose', 'blob',
                                raiseonerr=False)
        assert refused.returncode != 0
        policy([ad])
        self.kuipa_as('aduser', 'kuipa', 'sign', 'blob', '/tmp/blob.txt',
                      '--purpose', 'blob')
        master.run_command(['test', '-s', '/tmp/blob.txt.kusig'])

        # a seal administrator through an IPA group holding the override
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'group-add', 'sealadm'])
        master.run_command(['ipa', 'group-add-member', 'sealadm',
                            '--idoverrideusers', self.aduser])
        master.run_command(['ipa', 'role-add', 'AD seal administrators'])
        master.run_command(['ipa', 'role-add-privilege',
                            'AD seal administrators', '--privileges',
                            'KUIPA Seal Administrators'])
        master.run_command(['ipa', 'role-add-member',
                            'AD seal administrators', '--groups', 'sealadm'])
        self.kuipa_as('aduser', 'ipa', 'seal-revoke', seal_id)
        shown = master.run_command(['ipa', 'seal-show', seal_id])
        assert 'revoked' in shown.stdout_text

    def test_unknown_trusted_realm_user_is_refused(self):
        # the realm refuses a trusted realm's user who has no override
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'idoverrideuser-del',
                                 'Default Trust View', self.aduser])
        refused = self.decide('aduser', 'approve', '0' * 32)
        assert refused.returncode != 0
        listed = self.kuipa_as('aduser', 'kuipa', 'seal', 'list',
                               raiseonerr=False)
        assert listed.returncode != 0
