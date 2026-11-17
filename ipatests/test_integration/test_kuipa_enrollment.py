# Copyright (C) 2026 FreeIPA Contributors.  See COPYING for license.

import re

from pytest_sourceorder import ordered

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.kuipa_common import stage


@ordered
class KuipaEnrollmentTests:
    """A host-add credential enrolls through the normal client installer."""

    @classmethod
    @stage('enrollment')
    def stage_enrollment(cls):
        for client in cls.clients:
            cls.reset_client(client)

    def enrollment_string(self, client):
        tasks.kinit_admin(self.master)
        created = self.master.run_command([
            'env', 'LC_ALL=C', 'ipa', 'host-add', client.hostname,
            '--force', '--random',
        ])
        match = re.search(r'^\s*Enrollment string:\s*(ipa-ku1:\S+)',
                          created.stdout_text, re.MULTILINE)
        assert match is not None
        return match.group(1)

    def test_otp_enrollment_string(self):
        self.stage_enrollment()
        master, client = self.master, self.clients[0]
        enrollment = self.enrollment_string(client)
        parts = enrollment.split(':')
        assert len(parts) == 5 and parts[-1]
        command = [
            'ipa-client-install', '--unattended', '--no-ntp', '-W',
            '--domain', master.domain.name, '--server', master.hostname,
        ]
        joined = client.run_command(command, stdin_text=enrollment + '\n')
        assert joined.returncode == 0
        assert enrollment not in joined.stdout_text + joined.stderr_text
        client.run_command(['test', '-s', '/etc/ipa/ku-anchors'])
        client.run_command([
            'kinit', '-k', '-t', '/etc/krb5.keytab',
            'host/{}@{}'.format(client.hostname, master.domain.realm),
        ])
        log = client.get_file_contents('/var/log/ipaclient-install.log',
                                       encoding='utf-8')
        assert enrollment not in log
        assert parts[-1] not in log
        tasks.uninstall_client(client)
        client.run_command(['test', '!', '-e', '/etc/ipa/ku-anchors'])
        client.run_command([
            'test', '!', '-e', '/var/lib/ipa-client/ku/state.json',
        ])
        # the uninstall restored the resolver; later areas need the master
        client.resolver.backup()
        client.resolver.setup_resolver(master.ip)

    def test_wrong_anchor_does_not_fall_back_with_force(self):
        self.stage_enrollment()
        client = self.clients[1]
        parts = self.enrollment_string(client).split(':')
        parts[2] = ('A' if parts[2][0] != 'A' else 'B') + parts[2][1:]
        wrong = ':'.join(parts)
        refused = client.run_command([
            'ipa-client-install', '--unattended', '--force', '--no-ntp', '-W',
            '--domain', self.master.domain.name, '--server',
            self.master.hostname,
        ], stdin_text=wrong + '\n', raiseonerr=False)
        assert refused.returncode != 0
        assert wrong not in refused.stdout_text + refused.stderr_text
