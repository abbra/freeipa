# Copyright (C) 2026 FreeIPA Contributors.  See COPYING for license.

import re

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestKuipaEnrollment(IntegrationTest):
    """A host-add credential enrolls through the normal client installer."""

    num_clients = 2

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        for client in cls.clients:
            client.resolver.backup()
            client.resolver.setup_resolver(cls.master.ip)

    @classmethod
    def uninstall(cls, mh):
        for client in cls.clients:
            tasks.uninstall_client(client)
        tasks.uninstall_master(cls.master)

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

    def test_wrong_anchor_does_not_fall_back_with_force(self):
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
