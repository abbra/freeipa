# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

import json

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestKuipaServerEnrollment(IntegrationTest):
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        cls.master.run_command([
            'su', '-s', '/bin/sh', '-c',
            'test -r /etc/ipa/ca.crt && test -r /etc/ipa/ku/realm.json',
            'ipaapi',
        ])
        tasks.install_replica(cls.master, cls.replicas[0], setup_ca=False,
                              promote=False, extra_args=['--no-ntp'])

    @classmethod
    def uninstall(cls, mh):
        tasks.uninstall_master(cls.replicas[0])
        tasks.uninstall_master(cls.master)

    def test_daemon_keytab_is_brokered(self):
        for host in (self.master, self.replicas[0]):
            config = json.loads(host.get_file_contents(
                '/etc/ipa/kuipad.json', encoding='utf-8'))
            assert config['gssproxy'] is True
            assert config['keys']['broker'] == '/run/ipa/kuipad-keys.sock'
            assert config['keytab'] == '/etc/ipa/kuipad.keytab'
            assert host.run_command([
                'stat', '-c', '%U:%G %a', config['keytab'],
            ]).stdout_text.strip() == 'root:root 600'
            assert host.run_command([
                'stat', '-c', '%U:%G %a', '/etc/ipa/kuipad.json',
            ]).stdout_text.strip() == 'root:kuipad 640'
            gssproxy = host.get_file_contents(
                '/etc/gssproxy/20-kuipad.conf', encoding='utf-8')
            # the custody broker accepts custody callers' tokens itself
            assert '[service/kuipad-keys]' in gssproxy
            assert 'program = /usr/libexec/kuipad' in gssproxy
            host.run_command([
                'su', '-s', '/bin/sh', '-c',
                'test ! -r /etc/ipa/kuipad.keytab && '
                'test ! -w /etc/ipa && '
                'test -w /var/lib/ipa/ku',
                'kuipad',
            ])

    def test_replica_fetches_custody_secret(self):
        replica = self.replicas[0]
        directory = replica.run_command(
            ['mktemp', '-d', '-p', '/tmp', 'kuipa-custody-XXXXXX']
        ).stdout_text.strip()
        output = directory + '/dmhash.json'
        try:
            replica.run_command([
                'kuipa', 'keys', 'fetch', 'dm/DMHash', '--out', output,
            ])
            replica.run_command([
                'python3', '-c',
                'import json,sys; '
                'assert json.load(open(sys.argv[1]))["dmhash"]',
                output,
            ])
        finally:
            replica.run_command(['rm', '-f', output])
            replica.run_command(['rmdir', directory])

    def test_servers_are_enrolled_and_authenticate(self):
        for host in (self.master, self.replicas[0]):
            status = json.loads(host.run_command(
                ['kuipa', '--json', 'status']).stdout_text)
            assert status['enrolled'] is True
            assert status['principal'] == 'host/{}@{}'.format(
                host.hostname, host.domain.realm)
            assert status['kvno'] is not None
            assert status['anchors']
            host.run_command([
                'env', 'KRB5CCNAME=FILE:/tmp/kuipa-server-enrollment-test',
                'kinit', '-k', '-t', '/etc/krb5.keytab', status['principal'],
            ])

    def test_seal_administration_uses_public_realm(self):
        host = self.master
        tasks.kinit_admin(host)
        created = host.run_command([
            'env', 'KUIPA_USER_DIR=/tmp/kuipa-server-seal-test',
            'kuipa', '--json', 'seal', 'create', 'server-realm-test',
            '--require', 'ticket',
        ])
        seal_id = json.loads(created.stdout_text)['seals'][0]['id']
        host.run_command(['ipa', 'seal-revoke', seal_id])
        shown = host.run_command(['ipa', 'seal-show', seal_id])
        assert 'revoked' in shown.stdout_text

    def test_upgrade_does_not_reenroll(self):
        host = self.master
        before = json.loads(host.run_command(
            ['kuipa', '--json', 'status']).stdout_text)
        host.run_command(['ipa-server-upgrade'])
        after = json.loads(host.run_command(
            ['kuipa', '--json', 'status']).stdout_text)
        assert after['enrolled'] is True
        assert after['principal'] == before['principal']
        assert after['kvno'] == before['kvno']

        # Simulate a server installed before kuipa host enrollment existed.
        host.run_command(['rm', '/var/lib/ipa-client/ku/state.json'])
        host.run_command(['ipa-server-upgrade'])
        migrated = json.loads(host.run_command(
            ['kuipa', '--json', 'status']).stdout_text)
        assert migrated['enrolled'] is True
        assert migrated['principal'] == before['principal']
        # adopt records state only: the keytab is not rekeyed
        assert migrated['kvno'] == before['kvno']
        host.run_command([
            'env', 'KRB5CCNAME=FILE:/tmp/kuipa-server-upgrade-test',
            'kinit', '-k', '-t', '/etc/krb5.keytab', migrated['principal'],
        ])
