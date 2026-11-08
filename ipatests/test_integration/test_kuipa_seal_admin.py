# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

import json
import re

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestKuipaSealAdministration(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        master, client = cls.master, cls.clients[0]
        tasks.install_master(master, setup_dns=True)
        config = json.loads(master.get_file_contents('/etc/ipa/kuipad.json',
                                                     encoding='utf-8'))
        config['tlog_head_interval'] = 0
        master.put_file_contents('/etc/ipa/kuipad.json', json.dumps(config))
        master.run_command(['systemctl', 'restart', 'kuipad.service'])
        client.resolver.backup()
        client.resolver.setup_resolver(master.ip)
        tasks.kinit_admin(master)
        created = master.run_command(['env', 'LC_ALL=C', 'ipa', 'host-add',
                                      client.hostname, '--force', '--random'])
        match = re.search(r'^\s*Enrollment string:\s*(ipa-ku1:\S+)',
                          created.stdout_text, re.MULTILINE)
        assert match is not None
        client.run_command(['ipa-client-install', '--unattended', '--no-ntp',
                            '-W', '--domain', master.domain.name, '--server',
                            master.hostname], stdin_text=match.group(1) + '\n')
        for user in ('seal-owner', 'seal-guest'):
            tasks.user_add(master, user, password='FirstPass123!')
            client.run_command([
                'env', 'KRB5CCNAME=FILE:/tmp/{}.ccache'.format(user),
                'kinit', user,
            ], stdin_text='FirstPass123!\nSecondPass456!\nSecondPass456!\n')

    @classmethod
    def uninstall(cls, mh):
        tasks.uninstall_client(cls.clients[0])
        tasks.uninstall_master(cls.master)

    def test_administrative_revocation_and_limits(self):
        master, client = self.master, self.clients[0]
        owner = ['env', 'KRB5CCNAME=FILE:/tmp/seal-owner.ccache',
                 'KUIPA_USER_DIR=/tmp/seal-owner']
        guest = ['env', 'KRB5CCNAME=FILE:/tmp/seal-guest.ccache',
                 'KUIPA_USER_DIR=/tmp/seal-guest']
        created = client.run_command(owner + [
            'kuipa', '--json', 'seal', 'create', 'admin-test',
            '--require', 'ticket',
        ])
        seal_id = json.loads(created.stdout_text)['seals'][0]['id']
        source = '/tmp/kuipa-seal-test.txt'
        client.put_file_contents(source, 'test data\n')
        client.run_command(
            owner + ['kuipa', 'seal', 'file', 'admin-test', source])
        opened = client.run_command(owner + [
            'kuipa', 'seal', 'open', source + '.sealed', '--out', '-',
        ])
        assert opened.stdout_text == 'test data\n'
        client.run_command(
            owner + ['kuipa', '--json', 'tlog', 'watch', 'admin-test'])

        refused = client.run_command(guest + [
            'kuipa', 'seal', 'admin-revoke',
            'seal-owner@{}'.format(master.domain.realm), 'admin-test',
        ], raiseonerr=False)
        assert refused.returncode != 0
        denied = client.run_command(guest + [
            'ipa', 'seal-revoke', seal_id,
        ], raiseonerr=False)
        assert denied.returncode != 0
        tasks.kinit_admin(master)
        found = master.run_command([
            'ipa', 'seal-find', '--owner=seal-owner@{}'.format(
                master.domain.realm),
        ])
        assert seal_id in found.stdout_text
        assert 'Opening needs: Kerberos ticket' in found.stdout_text
        visible = master.run_command(['ipa', 'seal-show', seal_id])
        assert 'admin-test' in visible.stdout_text
        assert 'Opening needs: Kerberos ticket' in visible.stdout_text
        raw = master.run_command(['ipa', 'seal-show', seal_id, '--raw'])
        assert '"ticket":true' in raw.stdout_text
        master.run_command(['ipa', 'seal-revoke', seal_id])
        shown = master.run_command(['ipa', 'seal-show', seal_id])
        assert 'revoked' in shown.stdout_text
        refused = client.run_command(owner + [
            'kuipa', 'seal', 'open', source + '.sealed', '--out', '-',
        ], raiseonerr=False)
        assert refused.returncode != 0
        watched = client.run_command(owner + [
            'kuipa', '--json', 'tlog', 'watch', 'admin-test',
        ], raiseonerr=False)
        assert any(event['action'] == 'revoke'
                   for event in json.loads(watched.stdout_text)['events'])

        limits = {'max_lifetime': 34560000, 'max_seals': 0, 'max_devices': 8,
                  'max_reauth': 43200, 'without_device': True,
                  'descriptor_age': 2592000}
        try:
            master.run_command(['ipa', 'sealconfig-mod', '--limits',
                                json.dumps(limits)])
            denied = client.run_command(owner + [
                'kuipa', 'seal', 'create', 'not-allowed', '--require', 'ticket',
            ], raiseonerr=False)
            assert denied.returncode != 0
            invalid = master.run_command([
                'ipa', 'sealconfig-mod',
                '--setattr=ipakuseallimits={"max_seals":true}',
            ], raiseonerr=False)
            assert invalid.returncode != 0
        finally:
            master.run_command(['ipa', 'sealconfig-mod', '--limits='])
