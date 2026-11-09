# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

import re

from ipapython import ipautil
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

WORDS = '/root/kuipa-recovery-words'
RECIPIENT = '/root/kuipa-recipient.json'
EAB_KEY = '/var/lib/akamu/akamu-ra-agent.key'


class TestKuipaSealedBackup(IntegrationTest):
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def test_sealed_backup_survives_reinstall_and_restore(self):
        master = self.master
        realm = master.domain.realm
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'user-add', 'kuipabackup',
                            '--first', 'Kuipa', '--last', 'Backup'])

        # The recovery key is made once, away from the servers; the three
        # papers it prints are what restores a backup after total loss.
        master.put_file_contents(WORDS, 'six honest words to open the papers')
        made = master.run_command([
            'kuipa', 'backup', 'key', 'create', '--realm', realm,
            '--recovery-file', WORDS, '--out', RECIPIENT])
        papers = re.findall(r'kuipa backup recovery shard.*?(?=\n\n|\Z)',
                            made.stdout_text, re.S)
        assert len(papers) == 3
        two_papers = '\n\n'.join(papers[:2]) + '\n'

        sealed_secret = master.run_command(['sha256sum', EAB_KEY]).stdout_text

        result = master.run_command(
            ['ipa-backup', '-v', '--kuipa', '--kuipa-recipient', RECIPIENT])
        prefix = 'ipaserver.install.ipa_backup: INFO: Backed up to '
        path = next(line[len(prefix):].strip()
                    for line in result.stderr_text.splitlines()
                    if line.startswith(prefix))

        # The card (realm, anchors, recovery key id) is kept with the papers;
        # it is what a brand-new host trusts to open the backup.
        card = master.run_command(['kuipa', 'backup', 'card']).stdout_text
        anchors = re.findall(r'^\s*anchor (\S+)$', card, re.M)
        assert anchors, card

        listing = master.run_command(['ls', path]).stdout_text.split()
        for name in ('ipa-full.tar.kuipa', 'ipa-full.tar.kuipa.kusig',
                     'header', 'header.kusig'):
            assert name in listing, listing
        assert 'ipa-full.tar' not in listing

        # A flipped byte is refused before the papers are asked for.
        tampered = path + '-tampered'
        master.run_command(['cp', '-a', path, tampered])
        master.run_command(
            'printf X | dd of=%s/ipa-full.tar.kuipa bs=1 seek=100 '
            'conv=notrunc' % ipautil.shell_quote(tampered))
        refused = master.run_command(
            ['ipa-restore', '-U', '-p', master.config.dirman_password,
             '--kuipa-realm', realm, '--kuipa-anchor', anchors[0],
             '--kuipa-recovery-file', WORDS, tampered],
            stdin_text=two_papers, raiseonerr=False)
        assert refused.returncode != 0
        master.run_command(['ipa', 'user-show', 'kuipabackup'])

        # Total loss: the new install has its own ahdapa and akamu state,
        # which the restore replaces rather than mixes with.
        tasks.uninstall_master(master)
        tasks.install_master(master, setup_dns=True)
        master.run_command(
            ['ipa-restore', '-U', '-p', master.config.dirman_password,
             '--kuipa-realm', realm, '--kuipa-anchor', anchors[0],
             '--kuipa-recovery-file', WORDS, path],
            stdin_text=two_papers)
        tasks.clear_sssd_cache(master)
        tasks.kinit_admin(master)

        master.run_command(['ipa', 'user-show', 'kuipabackup'])
        assert master.run_command(
            ['kuipa', 'backup', 'card']).stdout_text == card
        assert master.run_command(
            ['sha256sum', EAB_KEY]).stdout_text == sealed_secret
        for service in ('ahdapa', 'akamu', 'kuipad'):
            assert tasks.host_service_active(master, service), service
