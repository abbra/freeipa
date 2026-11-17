# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

"""A LUKS2 volume on a client, bound to the realm's post-quantum Tang."""

import base64
import json

from pytest_sourceorder import ordered

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.kuipa_common import stage

PASSPHRASE = 'luks-test-passphrase'
IMAGE = '/var/tmp/kuipa-luks.img'
NAME = 'kuipa-luks'
KUIPAD = '/usr/libexec/kuipad'


@ordered
class KuipaClevisTests:
    """clevis luks bind, unlock and regen with the kuipa pin."""

    @classmethod
    @stage('clevis')
    def stage_clevis(cls):
        master, client = cls.master, cls.clients[0]
        cls.reset_client(client)
        tasks.install_client(master, client)
        client.run_command(['dnf', '-y', 'install', 'cryptsetup',
                            'clevis-luks', 'tang-pqc',
                            'clevis-pin-kuipa'])
        # keys of an earlier run survive an uninstall
        master.run_command(['rm', '-rf', '/var/lib/ipa/ku/tang'])
        master.run_command([KUIPAD, 'tang-keygen'])
        master.run_command(['systemctl', 'restart', 'kuipad.service'])
        client.run_command(['truncate', '-s', '64M', IMAGE])
        client.run_command(
            ['cryptsetup', 'luksFormat', '--type', 'luks2', '--batch-mode',
             '--key-file', '-', IMAGE], stdin_text=PASSPHRASE)

    @classmethod
    def cleanup_clevis(cls):
        client = cls.clients[0]
        client.run_command(['cryptsetup', 'close', NAME], raiseonerr=False)
        client.run_command(['rm', '-f', IMAGE], raiseonerr=False)

    @property
    def url(self):
        return 'https://{}/ipa/ku/tang'.format(self.master.hostname)

    def thumbprints(self):
        out = self.master.run_command([KUIPAD, 'tang-thp']).stdout_text
        return out.split()

    def config(self, thp):
        return '{{"url":"{}","thp":"{}"}}'.format(self.url, thp)

    def bind(self, thp, raiseonerr=True):
        return self.clients[0].run_command(
            ['clevis', 'luks', 'bind', '-f', '-d', IMAGE, '-k', '-',
             'kuipa', self.config(thp)],
            stdin_text=PASSPHRASE, raiseonerr=raiseonerr)

    def unlock(self, raiseonerr=True):
        return self.clients[0].run_command(
            ['clevis', 'luks', 'unlock', '-d', IMAGE, '-n', NAME],
            raiseonerr=raiseonerr)

    def close(self):
        self.clients[0].run_command(['cryptsetup', 'close', NAME],
                                    raiseonerr=False)

    def bound(self):
        """(token id, keyslot) of every kuipa binding."""
        # `clevis luks list` only knows Clevis's own pins ("unknown pin
        # 'kuipa'"), so read the LUKS2 tokens
        out = self.clients[0].run_command(
            ['cryptsetup', 'luksDump', '--dump-json-metadata',
             IMAGE]).stdout_text
        self.listing = out

        def pin(token):
            # the pin is named in the JWE's protected header
            protected = token['jwe']['protected']
            protected += '=' * (-len(protected) % 4)
            header = json.loads(base64.urlsafe_b64decode(protected))
            return header['clevis']['pin']

        return sorted(
            (tid, slot) for tid, token in json.loads(out)['tokens'].items()
            if token.get('type') == 'clevis' and pin(token) == 'kuipa'
            for slot in token['keyslots'])

    def slots(self):
        return [slot for _, slot in self.bound()]

    def test_advertisement_is_verified(self):
        self.stage_clevis()
        client = self.clients[0]
        out = client.run_command(['tang-pqc', 'adv', self.url]).stdout_text
        assert self.thumbprints()[0] in out

    def test_wrong_thumbprint_is_refused(self):
        self.stage_clevis()
        wrong = self.thumbprints()[0]
        wrong = ('A' if wrong[0] != 'A' else 'B') + wrong[1:]
        assert self.bind(wrong, raiseonerr=False).returncode != 0
        assert self.slots() == []

    def test_bind_and_unlock(self):
        self.stage_clevis()
        self.bind(self.thumbprints()[0])
        assert len(self.slots()) == 1, self.listing
        self.unlock()
        try:
            client = self.clients[0]
            client.run_command(['test', '-b', '/dev/mapper/' + NAME])
            client.run_command(['mkfs.ext4', '-q', '/dev/mapper/' + NAME])
            client.run_command(['mkdir', '-p', '/mnt/kuipa-luks'])
            client.run_command(['mount', '/dev/mapper/' + NAME,
                                '/mnt/kuipa-luks'])
            client.put_file_contents('/mnt/kuipa-luks/data', 'sealed\n')
            client.run_command(['umount', '/mnt/kuipa-luks'])
        finally:
            self.close()
        self.unlock()
        try:
            client.run_command(['mount', '/dev/mapper/' + NAME,
                                '/mnt/kuipa-luks'])
            assert client.get_file_contents(
                '/mnt/kuipa-luks/data', encoding='utf-8') == 'sealed\n'
            client.run_command(['umount', '/mnt/kuipa-luks'])
        finally:
            self.close()

    def test_unlock_needs_the_server(self):
        self.stage_clevis()
        master = self.master
        master.run_command(['systemctl', 'stop', 'kuipad.service',
                            'kuipad.socket'])
        try:
            assert self.unlock(raiseonerr=False).returncode != 0
            self.clients[0].run_command(['test', '!', '-e',
                                         '/dev/mapper/' + NAME])
        finally:
            master.run_command(['systemctl', 'start', 'kuipad.socket'])
            master.run_command(['systemctl', 'restart', 'kuipad.service'])
        self.unlock()
        self.close()

    def test_rotation_and_rebind(self):
        self.stage_clevis()
        master, client = self.master, self.clients[0]
        old = self.thumbprints()
        master.run_command([KUIPAD, 'tang-rotate'])
        master.run_command(['systemctl', 'restart', 'kuipad.service'])
        new = self.thumbprints()
        assert new != old
        # a retired key still answers the existing binding
        self.unlock()
        self.close()
        # Clevis's `luks regen` cannot read this pin (it goes through
        # `luks list`), so rebind: a new slot, then drop the old one
        before = self.bound()
        self.bind(new[0])
        after = self.slots()
        assert len(after) == len(before) + 1, self.listing
        for token, slot in before:
            # `clevis luks unbind` cannot read this pin either
            client.run_command(['cryptsetup', 'token', 'remove',
                                '--token-id', token, IMAGE])
            client.run_command(['cryptsetup', 'luksKillSlot', '--batch-mode',
                                '--key-file', '-', IMAGE, slot],
                               stdin_text=PASSPHRASE)
        assert len(self.slots()) == 1
        # once every client has rebound, the retired keys can go
        master.run_command(
            'rm -f /var/lib/ipa/ku/tang/.*.jwk', raiseonerr=False)
        master.run_command(['systemctl', 'restart', 'kuipad.service'])
        self.unlock()
        self.close()

    def test_initramfs_carries_the_pin(self):
        self.stage_clevis()
        client = self.clients[0]
        client.run_command(['dnf', '-y', 'install', 'dracut-network',
                            'clevis-dracut'])
        client.run_command(
            'dracut --force --no-hostonly --add "clevis clevis-pin-kuipa" '
            '/var/tmp/kuipa-initrd.img "$(uname -r)"')
        listing = client.run_command(
            ['lsinitrd', '/var/tmp/kuipa-initrd.img']).stdout_text
        assert 'clevis-decrypt-kuipa' in listing
        assert 'usr/bin/tang-pqc' in listing
        client.run_command(['rm', '-f', '/var/tmp/kuipa-initrd.img'])
