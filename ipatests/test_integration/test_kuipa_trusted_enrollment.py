# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

import json
import re
from collections import Counter

from pytest_sourceorder import ordered

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.kuipa_common import stage


@ordered
class KuipaTrustedEnrollmentTests:
    """An AD user with an ID override enrolls a client with kuipa.

    A mixin of TestKuipaTrust, which installs the two-way trust, the
    enrollers group and role, and sets `cls.ad`.
    """

    @classmethod
    @stage('trusted_enrollment')
    def stage_trusted_enrollment(cls):
        # the tests enroll client1 with a host entry of their own
        cls.reset_client(cls.clients[0])

    @classmethod
    def cleanup_trusted_enrollment(cls):
        cls.clients[0].run_command(['rm', '-rf', '/tmp/kuipa-krb5'],
                                   raiseonerr=False)

    def measure_ldap(self, label):
        """Log how much of the LDAP database kuipa data takes.

        Sizes are LDIF bytes of the entries as the server returns them
        (user and operational attributes), by kuipa container, plus the
        files of the database on disk. The full report is appended to
        /root/kuipa-ldap-sizes.txt on the master.
        """
        master = self.master
        suffix = ','.join('dc=' + p for p in master.domain.name.split('.'))
        dump = master.run_command([
            'ldapsearch', '-Q', '-LLL', '-o', 'ldif-wrap=no',
            '-H', 'ldapi://%2Frun%2Fslapd-{}.socket'.format(
                master.domain.realm.replace('.', '-')),
            '-Y', 'EXTERNAL',
            '-b', suffix, '-s', 'sub', '(objectClass=*)', '*', '+'],
            log_stdout=False).stdout_text
        sizes, counts = Counter(), Counter()
        detail = []
        for entry in dump.split('\n\n'):
            if not entry.strip():
                continue
            dn = entry.split('\n', 1)[0].partition(': ')[2]
            size = len(entry.encode()) + 2
            rdns = [r.strip() for r in dn.split(',')]
            if 'cn=kuipa,cn=etc' in dn:
                tail = rdns[:rdns.index('cn=kuipa')]
                group = 'kuipa ' + (tail[-1] if tail else 'container')
            elif re.search(r'^ipaku\w*:', entry, re.M | re.I):
                group = 'other entries with kuipa attributes'
            else:
                group = 'everything else'
            sizes[group] += size
            counts[group] += 1
            if group != 'everything else':
                detail.append((size, dn))
        ku_attrs = Counter()
        for m in re.finditer(r'^(ipaku\w+):[ :]\s*(.*)$', dump, re.M | re.I):
            ku_attrs[m.group(1).lower()] += len(m.group(0).encode()) + 1
        disk = master.run_command(
            'du -sb /var/lib/dirsrv/slapd-*/db /var/lib/dirsrv/slapd-*/ldif'
            ' 2>/dev/null; true', log_stdout=False).stdout_text
        lines = ['== LDAP sizes: ' + label]
        lines += ['  {:<42} {:>5} entries {:>9} bytes'.format(
            g, counts[g], sizes[g]) for g in sorted(sizes)]
        lines += ['  attribute {:<32} {:>9} bytes'.format(a, n)
                  for a, n in sorted(ku_attrs.items())]
        lines += ['  {:>9} bytes  {}'.format(n, dn)
                  for n, dn in sorted(detail, reverse=True)[:25]]
        lines.append('  on disk: ' + ' | '.join(disk.split('\n')))
        report = '\n'.join(lines)
        master.run_command(
            ['sh', '-c', 'cat >> /root/kuipa-ldap-sizes.txt'],
            stdin_text=report + '\n')
        master.run_command(['echo', report])

    def test_client_install_with_a_trusted_realm_user(self):
        self.stage_trusted_enrollment()
        self.measure_ldap('IPA installed, kuipa daemon running')
        client = self.clients[0]
        client.run_command([
            'ipa-client-install', '--unattended', '--no-ntp',
            '--domain', self.master.domain.name,
            '--server', self.master.hostname,
            '-p', 'testuser@' + self.ad.domain.name.upper(),
            '-w', 'Secret123'])
        client.run_command(['test', '-s', '/etc/ipa/ku-anchors'])
        client.run_command([
            'kinit', '-k', '-t', '/etc/krb5.keytab',
            'host/{}@{}'.format(client.hostname,
                                self.master.domain.realm)])

    def test_kuipa_enroll_with_a_trusted_realm_ticket(self):
        self.stage_trusted_enrollment()
        self.enroll_with_ticket(
            'testuser@' + self.ad.domain.name.upper(), 'Secret123')

    def test_kuipa_enroll_with_a_realm_ticket(self):
        self.stage_trusted_enrollment()
        self.enroll_with_ticket(
            'admin@' + self.master.domain.realm,
            self.master.config.admin_password)
        self.measure_ldap('one client enrolled with kuipa')

    def enroll_with_ticket(self, principal, password):
        master, client = self.master, self.clients[0]
        tasks.uninstall_client(client)
        client.resolver.backup()
        client.resolver.setup_resolver(master.ip)
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'host-del', client.hostname],
                           raiseonerr=False)
        created = master.run_command([
            'env', 'LC_ALL=C', 'ipa', 'host-add', client.hostname,
            '--force', '--random'])
        enrollment = re.search(r'^\s*Enrollment string:\s*(ipa-ku1:\S+)',
                               created.stdout_text, re.MULTILINE).group(1)
        client.put_file_contents('/tmp/enrollment', enrollment + '\n')
        client.run_command(['kuipa', 'realm-info', '--enrollment-file',
                            '/tmp/enrollment', '--server', master.hostname,
                            '--krb5-dir', '/tmp/kuipa-krb5'])
        client.run_command(
            "sed -i 's/dns_lookup_kdc = false/dns_lookup_kdc = true/' "
            "/tmp/kuipa-krb5/krb5.conf; printf '[libdefaults]\\n"
            "    forwardable = true\\n' >> /tmp/kuipa-krb5/krb5.conf")
        env = ['env', 'KRB5_CONFIG=/tmp/kuipa-krb5/krb5.conf',
               'KRB5CCNAME=FILE:/tmp/enroll.ccache']
        client.run_command(
            env + ['kinit', principal], stdin_text=password + '\n')
        client.run_command(env + [
            'kuipa', 'enroll', '--use-ccache', '--enrollment-file',
            '/tmp/enrollment', '--server', master.hostname])
        client.run_command(['test', '-s', '/etc/krb5.keytab'])

    def test_trusted_realm_user_owns_seals_only_as_the_realm_allows(self):
        self.stage_trusted_enrollment()
        master, client = self.master, self.clients[0]
        principal = 'testuser@' + self.ad.domain.name.upper()
        env = ['env', 'KRB5_CONFIG=/tmp/kuipa-krb5/krb5.conf',
               'KRB5CCNAME=FILE:/tmp/ad-owner.ccache',
               'KUIPA_USER_DIR=/tmp/ad-owner']
        client.run_command(env + ['kinit', principal],
                           stdin_text='Secret123\n')

        def create(name):
            return client.run_command(env + [
                'kuipa', '--json', 'seal', 'create', name,
                '--require', 'ticket'], raiseonerr=False)

        def limits(owners):
            tasks.kinit_admin(master)
            # fails with "no modifications" when nothing is stored yet
            master.run_command(['ipa', 'sealconfig-mod', '--reset'],
                               raiseonerr=False)
            master.run_command(
                ['ipa', 'sealconfig-mod']
                + ['--trusted-owners-{}={}'.format(kind, name)
                   for kind, names in (owners or {}).items()
                   for name in names])

        def refused_in_log(reason):
            # the client is told only that the server refused
            master.run_command(
                'journalctl -u kuipad --no-pager | grep -F "{}"'.format(
                    reason))

        source = '/tmp/ad-owner.txt'
        client.put_file_contents(source, 'owned by AD\n')
        try:
            closed = create('closed')
            assert closed.returncode != 0, 'closed by default'
            refused_in_log('does not let')
            limits({'allow': [self.ad.domain.name.upper()],
                    'deny': ['someone@' + self.ad.domain.name.upper()]})
            made = create('adseal')
            assert made.returncode == 0, made.stderr_text
            seal_id = json.loads(made.stdout_text)['seals'][0]['id']
            client.run_command(
                env + ['kuipa', 'seal', 'file', 'adseal', source])
            opened = client.run_command(env + [
                'kuipa', 'seal', 'open', source + '.sealed', '--out', '-'])
            assert opened.stdout_text == 'owned by AD\n'
            self.measure_ldap('one seal and one sealed file of an AD user')
            for n in range(1, 11):
                client.run_command(env + [
                    'kuipa', 'seal', 'create', 'bulk{}'.format(n),
                    '--require', 'ticket'])
            self.measure_ldap('eleven seals of an AD user')

            limits({'allow': [self.ad.domain.name.upper()],
                    'deny': [principal]})
            refused = client.run_command(env + [
                'kuipa', 'seal', 'open', source + '.sealed', '--out', '-'],
                raiseonerr=False)
            assert refused.returncode != 0, 'denied owner'
            refused_in_log('recover {}: request refused'.format(principal))
            master.run_command(['ipa', 'seal-revoke', seal_id])
            shown = master.run_command(['ipa', 'seal-show', seal_id])
            assert 'revoked' in shown.stdout_text
        finally:
            tasks.kinit_admin(master)
            master.run_command(['ipa', 'sealconfig-mod', '--reset'],
                               raiseonerr=False)
