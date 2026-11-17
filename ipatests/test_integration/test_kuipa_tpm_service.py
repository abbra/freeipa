# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

"""A TPM-bound IPA client serving HTTPS with an Akamu certificate.

client1 keeps its host keytab, an HTTP service keytab and its TLS key sealed
by kuipa with the TPM factor. nginx serves a page over TLS with a certificate
that Akamu issued, and a Kerberos client logs in through gssproxy, which loads
the service keytab with its keytab_loader. The tests reboot the host and take
its TPM away.

See docs/DESIGN-ci-tpm-service.md in the kuipa repository.
"""

import json
import re
import textwrap
import time

import pytest
from pytest_sourceorder import ordered

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.kuipa_common import stage

HELPER = '/usr/local/libexec/kuipa-spnego.py'
KEYTAB = '/etc/nginx/http.keytab'
KEY = '/etc/pki/tls/private/client1.key'
CERT = '/etc/pki/tls/certs/client1.crt'
WEBROOT = '/usr/share/nginx/html'
PAGE_TEXT = 'kuipa tpm service page'
USER = 'webuser'
INITIAL_PASSWORD = 'Secret123'
PASSWORD = 'Secret456'

SPNEGO_HELPER = textwrap.dedent('''\
    #!/usr/bin/python3
    """Accepts SPNEGO for nginx's auth_request, through gssproxy."""
    import base64
    import http.server
    import os
    import sys

    os.environ['GSS_USE_PROXY'] = 'yes'
    import gssapi


    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            header = self.headers.get('Authorization', '')
            if header.startswith('Negotiate '):
                try:
                    ctx = gssapi.SecurityContext(usage='accept')
                    ctx.step(base64.b64decode(header.split(None, 1)[1]))
                    if ctx.complete:
                        self.send_response(200)
                        self.send_header('X-Remote-User',
                                         str(ctx.initiator_name))
                        self.end_headers()
                        return
                except Exception as e:  # reported in the journal
                    print('accept failed: %s' % e, file=sys.stderr,
                          flush=True)
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Negotiate')
            self.end_headers()

        def log_message(self, fmt, *args):
            print(fmt % args, file=sys.stderr, flush=True)


    http.server.HTTPServer(('127.0.0.1', 8081), Handler).serve_forever()
    ''')

SPNEGO_UNIT = textwrap.dedent('''\
    [Unit]
    Description=SPNEGO acceptor for nginx, through gssproxy
    After=gssproxy.service
    Wants=gssproxy.service

    [Service]
    User=spnego
    Environment=GSS_USE_PROXY=yes
    ExecStart=/usr/bin/python3 {helper}

    [Install]
    WantedBy=multi-user.target
    ''').format(helper=HELPER)

# The loader runs in gssproxy's sandbox and needs the TPM, which the 0.9.3
# unit hides (PrivateDevices=yes). The network and the capabilities come from
# IPA's own drop-in, which ipa-client-install installs.
GSSPROXY_DROPIN = textwrap.dedent('''\
    [Service]
    PrivateDevices=no
    ''')

GSSPROXY_CONF = textwrap.dedent('''\
    [service/http]
      mechs = krb5
      cred_store = keytab:MEMORY:http
      keytab_loader = /usr/libexec/kuipa-unseal --memfd --sealed {keytab}.sealed
      cred_usage = accept
      euid = spnego
    ''').format(keytab=KEYTAB)

NGINX_DROPIN = textwrap.dedent('''\
    [Unit]
    After=kuipa-unseal.service
    Wants=kuipa-unseal.service
    ''')

NGINX_HTTP = textwrap.dedent('''\
    events {{}}
    http {{
        server {{
            listen 80;
            server_name {fqdn};
            root {webroot};
        }}
    }}
    ''')

NGINX_TLS = textwrap.dedent('''\
    events {{}}
    http {{
        server {{
            listen 80;
            server_name {fqdn};
            root {webroot};
        }}
        server {{
            listen 443 ssl;
            server_name {fqdn};
            root {webroot};
            ssl_certificate {cert};
            ssl_certificate_key {key};
            location = /_auth {{
                internal;
                proxy_pass http://127.0.0.1:8081;
                proxy_pass_request_body off;
                proxy_set_header Content-Length "";
            }}
            location = /kuipa.html {{
                auth_request /_auth;
                auth_request_set $kuipa_user $upstream_http_x_remote_user;
                add_header X-Remote-User $kuipa_user always;
            }}
        }}
    }}
    ''')


def reboot(host):
    """Reboot a host and wait until it answers again with a new boot."""
    boot = host.get_file_contents(
        '/proc/sys/kernel/random/boot_id', encoding='utf-8')
    host.run_command(['systemctl', 'reboot'], raiseonerr=False)
    time.sleep(20)
    deadline = time.time() + 600
    while time.time() < deadline:
        try:
            host.reset_connection()
            now = host.get_file_contents(
                '/proc/sys/kernel/random/boot_id', encoding='utf-8')
            if now != boot:
                break
        except Exception:  # not up yet
            pass
        time.sleep(5)
    else:
        raise AssertionError('{} did not come back'.format(host.hostname))
    host.run_command(['systemctl', 'is-system-running', '--wait'],
                     raiseonerr=False)


def unit_started(host, unit):
    """Monotonic time (us) at which a unit became active."""
    out = host.run_command(
        ['systemctl', 'show', '-p', 'ActiveEnterTimestampMonotonic', unit]
    ).stdout_text
    return int(out.split('=')[1])


@ordered
class KuipaTpmServiceTests:
    """TPM-sealed keytabs and key serve HTTPS and Kerberos after a boot."""

    @classmethod
    @stage('tpm')
    def stage_tpm(cls):
        master, c1, c2 = cls.master, cls.clients[0], cls.clients[1]
        # akamu-cli's http-01 challenge comes from RFC 1918 addresses here
        akamu_conf = master.get_file_contents('/etc/akamu/config.toml',
                                              encoding='utf-8')
        if 'http_validation_allow_private_ips' not in akamu_conf:
            master.put_file_contents(
                '/etc/akamu/config.toml', akamu_conf.replace(
                    '[server]\n', '[server]\nhttp_validation_allow_private_ips'
                    ' = true\n', 1))
            master.run_command(['systemctl', 'restart', 'akamu.service'])
        for client in (c1, c2):
            cls.reset_client(client)
        for client in (c1, c2):
            tpm = client.run_command(['systemd-analyze', 'has-tpm2'],
                                     raiseonerr=False)
            # prints "yes" and exits 0 only with a full TPM 2.0
            if tpm.returncode != 0:
                pytest.skip('{} has no TPM 2.0: {}'.format(
                    client.hostname, tpm.stdout_text.splitlines()[:1]))
            cls.enroll(master, client)

        tasks.install_packages(c1, [
            'nginx', 'akamu-client', 'certbot', 'python3-gssapi',
            'tpm2-tools', 'gssproxy',
        ])
        # gssproxy 0.9.3 has keytab_loader; abbra/pqc carries it
        c1.run_command(['dnf', '-y', 'upgrade', 'gssproxy'], raiseonerr=False)
        version = c1.run_command(
            ['rpm', '-q', '--qf', '%{VERSION}', 'gssproxy']).stdout_text
        assert tuple(int(p) for p in version.split('.')) >= (0, 9, 3), version
        c1.run_command(['setsebool', '-P', 'httpd_can_network_connect', '1'])
        # firewalld may start only at the next boot: edit its files directly
        c1.run_command(
            'firewall-offline-cmd --add-service=http --add-service=https; '
            'if systemctl is-active firewalld; then firewall-cmd --reload; '
            'fi')

        tasks.kinit_admin(master)
        master.run_command(['ipa', 'service-add',
                            'HTTP/{}'.format(c1.hostname)])
        tasks.user_add(master, USER, password=INITIAL_PASSWORD)
        # the KDC of client2 may be a replica: it must know the user
        for server in [master] + list(cls.replicas):
            tasks.wait_for_replication(server.ldap_connect())
        # the first login makes the user choose a password
        c2.run_command(
            ['env', 'KRB5CCNAME=FILE:/tmp/kuipa-tpm-init.ccache', 'kinit',
             USER], stdin_text='{0}\n{1}\n{1}\n'.format(
                 INITIAL_PASSWORD, PASSWORD))
        for server in [master] + list(cls.replicas):
            tasks.wait_for_replication(server.ldap_connect())
        c1.run_command('id -u spnego || useradd --system --shell '
                       '/sbin/nologin spnego')

        # host keytab, then the service keytab and the key, all with the TPM
        c1.run_command(['kuipa', 'protect', '--tpm'])
        tasks.kinit_admin(c1)
        c1.run_command(['ipa-getkeytab', '-s', master.hostname, '-p',
                        'HTTP/{}'.format(c1.hostname), '-k', KEYTAB])
        c1.run_command(['kuipa', 'protect', '--tpm', '--keytab', KEYTAB])

        # gssproxy loads the service keytab itself, in its sandbox
        c1.put_file_contents(HELPER, SPNEGO_HELPER)
        c1.run_command(['chmod', '0755', HELPER])
        c1.put_file_contents('/etc/systemd/system/kuipa-spnego.service',
                             SPNEGO_UNIT)
        c1.run_command(['mkdir', '-p',
                        '/etc/systemd/system/gssproxy.service.d',
                        '/etc/systemd/system/nginx.service.d'])
        c1.put_file_contents(
            '/etc/systemd/system/gssproxy.service.d/tpm.conf',
            GSSPROXY_DROPIN)
        c1.put_file_contents(
            '/etc/systemd/system/nginx.service.d/kuipa.conf', NGINX_DROPIN)
        c1.put_file_contents('/etc/gssproxy/60-http.conf', GSSPROXY_CONF)
        # the kuipa package ships the SELinux policy for the loader, the
        # TPM and the unsealed files; the test runs with it enforcing
        c1.run_command('semodule -l | grep -q "^kuipa\\b"')
        c1.run_command(['systemctl', 'daemon-reload'])
        c1.run_command(['systemctl', 'enable', 'gssproxy.service',
                        'kuipa-spnego.service'])
        # gssproxy may already run, without the drop-in and the policy
        c1.run_command(['systemctl', 'restart', 'gssproxy.service'])
        c1.run_command(['systemctl', 'start', 'kuipa-spnego.service'])

        c1.run_command(['mkdir', '-p', WEBROOT])
        c1.put_file_contents(WEBROOT + '/kuipa.html', PAGE_TEXT + '\n')
        cls.issue_certificate(master, c1)
        c1.put_file_contents('/etc/nginx/nginx.conf', cls.tls_config(c1))
        c1.run_command(['systemctl', 'enable', '--now', 'nginx.service'])
        c1.run_command(['systemctl', 'restart', 'nginx.service'])

    @classmethod
    def enroll(cls, master, client):
        tasks.kinit_admin(master)
        created = master.run_command(['env', 'LC_ALL=C', 'ipa', 'host-add',
                                      client.hostname, '--force', '--random'])
        match = re.search(r'^\s*Enrollment string:\s*(ipa-ku1:\S+)',
                          created.stdout_text, re.MULTILINE)
        assert match is not None
        client.run_command(['ipa-client-install', '--unattended', '--no-ntp',
                            '-W', '--domain', master.domain.name, '--server',
                            master.hostname], stdin_text=match.group(1) + '\n')

    @staticmethod
    def tls_config(client):
        return NGINX_TLS.format(fqdn=client.hostname, webroot=WEBROOT,
                                cert=CERT, key=KEY)

    @classmethod
    def issue_certificate(cls, master, client, key_exists=False):
        """Get a certificate for the client's HTTP service from Akamu.

        certbot proves the host name over http-01 and authenticates to Akamu
        with EAB credentials that the host gets with its keytab (SPNEGO).
        The key and the request are made in tmpfs; the key goes to its sealed
        place and nothing else keeps a copy. nginx is stopped: certbot needs
        port 80, and the caller starts nginx again.
        """
        work = '/run/kuipa-cert'
        client.run_command(['systemctl', 'stop', 'nginx.service'],
                           raiseonerr=False)
        client.run_command(['rm', '-rf', work])
        client.run_command(['install', '-d', '-m', '0700', work])
        client.run_command([
            'openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt',
            'ec_paramgen_curve:P-256', '-nodes', '-keyout', work + '/key.pem',
            '-out', work + '/req.csr', '-subj', '/CN=' + client.hostname,
            '-addext', 'subjectAltName=DNS:' + client.hostname])
        client.run_command(['kinit', '-k', '-t', '/etc/krb5.keytab',
                            'host/{}'.format(client.hostname)])
        eab = json.loads(client.run_command([
            'curl', '-sS', '--cacert', '/etc/ipa/ca.crt', '--negotiate',
            '-u', ':', 'https://{}/akamu/acme/eab'.format(master.hostname)
        ]).stdout_text)
        # Akamu is served under /akamu; /acme is Dogtag's own responder
        issued = client.run_command([
            'env', 'REQUESTS_CA_BUNDLE=/etc/ipa/ca.crt', 'certbot',
            'certonly', '--standalone', '--non-interactive', '--agree-tos',
            '--register-unsafely-without-email',
            '--config-dir', work + '/etc', '--work-dir', work + '/work',
            '--logs-dir', work + '/log',
            '--server', 'https://{}/akamu/acme/directory'.format(
                master.hostname),
            '--eab-kid', eab['kid'], '--eab-hmac-key', eab['hmac_key'],
            '--csr', work + '/req.csr', '--cert-path', work + '/cert.pem',
            '--chain-path', work + '/ca.pem',
            '--fullchain-path', work + '/chain.pem'], raiseonerr=False)
        assert issued.returncode == 0, issued.stdout_text + issued.stderr_text
        client.run_command(['install', '-m', '0644', work + '/chain.pem',
                            CERT])
        if key_exists:
            client.run_command(['kuipa', 'unprotect', '--file', KEY])
        client.run_command(['install', '-m', '0600', work + '/key.pem', KEY])
        client.run_command(['rm', '-rf', work])
        sealed = client.run_command(
            ['kuipa', 'protect', '--tpm', '--file', KEY, '--keytab',
             KEYTAB], raiseonerr=False)
        assert sealed.returncode == 0, (
            sealed.stdout_text + sealed.stderr_text)

    @classmethod
    def cleanup_tpm(cls):
        c1 = cls.clients[0]
        c1.run_command(
            ['systemctl', 'disable', '--now', 'nginx.service',
             'kuipa-spnego.service'], raiseonerr=False)
        c1.run_command(
            ['rm', '-rf', KEY, CERT, KEYTAB, KEYTAB + '.sealed',
             KEY + '.sealed', '/etc/gssproxy/60-http.conf',
             '/etc/systemd/system/gssproxy.service.d',
             '/etc/systemd/system/nginx.service.d',
             '/etc/systemd/system/kuipa-spnego.service', HELPER,
             '/etc/letsencrypt'])
        # keep the directory: its label comes from the kuipa policy
        c1.run_command('find /run/ipa/kuipa -mindepth 1 -delete',
                       raiseonerr=False)
        c1.run_command(['userdel', 'spnego'], raiseonerr=False)

    # -- helpers ------------------------------------------------------------

    def diagnostics(self):
        client = self.clients[0]
        out = ''
        for cmd in (
            'journalctl -b --no-pager -u kuipa-unseal -u kuipa-spnego '
            '-u nginx | tail -n 15',
            'ausearch -m avc -ts boot 2>&1 | tail -n 10',
            'journalctl -b --no-pager -u gssproxy | grep -v "^$" | '
            'tail -n 60',
        ):
            out += client.run_command(cmd, raiseonerr=False).stdout_text
        return out

    def get_page(self, ticket=True, user=USER):
        """Fetch the page from client2; a ticket is made for the user."""
        client2, client1 = self.clients[1], self.clients[0]
        cache = 'FILE:/tmp/kuipa-tpm-{}.ccache'.format(user)
        client2.run_command(['rm', '-f', cache[5:]])
        if ticket:
            got = client2.run_command(
                ['env', 'KRB5CCNAME=' + cache, 'KRB5_TRACE=/dev/stderr',
                 'kinit', user], stdin_text=PASSWORD + '\n',
                raiseonerr=False)
            if got.returncode != 0:
                state = ''
                for host in [self.master] + list(self.replicas):
                    out = host.run_command(
                        'ipa user-show {} --all --raw | grep -i "krbLastPwd\\|'
                        'krbPasswordExp"; env KRB5CCNAME=FILE:/tmp/probe.cc '
                        'kinit {} 2>&1 <<< {}; ipa-replica-manage list -v '
                        '$(hostname) 2>&1 | tail -n 8'.format(
                            user, user, PASSWORD), raiseonerr=False)
                    state += '{}:\n{}\n'.format(host.hostname, out.stdout_text)
                assert False, state + got.stderr_text[-1500:]
        return client2.run_command([
            'env', 'KRB5CCNAME=' + cache, 'curl', '-sS', '-i',
            '--cacert', '/etc/ipa/ca.crt', '--negotiate', '-u', ':',
            'https://{}/kuipa.html'.format(client1.hostname)],
            raiseonerr=False)

    def assert_served_for(self, user=USER):
        got = self.get_page(user=user)
        assert ' 200 ' in (got.stdout_text.splitlines() or [''])[0], (
            got.stdout_text + got.stderr_text + self.diagnostics())
        assert PAGE_TEXT in got.stdout_text
        assert re.search(
            r'^x-remote-user:\s*{}@'.format(user), got.stdout_text,
            re.IGNORECASE | re.MULTILINE), got.stdout_text

    def plain_secrets(self):
        """Plain keys and keytabs found outside tmpfs, minus known files."""
        client = self.clients[0]
        found = []
        out = client.run_command(
            "grep -rIl -E 'BEGIN [A-Z ]*PRIVATE KEY' /etc /var/lib /root "
            "/home /tmp /var/tmp 2>/dev/null || true").stdout_text
        for path in out.split():
            if path.startswith(('/etc/ssh/', '/etc/letsencrypt/accounts/')):
                continue
            found.append(path)
        names = client.run_command(
            "find /etc /var/lib /root /home /tmp /var/tmp -type f "
            "-name '*keytab*' ! -name '*.sealed' 2>/dev/null || true"
        ).stdout_text.split()
        for path in names:
            head = client.run_command(
                ['od', '-An', '-tx1', '-N2', path]).stdout_text.split()
            if head == ['05', '02']:
                found.append(path)
        return found

    # -- tests, in this order ----------------------------------------------

    def test_no_plain_secrets_on_disk(self):
        self.stage_tpm()
        client = self.clients[0]
        for path in (KEYTAB, KEY, '/etc/krb5.keytab'):
            target = client.run_command(
                ['readlink', '-f', path]).stdout_text.strip()
            assert target.startswith('/run/'), (path, target)
        assert self.plain_secrets() == []

    def test_https_and_kerberos_before_reboot(self):
        self.stage_tpm()
        client2 = self.clients[1]
        self.assert_served_for()
        issuer = client2.run_command(
            'openssl s_client -connect {}:443 -servername {} </dev/null 2>'
            '/dev/null | openssl x509 -noout -issuer'.format(
                self.clients[0].hostname, self.clients[0].hostname)
        ).stdout_text
        assert 'IPA.TEST' in issuer.upper() or 'CERTIFICATE AUTHORITY' in \
            issuer.upper(), issuer
        denied = self.get_page(ticket=False)
        assert ' 401 ' in denied.stdout_text.splitlines()[0]

    def test_reboot_unseals_everything(self):
        self.stage_tpm()
        client = self.clients[0]
        for _round in range(2):
            reboot(client)
            tasks.kinit_admin(self.master)
            unseal = unit_started(client, 'kuipa-unseal.service')
            for unit in ('gssproxy.service', 'nginx.service'):
                assert unseal <= unit_started(client, unit), (
                    unit, self.diagnostics())
            client.run_command(
                ['kinit', '-k', '-t', '/etc/krb5.keytab',
                 'host/{}'.format(client.hostname)])
            self.assert_served_for()
            assert self.plain_secrets() == []

    def test_service_keytab_comes_from_the_loader(self):
        self.stage_tpm()
        client = self.clients[0]
        copy = client.run_command(
            ['readlink', '-f', KEYTAB]).stdout_text.strip()
        client.run_command(['rm', '-f', copy])
        client.run_command(['systemctl', 'restart', 'gssproxy.service'])
        client.run_command(['systemctl', 'restart', 'kuipa-spnego.service'])
        self.assert_served_for()
        client.run_command(['test', '!', '-e', copy])
        # give the next tests the memory copy back
        client.run_command(['/usr/libexec/kuipa-unseal', '--all'])

    def test_selinux_is_enforcing_and_clean(self):
        self.stage_tpm()
        client = self.clients[0]
        assert client.run_command(['getenforce']).stdout_text.strip() \
            == 'Enforcing'
        avc = client.run_command(
            'ausearch -m avc -ts boot 2>/dev/null || true').stdout_text
        offending = [line for line in avc.splitlines() if re.search(
            r'gssproxy|systemd-creds|kuipa|nginx|tpmrm', line)]
        assert offending == [], '\n'.join(offending)

    def test_reissue_reseals_the_key(self):
        self.stage_tpm()
        master, client = self.master, self.clients[0]
        old = client.run_command(
            ['openssl', 'x509', '-noout', '-serial', '-in', CERT]
        ).stdout_text
        self.issue_certificate(master, client, key_exists=True)
        client.put_file_contents('/etc/nginx/nginx.conf',
                                 self.tls_config(client))
        client.run_command(['systemctl', 'restart', 'nginx.service'])
        new = client.run_command(
            ['openssl', 'x509', '-noout', '-serial', '-in', CERT]
        ).stdout_text
        assert new != old
        self.assert_served_for()
        assert self.plain_secrets() == []

    def test_certificate_from_akamu(self):
        self.stage_tpm()
        """The host gets a certificate from Akamu with its own keytab."""
        master, client = self.master, self.clients[0]
        # Akamu is served under /akamu; /acme is Dogtag's own responder
        acme = 'https://{}/akamu/acme/directory'.format(master.hostname)
        work = '/run/kuipa-akamu'
        client.run_command(['systemctl', 'stop', 'nginx.service'])
        try:
            client.run_command(['rm', '-rf', work])
            client.run_command(['install', '-d', '-m', '0700', work])
            issued = client.run_command([
                'env', 'KRB5_CLIENT_KTNAME=/etc/krb5.keytab',
                'akamu-cli', 'issue', '--server', acme,
                '--server-ca', '/etc/ipa/ca.crt',
                '--account-key', work + '/account.pem',
                '--gssapi-keytab', '/etc/krb5.keytab',
                '-d', client.hostname, '--out', work + '/chain.pem',
                '--challenge', 'http-01', '--http-port', '80'],
                raiseonerr=False)
        finally:
            client.run_command(['systemctl', 'start', 'nginx.service'])
        assert issued.returncode == 0, issued.stdout_text + issued.stderr_text
        client.run_command(['grep', '-q', 'BEGIN CERTIFICATE',
                            work + '/chain.pem'])
        client.run_command(['rm', '-rf', work])

    def test_stolen_disk_has_no_tpm(self):
        self.stage_tpm()
        c1, c2 = self.clients
        sealed = KEYTAB + '.sealed'
        c1.run_command(['tar', 'cf', '/tmp/ku-stolen.tar', sealed,
                        '/var/lib/ipa-client/ku'])
        c2.put_file_contents(
            '/tmp/ku-stolen.tar',
            c1.get_file_contents('/tmp/ku-stolen.tar'))
        c2.run_command(['tar', 'xf', '/tmp/ku-stolen.tar', '-C', '/tmp'])
        got = c2.run_command(
            ['env', 'KUIPA_ROOT=/tmp', '/usr/libexec/kuipa-unseal',
             '--sealed', '/tmp' + sealed, '--out', '/tmp/stolen.keytab'],
            raiseonerr=False)
        assert got.returncode not in (0, 75), got.stdout_text + \
            got.stderr_text
        c2.run_command(['test', '!', '-s', '/tmp/stolen.keytab'])

    def test_cleared_tpm_denies_service(self):
        self.stage_tpm()
        client = self.clients[0]
        client.run_command(['tpm2_clear'])
        reboot(client)
        unseal = client.run_command(
            ['systemctl', 'show', '-p', 'ActiveState', '-p', 'ExecMainStatus',
             'kuipa-unseal.service']).stdout_text
        state = dict(line.split('=', 1) for line in unseal.split())
        # a failed or restarting oneshot, and a plain error: not the
        # "no server yet" status 75 or success
        assert state['ActiveState'] in ('failed', 'activating'), unseal
        assert state['ExecMainStatus'] not in ('0', '75'), (
            unseal + self.diagnostics())
        denied = self.get_page()
        assert ' 200 ' not in (denied.stdout_text.splitlines() or [''])[0]
        kinit = client.run_command(
            ['kinit', '-k', '-t', '/etc/krb5.keytab',
             'host/{}'.format(client.hostname)], raiseonerr=False)
        assert kinit.returncode != 0
