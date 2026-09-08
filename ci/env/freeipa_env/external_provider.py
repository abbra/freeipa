"""external provider (B4): attach to pre-created environments.

Hosts are provisioned elsewhere (VMs, bare metal, an existing AD forest).
The env spec lists them with address:; the provider's contract is the same
multihost config YAML, so the test side is unchanged.

  up    = attach: validate SSH reachability, hostname, dist, IPA state;
          render the config.  It never mutates the hosts.
  down  = collect logs only; nothing is destroyed.

Ports are probed from the provisioner's vantage point; a failure is a
warning (the provisioner may sit off the environment's network) unless
--strict is set.
"""

import os
import shlex
import socket
import subprocess

CHECK_PORTS = [22, 53, 88, 389, 636]


class ExternalError(Exception):
    pass


class ExternalProvider:
    def __init__(self, spec, workdir, strict=False, ssh_user=None,
                 ssh_key=None):
        self.spec = spec
        self.workdir = workdir
        self.strict = strict
        self.ssh_user = ssh_user or 'root'
        self.ssh_key = ssh_key
        self.logdir = os.path.join(workdir, 'logs')
        os.makedirs(self.logdir, exist_ok=True)
        self.ok = True

    def _ssh_args(self, h):
        args = ['ssh',
                '-o', 'BatchMode=yes',
                '-o', f'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=accept-new']
        key = self.ssh_key_path()
        if key:
            args += ['-i', key]
        args += ['-p', str(h.port or 22), f'{self.ssh_user}@{h.address}']
        return args

    def _ssh(self, h, cmd, timeout=15, check=True):
        args = self._ssh_args(h) + [cmd]
        log = os.path.join(self.logdir, f'ext-{h.name}-check.log')
        with open(log, 'a') as lf:
            lf.write(f'+ {cmd}\n')
            lf.flush()
            proc = subprocess.run(args, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=timeout)
        out = proc.stdout.decode().strip()
        if check and proc.returncode:
            raise ExternalError(f'{h.name}: ssh failed: {out[:500]}')
        return proc.returncode, out

    def _check_host(self, h):
        print(f'== {h.name} ({h.address}) [{h.role}]')
        try:
            rc, out = self._ssh(h,
                                'hostname -f; '
                                'grep PRETTY_NAME /etc/os-release; '
                                'rpm -q freeipa-server freeipa-server-dns '
                                '2>/dev/null || echo "IPA: not installed"; '
                                'ip -4 -o addr show | head -3')
        except (ExternalError, subprocess.TimeoutExpired) as e:
            print(f'   FAIL: {e}')
            self.ok = False
            return
        lines = out.splitlines()
        fqdn = lines[0] if lines else '?'
        expected = f'{h.name}.{self.spec.domain}'
        host_ok = 'OK' if fqdn.endswith(self.spec.domain) else \
            f'MISMATCH (expected suffix .{self.spec.domain})'
        dist = next((l for l in lines if 'PRETTY_NAME' in l), '?')
        ipa = next((l for l in lines if 'IPA:' in l
                    or 'freeipa-server-' in l or 'freeipa-server-common' in l
                    or 'not installed' in l), '?')
        print(f'   fqdn: {fqdn} {host_ok}')
        print(f'   dist: {dist}')
        print(f'   ipa:  {ipa}')
        # port probe from the provisioner
        ports = []
        for p in CHECK_PORTS:
            try:
                with socket.create_connection((h.address, p), timeout=2):
                    ports.append(f'{p}+')
            except OSError:
                ports.append(f'{p}-')
        print(f'   ports: {", ".join(ports)}')
        bad = [p for p in ports if p.endswith('-')]
        if bad and self.strict:
            self.ok = False
            print(f'   FAIL: unreachable ports {bad} (strict)')

    def up(self):
        """Attach: validate every host, then render the shared config."""
        for h in self.spec.hosts:
            if not h.is_external:
                raise ExternalError(
                    f'external provider: host {h.name} has no address:')
            self._check_host(h)
        if not self.ok:
            raise ExternalError('attach validation failed')
        cfg = self._write_config()
        print(f'== attached to environment {self.spec.name}')
        return cfg

    def _write_config(self):
        import yaml
        hosts = []
        for h in self.spec.hosts:
            role = h.role
            hosts.append({
                'name': h.name,
                'role': role,
                'type': 'IPA' if role in ('master', 'replica', 'client')
                         else role.upper(),
                'ip': h.address,
            })
        cfg = {
            'admin_name': self.spec.admin_name,
            'admin_password': self.spec.admin_password,
            'debug': False,
            'dirman_dn': 'cn=directory manager',
            'dirman_password': self.spec.dirman_password,
            'domain_level': self.spec.domain_level,
            'dns_forwarder': self.spec.dns_forwarder,
            'root_ssh_key_filename': self.ssh_key_path(),
            'domains': [{'name': self.spec.domain, 'type': 'IPA',
                         'hosts': hosts}],
        }
        path = os.path.join(self.workdir, 'ipa-test-config.yaml')
        with open(path, 'w') as f:
            yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
        print(f'== wrote {path}')
        return cfg

    def ssh_key_path(self):
        """The framework authenticates with this key; the provisioner
        assumes the operator's key already has root access (attach
        validation proved it with the same identity)."""
        return self.ssh_key or os.path.expanduser('~/.ssh/id_rsa')

    # the daemon log set, identical to Azure CI's collect_logs()
    # (ipatests/azure/scripts/azure-run-base-tests.sh)
    _DAEMON_LOG_TAR = (
        'journalctl -b --no-pager > /tmp/freeipa-env-{n}.journal.log; '
        'tar --ignore-failed-read -czf - --warning=no-failed-read '
        '/var/log/dirsrv /var/log/httpd /var/log/ipa* '
        '/var/log/krb5kdc.log /var/log/pki /var/log/samba '
        '/var/named/data /tmp/freeipa-env-{n}.journal.log 2>/dev/null')

    def down(self, collect=True):
        if collect:
            dest = os.path.join(self.logdir, 'collected')
            os.makedirs(dest, exist_ok=True)
            for h in self.spec.hosts:
                host_dir = os.path.join(dest, h.name)
                os.makedirs(host_dir, exist_ok=True)
                tarball = os.path.join(host_dir, f'{h.name}-logs.tar.gz')
                tmp = tarball + '.partial'
                try:
                    cmd = self._ssh_args(h) + [
                        '-T', self._DAEMON_LOG_TAR.format(n=h.name)]
                    with open(tmp, 'wb') as f:
                        subprocess.run(cmd, stdout=f,
                                       stderr=subprocess.DEVNULL,
                                       timeout=300)
                    if os.path.getsize(tmp) > 0:
                        os.replace(tmp, tarball)
                    else:
                        os.unlink(tmp)
                        print(f'   {h.name}: no logs collected')
                except (ExternalError, subprocess.TimeoutExpired) as e:
                    print(f'   {h.name}: log collection skipped ({e})')
                    if os.path.exists(tmp):
                        os.unlink(tmp)
        print(f'== environment {self.spec.name}: logs collected, '
              f'hosts left running (external)')

    def show(self):
        for h in self.spec.hosts:
            try:
                _rc, out = self._ssh(h, 'hostname -f')
                state = 'up'
            except (ExternalError, subprocess.TimeoutExpired):
                out, state = 'unreachable', 'down'
            print(f'{h.name:20s} external  {h.address:18s} {out} ({h.role})')

    def collect_logs(self):
        self.down()

    # base-mode support: scp the run script to the controller, exec it.
    def copy_to_controller(self, local, remote):
        h = self.spec.master
        self._scp(h, local, remote)

    def _scp(self, h, local, remote):
        args = ['scp', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=accept-new']
        key = self.ssh_key_path()
        if key:
            args += ['-i', key]
        args += ['-P', str(h.port or 22), local,
                 f'{self.ssh_user}@{h.address}:{remote}']
        subprocess.run(args, check=True)

    def run_in_controller(self, cmd, env=None, log='run.log',
                          timeout=None):
        h = self.spec.master
        envprefix = ''.join(f'{k}={shlex.quote(v)} ' for k, v in (env or {}).items())
        args = ['ssh', '-t', '-o', 'BatchMode=yes']
        key = self.ssh_key_path()
        if key:
            args += ['-i', key]
        args += ['-p', str(h.port or 22), f'{self.ssh_user}@{h.address}',
                 envprefix + cmd]
        logpath = os.path.join(self.logdir, log)
        with open(logpath, 'w') as lf:
            lf.write(f'+ {envprefix}{cmd}\n')
            lf.flush()
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            for line in proc.stdout:
                sys.stdout.buffer.write(line)
                sys.stdout.flush()
                lf.write(line)
            return proc.wait()
