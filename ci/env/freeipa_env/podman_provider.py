"""podman provider (B2/B3): environments made of systemd containers.

Faithful to the validated Azure flow
(ipatests/azure/scripts/setup_containers.py + Dockerfiles/docker-compose.yml):
  * dual-stack podman network with built-in DNS
  * systemd as PID 1, booted to multi-user.target before setup
  * per-container /etc/hosts, /etc/hostname, /etc/resolv.conf rewrites
  * controller (master) SSH keypair; public key distributed to all hosts
  * services known to misbehave in containers get a
    ConditionVirtualization=!container override
  * ipa-test-config.yaml mounted at /root/.ipa/ipa-test-config.yaml
"""

import os
import shlex
import subprocess
import sys
import time

from .envspec import EnvSpec

DEFAULT_V4_SUBNET = '10.89.0.0/24'
DEFAULT_V6_SUBNET = '2001:db8:1::/64'
CONFIG_PATH_IN_CONTAINER = '/root/.ipa/ipa-test-config.yaml'
SSH_PRIVKEY_IN_CONTAINER = '/root/.ssh/id_rsa'
SYSTEMD_TIMEOUT_S = 180
IGNORED_SERVICES = ['nis-domainname']


class PodmanError(Exception):
    pass


class PodmanProvider:
    def __init__(self, spec, workdir, tool='podman', seccomp=None):
        self.spec = spec
        self.workdir = workdir
        self.tool = tool
        self.seccomp = seccomp
        self.logdir = os.path.join(workdir, 'logs')
        self.config_path = os.path.join(workdir, 'ipa-test-config.yaml')

    # ------------------------------------------------------------------ util
    def _podman(self, args, log=None, timeout=None, check=True, env=None,
                echo=True):
        cmd = [self.tool] + args
        if log:
            lf = open(os.path.join(self.logdir, log), 'a')
        else:
            lf = sys.stdout
        try:
            lf.write(f'+ {shlex.join(cmd)}\n')
            lf.flush()
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=timeout, env={**os.environ, **(env or {})})
        finally:
            if log:
                lf.close()
        out = proc.stdout.decode()
        if echo:
            print(out, file=sys.stderr)
        if check and proc.returncode:
            raise PodmanError(f'command failed ({proc.returncode}): '
                              f'{shlex.join(cmd)}')
        return proc.returncode, out

    def _exec(self, name, cmd, check=True, env=None, timeout=None, log=None):
        args = ['exec', '-i']
        for k, v in (env or {}).items():
            args += ['-e', f'{k}={v}']
        args += [name, '/bin/bash', '-c', cmd]
        return self._podman(args, log=log, timeout=timeout, check=check)

    def _exec_rc(self, name, cmd, **kw):
        rc, _ = self._exec(name, cmd, check=False, **kw)
        return rc

    # ------------------------------------------------------------- containers
    def _network_args(self):
        args = ['network', 'create']
        args += ['--subnet', DEFAULT_V4_SUBNET]
        if self.spec.ipv6:
            args += ['--subnet', DEFAULT_V6_SUBNET]
        args.append(self.spec.network_name())
        return args

    def _create_network(self):
        rc, _ = self._podman(['network', 'exists', self.spec.network_name()],
                             check=False)
        if rc != 0:
            self._podman(self._network_args(), log='network.log')

    def _container_args(self, h, idx_in_role):
        name = self.spec.container_name(h)
        fqdn = self.spec.host_fqdn(h)
        res = self.spec.resource(h.role)
        args = ['run', '-d',
                '--name', name,
                '--hostname', fqdn,
                '--network', self.spec.network_name(),
                # runc defaults to container=oci; declare the real runtime
                # so /run/systemd/container and the container env var agree
                # (test_ipaplatform/test_tasks.py::test_detect_container).
                '-e', 'container=podman',
                '--cap-add', 'ALL',
                '--cap-drop', 'CAP_SYS_TIME',
                '--security-opt', 'label=disable',
                '--memory', res['memory'],
                '--memory-swap', res['memory-swap']]
        if self.seccomp:
            args += ['--security-opt', f'seccomp={self.seccomp}']
        args += ['-v', f'{self.config_path}:{CONFIG_PATH_IN_CONTAINER}:ro']
        args.append(self.spec.podman_image(h))
        return args

    def _run_containers(self):
        for h in self.spec.hosts:
            if h.is_external:
                continue
            self._podman(self._container_args(h, 0), log=f'{h.name}.run.log')

    def _wait_systemd(self):
        for h in self.spec.hosts:
            if h.is_external:
                continue
            name = self.spec.container_name(h)
            deadline = time.time() + SYSTEMD_TIMEOUT_S
            while time.time() < deadline:
                rc = self._exec_rc(name, 'systemctl is-active multi-user.target',
                                   log=f'{h.name}.systemd-wait.log')
                if rc == 0:
                    print(f'== {h.name}: multi-user.target reached')
                    break
                time.sleep(3)
            else:
                raise PodmanError(f'{name}: multi-user.target not reached')

    def _umount(self, name, path):
        self._exec_rc(name, f'umount {path} 2>/dev/null || true')

    def _setup_hosts(self):
        """Per-container /etc/hosts; controller also learns the rest."""
        for h in self.spec.hosts:
            if h.is_external:
                continue
            name = self.spec.container_name(h)
            fqdn = self.spec.host_fqdn(h)
            self._umount(name, '/etc/hosts')
            self._exec(
                name,
                f"echo -e '127.0.0.1 localhost\n::1 localhost\n"
                f"0:0:0:0:0:0:0:1 localhost' > /etc/hosts",
                log=f'{h.name}.setup.log')
        # controller entry for every other host (DNS covers this too, but
        # keep the Azure behaviour)
        cname = self.spec.container_name(self.spec.master)
        extra = [f'{self._ip(h)} {self.spec.host_fqdn(h)}'
                 for h in self.spec.hosts
                 if not h.is_external and h.role != 'master']
        if extra:
            self._exec(cname, 'echo -e ' + shlex.quote('\n'.join(extra))
                       + ' >> /etc/hosts', log=f'{self.spec.master.name}.setup.log')

    def _setup_hostname(self):
        for h in self.spec.hosts:
            if h.is_external:
                continue
            name = self.spec.container_name(h)
            fqdn = self.spec.host_fqdn(h)
            self._umount(name, '/etc/hostname')
            self._exec(name, f"echo -e '{fqdn}' > /etc/hostname"
                             f' && hostnamectl set-hostname {fqdn}',
                       log=f'{h.name}.setup.log')

    def _setup_resolvconf(self):
        # The multihost framework's PlainFileResolver requires
        # /etc/resolv.conf to be a plain regular file with a real first
        # line (an empty or NM/resolved-managed file is rejected), so the
        # master must always get a forwarder; 8.8.8.8 is the framework's
        # own default (env_config.py 'DNSFORWARD').
        fwd = self.spec.dns_forwarder or '8.8.8.8'
        for h in self.spec.hosts:
            if h.is_external:
                continue
            name = self.spec.container_name(h)
            self._umount(name, '/etc/resolv.conf')
            if h.role == 'master':
                ns = fwd
            else:
                # non-masters resolve through the master's DNS
                ns = self._ip(self.spec.master)
            if ns:
                self._exec(name, f"echo -e 'nameserver {ns}' > /etc/resolv.conf"
                              f' && chmod 0644 /etc/resolv.conf',
                           log=f'{h.name}.setup.log')

    def _setup_ssh(self):
        """Controller keypair (PEM RSA, as Azure) + pubkey distribution."""
        cname = self.spec.container_name(self.spec.master)
        self._exec(cname, 'rm -f ' + SSH_PRIVKEY_IN_CONTAINER
                   + ' && ssh-keygen -q -f ' + SSH_PRIVKEY_IN_CONTAINER
                   + ' -t rsa -m PEM -N ""', log='ssh.setup.log')
        _rc, out = self._exec(cname, f'cat {SSH_PRIVKEY_IN_CONTAINER}.pub')
        pubkey = out.strip().splitlines()[0].strip()
        for h in self.spec.hosts:
            if h.is_external:
                continue
            name = self.spec.container_name(h)
            self._exec(
                name,
                'mkdir -p /root/.ssh && chmod 0700 /root/.ssh'
                ' && touch /root/.ssh/authorized_keys && chmod 0600'
                ' /root/.ssh/authorized_keys'
                f' && echo {pubkey} >> /root/.ssh/authorized_keys',
                log=f'{h.name}.setup.log')
        # keep the private key available to the provisioner (framework on
        # the host uses root_ssh_key_filename in the config)
        self._podman(['cp', f'{cname}:{SSH_PRIVKEY_IN_CONTAINER}',
                      os.path.join(self.workdir, 'id_rsa')])
        os.chmod(os.path.join(self.workdir, 'id_rsa'), 0o600)
        self._podman(['cp', f'{cname}:{SSH_PRIVKEY_IN_CONTAINER}.pub',
                      os.path.join(self.workdir, 'id_rsa.pub')])

    def _setup_container_overrides(self):
        for h in self.spec.hosts:
            if h.is_external:
                continue
            name = self.spec.container_name(h)
            for svc in IGNORED_SERVICES:
                d = f'/etc/systemd/system/{svc}.service.d'
                self._exec(
                    name,
                    f'mkdir -p {d} && printf "[Unit]\\n'
                    f'ConditionVirtualization=!container\\n"'
                    f' > {d}/ipa-override.conf',
                    log=f'{h.name}.setup.log')
            self._exec_rc(name, 'systemctl daemon-reload')

    # ------------------------------------------------------------------ config
    def _state(self, name):
        import json
        try:
            _rc, out = self._podman(['inspect', name], check=False,
                                         echo=False)
            return json.loads(out)[0]['State']['Status']
        except Exception:
            return 'not found'

    def _ip(self, h):
        name = self.spec.container_name(h)
        import json
        _rc, out = self._podman(['inspect', name], echo=False)
        net = json.loads(out)[0]['NetworkSettings']['Networks']
        ip = net.get(self.spec.network_name(), {}).get('IPAddress', '')
        if not ip:
            raise PodmanError(f'no IP for {name} on {self.spec.network_name()}')
        return ip

    def write_config(self):
        """Render the multihost config understood by
        ipatests/pytest_ipa/integration/env_config.py (same shape as
        ipatests/azure/templates/ipa-test-config-template.yaml).

        NOTE: pytest_multihost's Host.from_dict rejects unknown keys, so
        the host entries must look exactly like the Azure template:
        external_hostname / name (FQDN) / ip / role -- no 'type' key.
        'type: IPA' belongs on the domain, not the host."""
        hosts = []
        for h in self.spec.hosts:
            if h.is_external:
                address = h.address
                fqdn = h.name  # external hosts are given as FQDNs
            else:
                address = self._ip(h)
                fqdn = self.spec.host_fqdn(h)
            hosts.append({
                'external_hostname': fqdn,
                'name': fqdn,
                'ip': address,
                'role': h.role,
            })
        cfg = {
            'admin_name': self.spec.admin_name,
            'admin_password': self.spec.admin_password,
            'debug': False,
            'dirman_dn': 'cn=Directory Manager',
            'dirman_password': self.spec.dirman_password,
            'domain_level': self.spec.domain_level,
            # the framework's own default is 8.8.8.8; a null forwarder in
            # the YAML would not be picked up the same way
            'dns_forwarder': self.spec.dns_forwarder or '8.8.8.8',
            'root_ssh_key_filename': os.path.join(self.workdir, 'id_rsa'),
            'domains': [{
                'name': self.spec.domain,
                'type': 'IPA',
                'hosts': hosts,
            }],
        }
        import yaml
        with open(self.config_path, 'w') as f:
            yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
        print(f'== wrote {self.config_path}')
        return cfg

    # ------------------------------------------------------------------ ops
    def up(self):
        os.makedirs(self.logdir, exist_ok=True)
        # the config file must exist before containers mount it
        open(self.config_path, 'a').close()
        self._create_network()
        self._run_containers()
        self._wait_systemd()
        self._setup_hosts()
        self._setup_hostname()
        self._setup_resolvconf()
        self._setup_ssh()
        self._setup_container_overrides()
        self.write_config()
        print(f'== environment {self.spec.name} is up')

    def down(self, collect=True):
        self.collect_logs()
        for h in self.spec.hosts:
            if h.is_external:
                print(f'== {h.name}: external host, leaving in place')
                continue
            name = self.spec.container_name(h)
            self._podman(['stop', '-t', '30', name],
                         log=f'{h.name}.stop.log', check=False)
            self._podman(['rm', name], check=False)
        self._podman(['network', 'rm', self.spec.network_name()], check=False)
        print(f'== environment {self.spec.name} torn down')

    def show(self):
        for h in self.spec.hosts:
            if h.is_external:
                print(f'{h.name:20s} external  {h.address} ({h.role})')
                continue
            name = self.spec.container_name(h)
            try:
                _rc, out = self._podman(['inspect', name])
                import json
                d = json.loads(out)[0]
                ip = (d['NetworkSettings']['Networks']
                      .get(self.spec.network_name(), {})
                      .get('IPAddress', '?'))
                print(f'{name:20s} {self._state(name):20s} '
                      f'{ip} ({h.role})')
            except (PodmanError, KeyError):
                print(f'{name:20s} not found ({h.role})')

    # the daemon log set, identical to Azure CI's collect_logs()
    # (ipatests/azure/scripts/azure-run-base-tests.sh): dirsrv, httpd,
    # ipa*, krb5kdc, pki, samba, bind data, plus the boot journal
    _DAEMON_LOG_TAR = (
        'journalctl -b --no-pager > /tmp/{n}.journal.log &&'
        ' tar --ignore-failed-read -czf /tmp/{n}-logs.tar.gz'
        ' --warning=no-failed-read'
        ' /var/log/dirsrv /var/log/httpd /var/log/ipa*'
        ' /var/log/krb5kdc.log /var/log/pki /var/log/samba'
        ' /var/named/data /tmp/{n}.journal.log || :')

    def collect_logs(self):
        dest = os.path.join(self.logdir, 'collected')
        os.makedirs(dest, exist_ok=True)
        for h in self.spec.hosts:
            if h.is_external:
                continue
            name = self.spec.container_name(h)
            host_dir = os.path.join(dest, h.name)
            os.makedirs(host_dir, exist_ok=True)
            try:
                rc, out = self._podman(
                    ['exec', name, 'journalctl', '-b', '--no-pager'],
                    check=False, echo=False)
                if rc == 0 and out.strip():
                    jpath = os.path.join(
                        self.logdir, f'collect-{h.name}.journal.log')
                    with open(jpath, 'w') as lf:
                        lf.write(out if out.endswith('\n')
                                 else out + '\n')
                elif rc != 0:
                    print(f'== {h.name}: journal collection skipped '
                          f'(container not running?)')
            except PodmanError:
                pass
            # daemon logs: Azure-parity tarball
            self._exec_rc(name, self._DAEMON_LOG_TAR.format(n=h.name))
            if self._exec_rc(name, f'[ -s /tmp/{h.name}-logs.tar.gz ]'):
                continue
            try:
                self._podman(
                    ['cp', f'{name}:/tmp/{h.name}-logs.tar.gz',
                     os.path.join(host_dir, f'{h.name}-logs.tar.gz')],
                    check=False, echo=False)
            except PodmanError:
                pass
            # framework per-test logs + workflow tarballs (run-base-tests.sh)
            for path, dst in [('/root/ipa-env', 'ipa-env'),
                              ('/root/nosetests.xml', 'nosetests.xml')]:
                if self._exec_rc(name, f'[ -e {path} ]'):
                    continue
                try:
                    self._podman(['cp', f'{name}:{path}',
                                  os.path.join(host_dir, dst)],
                                 check=False, echo=False)
                except PodmanError:
                    pass

    # ------------------------------------------------------------------ run
    def copy_to_controller(self, local, remote):
        cname = self.spec.container_name(self.spec.master)
        self._podman(['cp', local, f'{cname}:{remote}'])

    def run_in_controller(self, cmd, env=None, log='run.log',
                          timeout=None):
        """Run a command in the master container, streaming output."""
        cname = self.spec.container_name(self.spec.master)
        # -w /root: ipa-run-tests captures $PWD for IPATEST_XUNIT_PATH
        # before chdir-ing into the ipatests package dir
        args = ['exec', '-i', '-w', '/root']
        for k, v in (env or {}).items():
            args += ['-e', f'{k}={v}']
        args += [cname, '/bin/bash', '-euxc', cmd]
        logpath = os.path.join(self.logdir, log)
        with open(logpath, 'wb') as lf:
            lf.write(f'+ {shlex.join(args[1:])}\n'.encode())
            lf.flush()
            proc = subprocess.Popen(
                [self.tool] + args, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            for line in proc.stdout:
                sys.stdout.buffer.write(line)
                sys.stdout.flush()
                lf.write(line)
            rc = proc.wait()
        return rc
