"""VM acquisition backends for the nested provider (design doc §3.9).

A VMBackend is the "get a VM" half of a nested provider: it turns a config
dict into provisioned VMs and hands back VMHandle objects (ssh targets)
that the nested provider then drives.  The "run the env in the VM" half
lives in nested_provider.py and composes a VMBackend with an inner
provider (default: podman).

Backends:
  * ``ssh``      -- a pool of pre-allocated user@host entries; the
                    "no real API" reference case.
  * ``command``  -- shell out to provision/deprovision scripts; the generic
                    cloud-API integration point (wrap any cloud in 2 scripts).
  * ``openstack``-- a concrete real-API example (openstack CLI); the
                    template for any other cloud.

VMHandle is the currency between a backend and the nested provider: an ssh
target (user@host[:port]) with an optional private key and free-form meta
(the backend's own VM id, used for terminate).
"""

import json
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class VMBackendError(Exception):
    pass


# --------------------------------------------------------------------- handle
@dataclass
class VMHandle:
    """An ssh-reachable provisioned VM."""
    host: str
    user: str = 'root'
    port: int = 22
    id: Optional[str] = None        # backend-specific id (used by terminate)
    key: Optional[str] = None       # private key path on the control node
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def target(self):
        return f'{self.user}@{self.host}'

    @classmethod
    def parse(cls, line: str) -> 'VMHandle':
        """Parse ``user@host``, ``user@host:port``, or a bare ``host``."""
        line = line.strip()
        user, sep, host = line.rpartition('@')
        if not sep:
            user, host = 'root', line
        port = 22
        if host.count(':') == 1 and not host.startswith('['):
            host, _, p = host.rpartition(':')
            if p.isdigit():
                port = int(p)
        return cls(host=host, user=user or 'root', port=port)

    def to_dict(self):
        return {
            'host': self.host, 'user': self.user, 'port': self.port,
            'id': self.id, 'key': self.key, 'meta': self.meta,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(host=d['host'], user=d.get('user', 'root'),
                   port=int(d.get('port', 22)), id=d.get('id'),
                   key=d.get('key'), meta=d.get('meta') or {})


# ----------------------------------------------------------------- ssh helpers
SSH_OPTS = [
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ConnectTimeout=10',
    '-o', 'BatchMode=yes',
    '-o', 'ServerAliveInterval=30',
    '-o', 'ServerAliveCountMax=4',
]


def _ssh_prefix(handle: VMHandle):
    args = ['ssh'] + SSH_OPTS
    if handle.port and handle.port != 22:
        args += ['-p', str(handle.port)]
    if handle.key:
        args += ['-i', handle.key]
    args.append(handle.target)
    return args


def ssh_run(handle: VMHandle, cmd: str, check: bool = False,
            timeout: Optional[int] = None, stream: bool = False,
            log_path: Optional[str] = None):
    """Run a shell command on the VM. Returns (rc, stdout+stderr).

    When stream=True (and log_path is given) output is teed to the log and
    echoed to stdout line by line; otherwise it is captured and returned."""
    args = _ssh_prefix(handle) + [cmd]
    if stream and log_path:
        with open(log_path, 'wb') as lf:
            lf.write(f'+ {shlex.join(args)}\n'.encode())
            lf.flush()
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            for line in proc.stdout:
                import sys
                sys.stdout.buffer.write(line)
                sys.stdout.flush()
                lf.write(line)
            rc = proc.wait()
            return rc, ''
    proc = subprocess.run(args, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout)
    out = proc.stdout.decode(errors='replace')
    if log_path:
        with open(log_path, 'a') as lf:
            lf.write(out)
    if check and proc.returncode:
        raise VMBackendError(f'ssh {handle.target} failed '
                             f'({proc.returncode}): {cmd}\n{out[-2000:]}')
    return proc.returncode, out


def rsync_to(handle: VMHandle, local: str, remote: str):
    """rsync local -> VM:remote (remote path need not pre-exist)."""
    ssh = (f"ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
           f" -o BatchMode=yes")
    if handle.port and handle.port != 22:
        ssh += f" -p {handle.port}"
    if handle.key:
        ssh += f" -i {shlex.quote(handle.key)}"
    cmd = ['rsync', '-az', '--partial', '-e', ssh, local,
           f'{handle.target}:{remote}']
    subprocess.run(cmd, check=True)


def rsync_from(handle: VMHandle, remote: str, local: str):
    """rsync VM:remote -> local."""
    ssh = (f"ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
           f" -o BatchMode=yes")
    if handle.port and handle.port != 22:
        ssh += f" -p {handle.port}"
    if handle.key:
        ssh += f" -i {shlex.quote(handle.key)}"
    cmd = ['rsync', '-az', '--partial', '-e', ssh,
           f'{handle.target}:{remote}', local]
    subprocess.run(cmd, check=True)


# ------------------------------------------------------------------- backends
class VMBackend:
    name = 'base'

    def __init__(self, cfg: Optional[Dict] = None):
        self.cfg = cfg or {}

    def provision(self, count: int = 1) -> List[VMHandle]:
        raise NotImplementedError

    def terminate(self, handle: VMHandle) -> None:
        raise NotImplementedError

    def wait_ready(self, handle: VMHandle, timeout: int = 600,
                   interval: int = 5) -> None:
        """Poll until ssh reaches the VM (or timeout)."""
        deadline = time.time() + timeout
        last = ''
        while time.time() < deadline:
            rc, out = ssh_run(handle, 'true', check=False, timeout=30)
            if rc == 0:
                print(f'== vm {handle.target} is reachable')
                return
            last = out.strip().splitlines()[-1] if out.strip() else ''
            time.sleep(interval)
        raise VMBackendError(
            f'vm {handle.target} not ssh-reachable within {timeout}s'
            + (f' (last: {last})' if last else ''))

    def describe(self) -> str:
        return self.name


class SshBackend(VMBackend):
    """A pool of pre-allocated ``user@host[:port]`` entries.

    Config::

        vm:
          backend: ssh
          hosts: [root@10.0.0.5, root@10.0.0.6]
    """
    name = 'ssh'

    def __init__(self, cfg):
        super().__init__(cfg)
        hosts = self.cfg.get('hosts') or []
        self._pool = [VMHandle.parse(h) if isinstance(h, str)
                      else VMHandle.from_dict(h) for h in hosts]

    def provision(self, count=1):
        if not self._pool:
            raise VMBackendError('ssh backend: no hosts configured')
        if count > len(self._pool):
            raise VMBackendError(
                f'ssh backend: asked for {count} but the pool has '
                f'{len(self._pool)}')
        out, self._pool = self._pool[:count], self._pool[count:]
        return out

    def terminate(self, handle):
        # pre-allocated: leave it in place (it belongs to the pool)
        print(f'== vm {handle.target}: pre-allocated, leaving in place')


class CommandBackend(VMBackend):
    """Provision/deprovision by shelling out to user scripts.

    The generic cloud-API integration point: wrap any cloud in two scripts.

    Config::

        vm:
          backend: command
          provision_cmd: /opt/cloud/get-vms.sh     # $1 = count
          deprovision_cmd: /opt/cloud/drop-vms.sh  # args = handle ids/targets

    ``provision_cmd <count>`` must print one ``user@host[:port]`` per line
    (or a JSON list of {host, user, port, id, key}).  ``deprovision_cmd``
    receives one argument per VM being released (its id if present, else
    its user@host target)."""
    name = 'command'

    def _run_script(self, script: str, argv: List[str]) -> str:
        if not script:
            raise VMBackendError(f'command backend: no {script} configured')
        if isinstance(script, (list, tuple)):
            cmd = [str(x) for x in list(script) + argv]
        else:
            cmd = shlex.split(script) + [str(a) for a in argv]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=600)
        except FileNotFoundError:
            raise VMBackendError(f'command backend: script not found: '
                                 f'{shlex.join(cmd)}')
        out = proc.stdout.decode(errors='replace')
        if proc.returncode:
            raise VMBackendError(
                f'command backend: {shlex.join(cmd)} failed '
                f'({proc.returncode}):\n{out[-2000:]}')
        return out

    def provision(self, count=1):
        out = self._run_script(self.cfg.get('provision_cmd'), [count])
        handles: List[VMHandle] = []
        # try JSON first (a list of handle dicts), fall back to lines
        s = out.strip()
        if s.startswith('['):
            for i, d in enumerate(json.loads(s)):
                h = VMHandle.from_dict(d)
                h.id = h.id or f'vm{i}'
                handles.append(h)
            return handles
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            handles.append(VMHandle.parse(line))
        if not handles:
            raise VMBackendError(
                'command backend: provision_cmd printed no VM handles')
        return handles

    def terminate(self, handle):
        arg = handle.id or handle.target
        self._run_script(self.cfg.get('deprovision_cmd'), [arg])
        print(f'== vm {handle.target}: deprovisioned via command backend')


class OpenstackBackend(VMBackend):
    """A concrete real cloud-API example, built on the ``openstack`` CLI.

    This is the template for any other cloud: map provision to
    ``server create`` (+ floating IP), terminate to ``server delete``.

    Config::

        vm:
          backend: openstack
          cloud: prod          # `openstack --cloud prod` (or OS_* env)
          image: fedora-44
          flavor: m1.medium
          keypair: freeipa-ci # optional
          network: test-net   # optional fixed network
          floating_pool: public
    """
    name = 'openstack'

    def _os(self, args: List[str], parse_json: bool = True):
        cmd = ['openstack']
        cloud = self.cfg.get('cloud')
        if cloud:
            cmd += ['--cloud', cloud]
        cmd += args
        if parse_json and '--format' not in args:
            cmd += ['--format', 'json']
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=600)
        except FileNotFoundError:
            raise VMBackendError('openstack backend: `openstack` CLI not '
                                 'found on the control node')
        out = proc.stdout.decode(errors='replace')
        if proc.returncode:
            raise VMBackendError(
                f'openstack backend: {shlex.join(cmd)} failed '
                f'({proc.returncode}):\n{out[-2000:]}')
        return json.loads(out) if parse_json else out

    def provision(self, count=1):
        image = self.cfg.get('image')
        flavor = self.cfg.get('flavor')
        if not image or not flavor:
            raise VMBackendError('openstack backend: need `image` and '
                                 '`flavor`')
        import uuid
        handles = []
        for i in range(count):
            name = f'freeipa-ci-{uuid.uuid4().hex[:10]}'
            create = ['server', 'create', '--wait', '--image', image,
                      '--flavor', flavor, '-n', name]
            if self.cfg.get('keypair'):
                create += ['--keypair', self.cfg['keypair']]
            if self.cfg.get('network'):
                create += ['--network', self.cfg['network']]
            self._os(create, parse_json=False)
            self.wait_ready_ip(name)
            ip = self._ip_for(name)
            h = VMHandle(host=ip, user='root', id=name)
            h.meta['openstack'] = name
            handles.append(h)
            print(f'== openstack: provisioned {name} at {ip}')
        return handles

    def wait_ready_ip(self, name):
        # `server create --wait` already blocks until ACTIVE; poll the
        # address just in case the floating/fixed IP attaches late.
        deadline = time.time() + int(self.cfg.get('timeout', 300))
        while time.time() < deadline:
            ip = self._ip_for(name)
            if ip:
                return ip
            time.sleep(5)
        raise VMBackendError(f'openstack backend: no address for {name}')

    def _ip_for(self, name) -> Optional[str]:
        pool = self.cfg.get('floating_pool', 'public')
        # prefer a floating IP, else the first fixed address
        try:
            fips = self._os(['floating', 'ip', 'list', '--server', name,
                             '--format', 'json'])
            if fips:
                return fips[0]['IP']
        except VMBackendError:
            pass
        srv = self._os(['server', 'show', name, '--format', 'json'])
        addrs = srv.get('addresses') or {}
        for addrs_list in addrs.values():
            for a in addrs_list:
                if a.get('addr'):
                    return a['addr']
        return None

    def terminate(self, handle):
        name = handle.id
        if not name:
            print(f'== openstack: no server id for {handle.target}; '
                  f'skipping delete')
            return
        # release floating ip if present
        pool = self.cfg.get('floating_pool', 'public')
        try:
            fips = self._os(['floating', 'ip', 'list', '--server', name,
                             '--format', 'json'])
            for f in fips:
                self._os(['floating', 'ip', 'delete', f['IP']],
                         parse_json=False)
        except VMBackendError:
            pass
        self._os(['server', 'delete', name], parse_json=False)
        print(f'== openstack: deleted {name}')


BACKENDS = {
    'ssh': SshBackend,
    'command': CommandBackend,
    'openstack': OpenstackBackend,
}


def make_backend(cfg: Dict) -> VMBackend:
    cfg = cfg or {}
    name = cfg.get('backend')
    if not name:
        raise VMBackendError('vm backend: `vm.backend` is required')
    cls = BACKENDS.get(name)
    if cls is None:
        raise VMBackendError(
            f'unknown vm backend {name!r} (known: {sorted(BACKENDS)})')
    return cls(cfg)
