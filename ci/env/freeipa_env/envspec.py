"""env.yaml schema (B1).

An env spec describes the full set of hosts in a test environment and how
to build them:

  name: base-xmlrpc              # env id: container/network prefix
  provider: podman               # podman (default) | external
  domain: ipa.test
  domain_level: 1
  dist: 44                       # fedora dist (podman provider)
  image: freeipa-ci/full:44      # image (podman provider; per-host override)
  dns_forwarder: 8.8.8.8         # resolv.conf for non-controller hosts and
                                 # the installer's --forwarder default
  hosts:
    - {role: master, name: master1}
    - {role: client, name: client1}
    - {role: external-master, name: ad1, address: 10.0.0.5}   # external
  resources:                     # per-role overrides (defaults below)
    master: {memory: 1800m, memory-swap: 2500m}
  run:
    mode: base                   # base | integration
    setup_dns: true
    setup_kra: true
    forwarder: 8.8.8.8           # explicit; else --auto-forwarders
    tests: [test_xmlrpc]
    ignore: [test_xmlrpc/test_dns_plugin.py]
    deselect: [test_x::y]
    args: []                     # extra ipa-run-tests args
"""

from dataclasses import dataclass, field
from typing import Optional


class EnvSpecError(Exception):
    pass


@dataclass
class HostSpec:
    role: str
    name: str
    address: Optional[str] = None     # external host (SSH-reachable)
    user: Optional[str] = None        # external: SSH user (default root)
    port: Optional[int] = None        # external: SSH port
    image: Optional[str] = None       # per-host image override
    os: Optional[str] = None          # e.g. windows (ad-image lane)

    @classmethod
    def from_dict(cls, d, idx):
        for req in ('role', 'name'):
            if req not in d:
                raise EnvSpecError(f'hosts[{idx}]: missing {req!r}')
        return cls(**d)

    @property
    def is_external(self):
        return bool(self.address)


@dataclass
class RunSpec:
    mode: str = 'integration'         # base | integration
    setup_dns: bool = True
    setup_kra: bool = True
    forwarder: Optional[str] = None   # None -> --auto-forwarders (or
                                      # --no-forwarders for internal nets)
    network_internal: bool = False    # no egress: --no-forwarders
    tests: list = field(default_factory=list)
    ignore: list = field(default_factory=list)
    deselect: list = field(default_factory=list)
    args: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, d):
        if d is None:
            return cls()
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(d) - known
        if unknown:
            raise EnvSpecError(f'run: unknown keys {sorted(unknown)}')
        return cls(**d)


@dataclass
class EnvSpec:
    name: str
    domain: str
    provider: str = 'podman'
    dist: Optional[str] = None
    image: Optional[str] = None
    domain_level: int = 1
    fips: bool = False
    ipv6: bool = True
    dns_forwarder: Optional[str] = None
    admin_name: str = 'admin'
    admin_password: str = 'Secret123'
    dirman_password: str = 'Secret123'
    hosts: list = field(default_factory=list)
    resources: dict = field(default_factory=dict)
    run: Optional[RunSpec] = None
    raw: dict = field(default_factory=dict, repr=False)

    # Defaults mirror ipatests/azure/templates/variables-fedora.yml.
    DEFAULT_RESOURCES = {
        'master': {'memory': '1800m', 'memory-swap': '2500m'},
        'replica': {'memory': '1800m', 'memory-swap': '2500m'},
        'client': {'memory': '512m', 'memory-swap': '1024m'},
        'external': {'memory': '1800m', 'memory-swap': '2500m'},
    }

    @classmethod
    def from_dict(cls, d):
        for req in ('name', 'domain'):
            if req not in d:
                raise EnvSpecError(f"missing top-level {req!r}")
        known = {f for f in cls.__dataclass_fields__ if f != 'raw'}
        unknown = set(d) - known
        if unknown:
            raise EnvSpecError(f'unknown top-level keys {sorted(unknown)}')
        spec = cls(**{k: v for k, v in d.items() if k in known}, raw=d)
        spec.hosts = [HostSpec.from_dict(h, i)
                      for i, h in enumerate(spec.hosts)]
        if not spec.hosts:
            raise EnvSpecError('env needs at least one host')
        if not any(h.role == 'master' for h in spec.hosts):
            raise EnvSpecError('env needs a master host')
        spec.run = RunSpec.from_dict(d.get('run'))
        if spec.provider not in ('podman', 'external'):
            raise EnvSpecError(f'provider must be podman|external, '
                               f'got {spec.provider!r}')
        return spec

    @classmethod
    def from_file(cls, path):
        import yaml
        with open(path) as f:
            d = yaml.safe_load(f)
        if not isinstance(d, dict):
            raise EnvSpecError(f'{path}: not a mapping')
        return cls.from_dict(d)

    @property
    def realm(self):
        return self.domain.upper()

    def hosts_by_role(self, role):
        return [h for h in self.hosts if h.role == role]

    @property
    def controllers(self):
        """IPA servers (master + replicas) that run the framework."""
        return [h for h in self.hosts if h.role in ('master', 'replica')]

    @property
    def master(self):
        return self.hosts_by_role('master')[0]

    def resource(self, role):
        d = dict(self.DEFAULT_RESOURCES.get(role, self.DEFAULT_RESOURCES['client']))
        d.update(self.resources.get(role, {}))
        return d

    def host_fqdn(self, h):
        """FQDN for a host: <name>.<domain> unless it is external (its own
        FQDN is authoritative; name is a label only)."""
        return f'{h.name}.{self.domain}'

    def podman_image(self, h):
        img = h.image or self.image
        if not img:
            raise EnvSpecError(f'no image for host {h.name} '
                               f'(set image: or hosts[].image)')
        return img

    def network_name(self):
        return f'env-{self.name}'

    def container_name(self, h):
        # <name>_<role>_<index-within-role>
        idx = [x for x in self.hosts if x.role == h.role].index(h) + 1
        return f'{self.name}_{h.role}_{idx}'
