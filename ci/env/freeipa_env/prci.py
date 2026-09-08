"""Migrate PRCI definitions (ipatests/prci_definitions/*.yaml) to
freeipa-env presets.

PRCI model: a controller provisions VMs per topology (e.g.
``master_1repl_1client``) and exports ``MASTER_env1`` / ``REPLICA_env1`` /
``CLIENT_env1`` / ``AD_env1`` (see pytest_ipa/integration/env_config.py);
each job class (RunPytest*, RunWebuiTests, RunADTests) then installs the
topology and runs ``test_suite``.

Mapping to the freeipa-env preset model:

  PRCI                   preset
  ----                   ------
  topology name        ->  hosts (role + count)
  topology memory      ->  memory split evenly across IPA hosts
                           (limits, rounded down to 100 MiB, min 512 MiB)
  test_suite           ->  run.tests
  class Build          ->  skipped (the image pipeline replaces it)
  class RunPytest*     ->  mode: integration
  class RunWebuiTests  ->  mode: base + NOTE (needs a browser/selenium
                           environment, not in freeipa-ci/full)
  AD topology hosts    ->  external hosts: PRCI provisions real AD DCs,
                           freeipa-env expects the user to provide them
                           (placeholder FQDNs + RFC 5737 addresses)
  ipa_ipa_trust        ->  skipped (two IPA domains; the preset model has
                           one IPA domain plus AD domains)

The generated presets are plain freeipa-env presets: review them, replace
the AD placeholders, then ``freeipa-env up/run/down`` as usual.
"""

import os

import yaml


# PRCI AD topology tokens -> (config role, placeholder FQDN, placeholder IP).
# The FQDNs are placeholders: the real AD forest's zones are unknown here
# and must be edited per environment. Addresses are in the RFC 5737
# documentation range, like ci/env/presets/external-smoke.yaml.
_AD_TOKENS = {
    'adroot': ('ad', 'ad1.ad.test', '192.0.2.101'),
    'adchild': ('ad_subdomain', 'ad1.adchild.ad.test', '192.0.2.102'),
    'adtree': ('ad_treedomain', 'ad1.adtree.example', '192.0.2.103'),
}
# Role ordering must match the framework's AD domain types
# (pytest_ipa/integration/config.py Domain.static_roles).
_AD_ROLES_IN_ORDER = ('ad', 'ad_subdomain', 'ad_treedomain')

_RUNPYTEST_CLASSES = ('RunPytest', 'RunPytest2', 'RunPytest3', 'RunADTests')
_WEBUI_CLASS = 'RunWebuiTests'


def parse_topology(name):
    """Map a PRCI topology name to (ipa_roles, ad_tokens).

    Returns None for topologies freeipa-env cannot express.

    Grammar (from ipatests/prci_definitions/*.yaml + prci_checker.py):
      ipaserver                        1 IPA server (base mode)
      master[_Nrepl]_Mclient           IPA server(s) + clients
      ad_<same>                        + 1 AD domain (root)
      adroot_adchild_adtree_<same>     + AD, child, treeless AD domains
      build, ipa_ipa_trust             not mappable -> None
    """
    n = (name or '').lower()
    if n in ('ipaserver', 'master'):
        return (['master'], [])
    if n.startswith('build') or 'ipa_ipa_trust' in n:
        return None
    ad_tokens = []
    if n.startswith('adroot_adchild_adtree_'):
        ad_tokens = ['adroot', 'adchild', 'adtree']
        n = n[len('adroot_adchild_adtree_'):]
    elif n.startswith('ad_'):
        ad_tokens = ['adroot']
        n = n[len('ad_'):]
    m = __import__('re').fullmatch(r'master(?:_(\d+)repl)?(?:_(\d+)client)?', n)
    if not m:
        return None
    repl = int(m.group(1) or 0)
    clients = int(m.group(2) or 0)
    ipa = ['master'] + ['replica'] * repl + ['client'] * clients
    return (ipa, ad_tokens)


def split_memory(total_mb, n_hosts):
    """Split a PRCI topology memory budget across hosts (limits).

    PRCI treats the number as the topology's total memory (MB); we
    distribute it evenly as per-host limits, rounded down to 100 MiB
    with a 512 MiB floor (Fedora 44 images need more headroom)."""
    if not total_mb or n_hosts <= 0:
        return 1024
    per = (int(total_mb) // n_hosts // 100) * 100
    return max(512, per)


def _job_suffix(job_name, prefix):
    """`fedora-latest/test_foo` -> `test_foo` (lower-cased)."""
    if '/' in job_name:
        job_name = job_name.split('/', 1)[1]
    if prefix and job_name.startswith(prefix + '/'):
        job_name = job_name[len(prefix) + 1:]
    return job_name.lower()


def build_preset(defpath, job_name, job, common_prefix=None):
    """Build one preset dict from a PRCI job entry.

    Returns (preset, header_lines, notes) or None if the job cannot be
    mapped (the caller decides the skip reason)."""
    spec = job['job']
    cls = spec['class']
    args = spec.get('args', {}) or {}
    topo_name = (args.get('topology') or {}).get('name', '')
    suite = (args.get('test_suite') or '').split()
    timeout = args.get('timeout')

    parsed = parse_topology(topo_name)
    if parsed is None:
        return None
    ipa_roles, ad_tokens = parsed

    if cls == _WEBUI_CLASS:
        mode = 'base'
    elif cls in _RUNPYTEST_CLASSES:
        mode = 'integration' if len(ipa_roles) > 1 else 'base'
    else:
        return None

    per_mem = split_memory((args.get('topology') or {}).get('memory'),
                           len(ipa_roles))
    counts = {}
    hosts = []
    for r in ipa_roles:
        counts[r] = counts.get(r, 0) + 1
        hosts.append({'role': r, 'name': f'{r}{counts[r]}'})
    for tok in ad_tokens:
        role, fqdn, addr = _AD_TOKENS[tok]
        hosts.append({'role': role, 'name': fqdn, 'address': addr,
                      'user': 'root'})

    name = _job_suffix(job_name, common_prefix)
    preset = {
        'provider': 'podman',
        'name': name,
        'domain': 'ipa.test',
        'image': 'freeipa-ci/full:44',
        'hosts': hosts,
        # resources are keyed by role (EnvSpec.resource(role))
        'resources': {r: {'memory': f'{per_mem}m',
                          'memory-swap': f'{2*per_mem}m'}
                      for r in counts},
        'run': {
            'mode': mode,
            'setup_dns': True,
            'setup_kra': True,
            'tests': list(suite),
        },
    }

    header = [
        f'# Generated by `freeipa-env migrate` from {defpath}',
        f'# PRCI job: {job_name}  (class: {cls})',
        f'# PRCI topology: {topo_name} '
        f'(cpu {(args.get("topology") or {}).get("cpu", "?")}, '
        f'memory {(args.get("topology") or {}).get("memory", "?")})',
    ]
    if timeout:
        header.append(f'# PRCI timeout: {timeout}s (informational; '
                      f'freeipa-env has no timeout field)')
    notes = []
    if cls == _WEBUI_CLASS:
        header.append('# NOTE: PRCI RunWebuiTests needs a browser + selenium '
                      'on the test host,')
        header.append('#       which freeipa-ci/full does not include; '
                      'this preset will not pass as-is.')
        notes.append('RunWebuiTests: browser/selenium not in image')
    if ad_tokens:
        notes.append(f'{len(ad_tokens)} external AD host(s) require manual '
                     f'setup (edit placeholders)')
    if not suite:
        header.append('# NOTE: PRCI job has an empty test_suite; '
                      'fill in run.tests.')
        notes.append('empty test_suite')
    return (preset, header, notes)


def ad_comments(preset):
    """The AD placeholder footer for a preset with external AD hosts."""
    ad = [h for h in preset['hosts'] if h['role'] in _AD_ROLES_IN_ORDER]
    if not ad:
        return []
    out = ['',
           '# --- Active Directory hosts (external): PRCI provisions these '
           'AD DCs itself; freeipa-env does not.',
           "# Point each 'address' at a reachable AD DC and set 'name' to "
           'its real FQDN',
           '# before `freeipa-env up`. The IPA containers resolve the AD '
           'hosts via /etc/hosts.']
    for h in ad:
        out.append(f"# {h['role']}: {h['name']} ({h['address']}) -- EDIT ME")
    return out

def iter_jobs(defpath):
    """Yield (job_name, preset_name, skip_reason, built) in definition
    order.

    ``preset_name`` is the preset file stem (matching what ``migrate``
    writes under ``presets/prci/<definition>/``) or None for jobs that
    cannot be migrated, with ``skip_reason`` explaining why;
    ``built`` is the (preset, header, notes) tuple from ``build_preset``
    (None for skipped jobs)."""
    with open(defpath) as f:
        doc = yaml.safe_load(f) or {}
    jobs = doc.get('jobs') or {}
    if not jobs:
        raise ValueError(f'{defpath}: no jobs found')

    # strip the common leading component (`fedora-latest/`) so preset
    # names stay short
    prefixes = {j.split('/', 1)[0] if '/' in j else '' for j in jobs}
    common = prefixes.pop() if len(prefixes) == 1 and '' not in prefixes \
        else ''

    for job_name, job in jobs.items():
        cls = ((job.get('job') or {}).get('class', '?'))
        if cls == 'Build':
            yield (job_name, None, 'class Build: replaced by the freeipa-ci'
                                  ' image pipeline', None)
            continue
        built = build_preset(defpath, job_name, job, common)
        if built is None:
            topo = (((job.get('job') or {}).get('args') or {})
                    .get('topology') or {}).get('name', '?')
            yield (job_name, None, f'class {cls} / topology {topo}: '
                                   'not mappable', None)
            continue
        yield (job_name, built[0]['name'], None, built)


def migrate(defpath, outdir, only=None, report=True):
    """Migrate a PRCI definition file to presets under outdir.

    Returns (written, skipped): written is a list of
    (path, preset, notes), skipped a list of (job_name, reason)."""
    os.makedirs(outdir, exist_ok=True)
    written, skipped = [], []
    for job_name, preset_name, reason, built in iter_jobs(defpath):
        if built is None:
            skipped.append((job_name, reason))
            continue
        if only and not any(o.lower() in job_name.lower() for o in only):
            continue
        preset, header, notes = built
        path = os.path.join(outdir, f'{preset["name"]}.yaml')
        with open(path, 'w') as f:
            f.write('\n'.join(header) + '\n\n')
            yaml.safe_dump(preset, f, default_flow_style=False,
                           sort_keys=False)
            for ln in ad_comments(preset):
                f.write(ln + '\n')
        written.append((path, preset, notes))
    if report:
        _write_report(defpath, outdir, written, skipped)
    return written, skipped


def _write_report(defpath, outdir, written, skipped):
    defname = os.path.basename(defpath)
    path = os.path.join(outdir, 'MIGRATED.md')
    with open(path, 'w') as f:
        f.write(f'# PRCI -> freeipa-env migration: {defname}\n\n')
        f.write(f'Source: `{defpath}`\n\n')
        f.write(f'- migrated: {len(written)}\n')
        f.write(f'- skipped: {len(skipped)}\n\n')
        if skipped:
            f.write('## Skipped\n\n')
            for jn, reason in skipped:
                f.write(f'- `{jn}`: {reason}\n')
            f.write('\n')
        f.write('## Migrated\n\n')
        for _path, preset, notes in written:
            n_ad = len([h for h in preset['hosts']
                        if h['role'] in _AD_ROLES_IN_ORDER])
            n_ipa = len(preset['hosts']) - n_ad
            f.write(f'### `{preset["name"]}`  '
                    f'({preset["run"]["mode"]}, {n_ipa} IPA host(s)'
                    + (f', {n_ad} AD host(s)' if n_ad else '') + ')\n\n')
            for t in preset['run']['tests'][:4]:
                f.write(f'- test: `{t}`\n')
            if len(preset['run']['tests']) > 4:
                f.write(f'- ... and {len(preset["run"]["tests"]) - 4} more\n')
            for note in notes:
                f.write(f'- note: {note}\n')
            f.write('\n')
    return path
