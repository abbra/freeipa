"""freeipa-env CLI: up / run / down / show / logs over an env.yaml.

`logs` (D1) categorizes the collected artifacts and retrieves them per
category for CI issue triage; see loganalyze.py."""

import argparse
import json
import os
import re
import shlex
import sys

from .envspec import EnvSpec, EnvSpecError, RunSpec
from .podman_provider import PodmanProvider, PodmanError
from .external_provider import ExternalProvider, ExternalError
from .vmbackend import VMBackendError
from .nested_provider import NestedProvider, NestedError
from .loganalyze import (LogStore, CATEGORIES, CATEGORY_NAMES,
                         render_list, render_json, show_categories,
                         DEFAULT_LINES, DEFAULT_TAIL)

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), 'scripts')
RUN_SCRIPT = os.path.join(SCRIPTS_DIR, 'run-base-tests.sh')
CONTAINER_LOGSDIR = '/root/ipa-env/logs'
CONFIG_IN_CONTAINER = '/root/.ipa/ipa-test-config.yaml'


def default_workdir(spec):
    return os.path.join(os.getcwd(), f'{spec.name}.env')


def load_spec(path):
    try:
        return EnvSpec.from_file(path)
    except EnvSpecError as e:
        print(f'error: {e}', file=sys.stderr)
        sys.exit(2)


def make_provider(spec, workdir, args):
    if spec.provider == 'podman':
        return PodmanProvider(spec, workdir, tool=args.tool,
                              seccomp=args.seccomp)
    if spec.provider == 'nested':
        return NestedProvider(spec, workdir, args)
    return ExternalProvider(spec, workdir, strict=args.strict,
                         ssh_key=args.ssh_key)


def build_run_env(spec):
    run = spec.run or RunSpec()
    env = {
        'IPA_TESTS_DOMAIN': spec.domain,
        'IPA_TESTS_REALM': spec.realm,
        'IPA_TESTS_LOGSDIR': CONTAINER_LOGSDIR,
        # shlex-quoted: the values expand through `bash -c` in the runner
        # scripts (and ipa-run-tests re-spawns pytest through a shell), so
        # multi-word elements (e.g. -k "not test_dns_soa") must survive.
        'IPA_TESTS_TO_RUN': ' '.join(shlex.quote(t) for t in run.tests),
        'IPA_TESTS_TO_IGNORE': ' '.join(f'--ignore {shlex.quote(x)}'
                                        for x in run.ignore),
        'IPA_TESTS_TO_DESELECT': ' '.join(f'--deselect {shlex.quote(x)}'
                                          for x in run.deselect),
        'IPA_TESTS_ARGS': ' '.join(shlex.quote(a) for a in run.args),
        'IPA_NETWORK_INTERNAL': str(run.network_internal).lower(),
        'SETUP_KRA': '1' if run.setup_kra else '0',
    }
    fwd = run.forwarder or spec.dns_forwarder
    if fwd and not run.network_internal:
        env['SERVER_FORWARDER'] = fwd
    return env


def cmd_up(args):
    spec = load_spec(args.env)
    workdir = args.workdir or default_workdir(spec)
    os.makedirs(workdir, exist_ok=True)
    prov = make_provider(spec, workdir, args)
    prov.up()
    return 0


def cmd_down(args):
    spec = load_spec(args.env)
    workdir = args.workdir or default_workdir(spec)
    prov = make_provider(spec, workdir, args)
    prov.down()
    return 0


def cmd_show(args):
    spec = load_spec(args.env)
    workdir = args.workdir or default_workdir(spec)
    prov = make_provider(spec, workdir, args)
    prov.show()
    return 0


def cmd_resolve(args):
    """Resolve the preset's logical image references to the concrete
    local images — a provider task (presets never pin a build).
    Prints one line per image: `<ref> <concrete> <image_id>`. Exit 0 iff
    every reference resolves."""
    spec = load_spec(args.env)
    workdir = args.workdir or default_workdir(spec)
    prov = make_provider(spec, workdir, args)
    resolved = prov.resolve_images()
    if not resolved:
        print('no image references to resolve locally (the provider '
              'resolves at `up` time, e.g. a nested provider resolves on '
              'the provisioned VM)')
        return 0
    for ref, (concrete, img_id) in resolved.items():
        print(f'{ref} {concrete} {img_id}')
    return 0


def cmd_ensure(args):
    """Build the preset's channel images ourselves (design §3.10) when they
    are missing on this host — a provider task, the build-side counterpart
    of `resolve`. Consumes the spec's `build.srpm` (the SRPM the control node
    produced with ci/scripts/make-srpms.sh); absent channels are built in the
    dedicated build image and baked into the channel `full` image. Present
    channels are left alone unless `--build` (or `build.force`) is set.
    Prints one line per channel: `<ref> <concrete> <image_id>`."""
    spec = load_spec(args.env)
    workdir = args.workdir or default_workdir(spec)
    os.makedirs(workdir, exist_ok=True)
    prov = make_provider(spec, workdir, args)
    force = getattr(args, 'build', False) or None
    ensured = prov.ensure_images(force=force)
    if not ensured:
        print('no channel images to build locally (the provider builds at '
              '`up` time on the provisioned host, e.g. a nested provider '
              'builds on the VM; or the spec has no build.srpm)')
        return 0
    for ref, (concrete, img_id) in ensured.items():
        print(f'{ref} {concrete} {img_id}')
    return 0


def cmd_check(args):
    """Parse + validate preset files without spawning anything (CI gating).

    Checks every preset (default: all under ci/env/presets) parses as an
    EnvSpec and passes the provider's read-only sanity checks. Exit 0 iff
    every preset is sound and no given path was missing."""
    from .checker import check_paths
    results, missing = check_paths(args.paths or None)
    n_ok = sum(1 for _p, errs in results if not errs)
    n_bad = sum(1 for _p, errs in results if errs)
    for path, errs in results:
        for e in errs:
            print(f'FAIL {path}: {e}')
    for m in missing:
        print(f'FAIL {m}: file not found')
    total = len(results)
    print(f'\nchecked {total} presets: {n_ok} ok, {n_bad} failed, '
          f'{len(missing)} missing')
    return 1 if (n_bad or missing) else 0


def cmd_migrate(args):
    """Generate freeipa-env presets from a PRCI definition file."""
    from .prci import migrate
    if args.out:
        outdir = args.out
    else:
        stem = os.path.splitext(os.path.basename(args.definition))[0]
        outdir = os.path.join('presets', 'prci', stem.replace('_', '-'))
    written, skipped = migrate(args.definition, outdir, only=args.jobs)
    for path, preset, notes in written:
        ad = any('AD host' in n for n in notes)
        flag = '  [AD: edit external placeholders]' if ad else ''
        print(f'== {path}  [{preset["run"]["mode"]}{flag}]')
        for n in notes:
            print(f'   note: {n}')
    for jn, reason in skipped:
        print(f'== skipped {jn}: {reason}')
    print(f'\n{len(written)} preset(s) generated in {outdir}, '
          f'{len(skipped)} skipped; report: '
          f'{os.path.join(outdir, "MIGRATED.md")}')
    return 0


def cmd_logs(args):
    workdir = args.workdir
    spec = None
    if not workdir:
        if not args.env:
            print('error: give an env file (to derive the default workdir) '
                  'or --workdir DIR', file=sys.stderr)
            return 2
        spec = load_spec(args.env)
        workdir = default_workdir(spec)
    if not os.path.isdir(workdir):
        print(f'error: no artifacts in {workdir} (run `up`/`run`/`down` first)',
              file=sys.stderr)
        return 2
    if args.refresh:
        if not args.env:
            print('error: --refresh requires the env file', file=sys.stderr)
            return 2
        spec = spec or load_spec(args.env)
        prov = make_provider(spec, workdir, args)
        print('== collecting fresh logs from the environment')
        try:
            prov.collect_logs()
        except (PodmanError, ExternalError) as e:
            print(f'warning: log collection failed: {e}', file=sys.stderr)
    if args.pattern:
        try:
            args.pattern_compiled = re.compile(args.pattern)
        except re.error as e:
            print(f'error: invalid --pattern: {e}', file=sys.stderr)
            return 2
    else:
        args.pattern_compiled = None
    store = LogStore(workdir)
    cats = args.category or []
    if args.list or not cats:
        if args.json:
            render_json(store)
        else:
            render_list(store)
    if cats:
        rc = show_categories(store, cats, args)
        return rc or 0
    return 0


def cmd_tf_logs(args):
    """Fetch a finished Testing Farm request's job artifacts into a local
    workdir and parse them with the same ``logs`` machinery a local/ssh job
    uses (categories, pattern, json, per-host)."""
    from .loganalyze import (LogStore, CATEGORIES, CATEGORY_NAMES,
                             render_list, render_json, show_categories,
                             DEFAULT_LINES, DEFAULT_TAIL)
    from .testingfarm import fetch_artifacts, TfApiError

    token = args.tf_token or os.environ.get('TESTING_FARM_API_TOKEN')
    if not token:
        print('error: no TF API token (pass --tf-token or set '
              'TESTING_FARM_API_TOKEN)', file=sys.stderr)
        return 2
    workdir = args.workdir
    if not workdir:
        stem = re.sub(r'[^A-Za-z0-9._-]+', '-', args.request_id).strip('-')
        workdir = os.path.join(os.getcwd(), f'tf-{stem}.env')
    try:
        n = fetch_artifacts(
            args.request_id, workdir, token,
            url=args.tf_url or 'https://api.testing-farm.io',
            include_consoles=not args.no_consoles,
            log=lambda l: print(l, file=sys.stderr))
    except TfApiError as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    if n == 0:
        print(f'error: no job artifacts in request {args.request_id} '
              '(the job may have died before `down`, or has not finished)',
              file=sys.stderr)
        return 1
    print(f'== fetched {n} artifact file(s) into {workdir}', file=sys.stderr)
    print(f'== workdir: {workdir}', file=sys.stderr)

    # reuse the `logs` parsing path exactly
    if args.pattern:
        try:
            args.pattern_compiled = re.compile(args.pattern)
        except re.error as e:
            print(f'error: invalid --pattern: {e}', file=sys.stderr)
            return 2
    else:
        args.pattern_compiled = None
    store = LogStore(workdir)
    cats = args.category or []
    if args.list or not cats:
        if args.json:
            render_json(store)
        else:
            render_list(store)
    if cats:
        rc = show_categories(store, cats, args)
        return rc or 0
    return 0


def cmd_run(args):
    spec = load_spec(args.env)
    workdir = args.workdir or default_workdir(spec)
    prov = make_provider(spec, workdir, args)
    run = spec.run or RunSpec()
    env = build_run_env(spec)

    if run.mode == 'base':
        prov.copy_to_controller(RUN_SCRIPT, '/root/run-base-tests.sh')
        rc = prov.run_in_controller('bash /root/run-base-tests.sh',
                                    env=env, log='run.log')
    elif run.mode == 'integration':
        argv = ['ipa-run-tests', '--logging-level=debug', '--verbose', '-ra',
                '--with-xunit']
        for x in run.ignore:
            argv += ['--ignore', x]
        for x in run.deselect:
            argv += ['--deselect', x]
        argv += run.args
        argv += run.tests
        env['IPATEST_YAML_CONFIG'] = CONFIG_IN_CONTAINER
        rc = prov.run_in_controller(shlex.join(
            [a for a in argv if a]), env=env, log='run.log')
    else:
        print(f'error: unknown run mode {run.mode!r}', file=sys.stderr)
        return 2

    # pull the xunit report next to the workdir logs (podman only)
    if isinstance(prov, PodmanProvider) and rc is not None:
        _fetch_xunit(prov, workdir)
    print(f'== run finished with exit code {rc}')
    return rc if rc is not None else 1


def _fetch_xunit(prov, workdir):
    try:
        # ipa-run-tests writes $PWD/nosetests.xml (PWD at invocation;
        # run-base-tests.sh pushd's into $IPA_TESTS_LOGSDIR, like Azure).
        # probe LOGSDIR, /root, /, and the pkg dir. The probe uses
        # double-quoted python literals only, so it can be wrapped in
        # single quotes for the container bash safely
        probe = ('import ipatests, os; '
                 'c = ["/root/ipa-env/logs/nosetests.xml", '
                 '"/root/nosetests.xml", "/nosetests.xml", '
                 'os.path.join(os.path.dirname(ipatests.__file__), '
                 '"nosetests.xml")]; '
                 'print(next(p for p in c if os.path.isfile(p)))')
        _rc, out = prov._exec(
            prov.spec.container_name(prov.spec.master),
            "python3 -c '%s'" % probe)
        src = out.strip().splitlines()[-1].strip()
        prov._podman(['cp', f'{prov.spec.container_name(prov.spec.master)}:'
                            f'{src}',
                      os.path.join(workdir, 'nosetests.xml')])
        print(f'== xunit report: {os.path.join(workdir, "nosetests.xml")}')
    except (PodmanError, IndexError):
        print('== no xunit report found', file=sys.stderr)


def cmd_queue(args):
    if args.queue_cmd == 'generate':
        from .queue import generate_prci_queue
        text = generate_prci_queue(args.definition)
        if args.out:
            d = os.path.dirname(os.path.abspath(args.out))
            os.makedirs(d, exist_ok=True)
            with open(args.out, 'w') as f:
                f.write(text)
            print(f'wrote {args.out}')
        else:
            sys.stdout.write(text)
        return 0

    from .queue import QueueSpec
    from .supervisor import Supervisor, SupervisorError
    from .runner import make_runner, RunnerTransportError
    try:
        q = QueueSpec.from_file(args.queue_file)
    except (ValueError, OSError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 2
    jobs = q.jobs
    if args.jobs:
        jobs = [j for j in jobs
                if any(o.lower() in j.key.lower() for o in args.jobs)]
    if args.limit:
        jobs = jobs[:args.limit]
    if not jobs:
        print('error: no jobs left after filtering', file=sys.stderr)
        return 2
    q.jobs = jobs
    tf_cfg = _tf_config(args)
    if tf_cfg is None:
        return 2
    if args.dry_run:
        print(f'queue {q.name}: {len(jobs)} job(s) over '
              f'{len(args.runner)} runner(s): '
              f'{"; ".join(args.runner)}')
        for i, j in enumerate(jobs, 1):
            note = f'  # {j.note}' if j.note else ''
            missing = '' if os.path.isfile(j.path) else '  [MISSING PRESET]'
            print(f'{i:3d}. {j.key:45s} {j.preset_rel}{note}{missing}')
        if any(s.strip() == 'testing-farm' for s in args.runner):
            from .testingfarm import build_tf_request
            if not tf_cfg.get('token'):
                print('(testing-farm: no token configured; the request '
                      'JSON below is what would be submitted)')
            srpm = getattr(args, 'srpm', None)
            for j in jobs:
                print(f'\n== testing-farm request for {j.key} ==')
                print(json.dumps(
                    build_tf_request(tf_cfg, j, args.job_timeout,
                                     srpm=srpm),
                    indent=2))
        return 0
    outdir = args.outdir or os.path.join(os.getcwd(), f'{q.name}.queue')
    try:
        runners = [make_runner(s, ssh_key=args.ssh_key, tf_cfg=tf_cfg)
                   for s in args.runner]
    except RunnerTransportError as e:
        print(f'error: {e}', file=sys.stderr)
        return 2
    srpm = getattr(args, 'srpm', None)
    has_tf = any(s.strip() == 'testing-farm' for s in args.runner)
    if srpm and not has_tf and not os.path.exists(srpm):
        print(f'error: --srpm path does not exist: {srpm}', file=sys.stderr)
        return 2
    srpm_dir = getattr(args, 'srpm_dir', None) or os.path.join(
        os.path.dirname(args.remote_ci.rstrip('/')), 'srpm')
    sup = Supervisor(q, runners, outdir, job_timeout=args.job_timeout,
                     keep_on_failure=args.keep_on_failure,
                     remote_ci=args.remote_ci, jobs_dir=args.jobs_dir,
                     bootstrap=not args.no_bootstrap, srpm=srpm,
                     srpm_dir=srpm_dir,
                     image_timeout=getattr(args, 'image_timeout', 9000))
    try:
        return sup.run()
    except SupervisorError as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


def _git_value(args, fallback=None):
    """git plumbing value for the current checkout (best effort)."""
    import subprocess
    try:
        p = subprocess.run(['git'] + args, capture_output=True, text=True,
                           timeout=10)
        return p.stdout.strip() or fallback
    except (OSError, subprocess.TimeoutExpired):
        return fallback


def _tf_config(args):
    """The TF cfg dict for `queue run` ({} when no TF runner is requested;
    None after printing an error)."""
    if not any(s.strip() == 'testing-farm' for s in args.runner):
        return {}
    token = getattr(args, 'tf_token', None) or \
        os.environ.get('TESTING_FARM_API_TOKEN')
    if not token:
        print('error: testing-farm runner: no API token (pass --tf-token '
              'or set TESTING_FARM_API_TOKEN)', file=sys.stderr)
        return None
    repo_url = getattr(args, 'tf_repo_url', None) or \
        _git_value(['config', 'remote.origin.url'])
    if not repo_url:
        print('error: testing-farm runner: no repo URL (pass '
              '--tf-repo-url; this checkout has no origin remote)',
              file=sys.stderr)
        return None
    cfg = {
        'token': token,
        'url': getattr(args, 'tf_url', None),
        'repo_url': repo_url,
        'ref': getattr(args, 'tf_ref', None) or
        _git_value(['rev-parse', 'HEAD']) or 'HEAD',
        'arch': getattr(args, 'tf_arch', None),
        'compose': getattr(args, 'tf_compose', None),
        'plan': getattr(args, 'tf_plan', None),
    }
    for kv in getattr(args, 'tf_variable', []):
        k, _, v = kv.partition('=')
        if not k:
            print(f'error: --tf-variable needs KEY=VALUE: {kv!r}',
                  file=sys.stderr)
            return None
        cfg.setdefault('extra_variables', {})[k] = v
    return cfg


def main(argv=None):
    p = argparse.ArgumentParser(
        prog='freeipa-env',
        description='Provision and drive FreeIPA CI environments '
                    '(doc/designs/ci_modernization.md).')
    p.add_argument('--tool', default='podman',
                   help='container tool (default: podman)')
    p.add_argument('--seccomp', default=None,
                   help='path to a seccomp profile json (podman provider)')
    p.add_argument('--strict', action='store_true',
                   help='external provider: fail on unreachable ports')
    sub = p.add_subparsers(dest='cmd', required=True)

    def add_common(sp):
        sp.add_argument('env', help='env.yaml (or preset) path')
        sp.add_argument('--workdir', default=None,
                        help='state/logs dir (default ./<env-name>.env)')
        sp.add_argument('--ssh-key', default=None,
                        help='external provider: private key for root SSH '
                             '(default: ~/.ssh/id_rsa)')

    sp = sub.add_parser('up', help='create (or attach) the environment')
    add_common(sp)
    sp.set_defaults(fn=cmd_up)

    sp = sub.add_parser('down', help='collect logs and tear down')
    add_common(sp)
    sp.set_defaults(fn=cmd_down)

    sp = sub.add_parser('show', help='show environment state')
    add_common(sp)
    sp.set_defaults(fn=cmd_show)

    sp = sub.add_parser(
        'resolve',
        help="resolve the preset's image references to concrete local "
             "images (a provider task; prints '<ref> <concrete> <id>')")
    add_common(sp)
    sp.set_defaults(fn=cmd_resolve)

    sp = sub.add_parser(
        'ensure',
        help="build the preset's channel images from build.srpm on this "
             "host when missing (a provider task; the build-side "
             "counterpart of resolve)")
    add_common(sp)
    sp.add_argument('--build', action='store_true',
                    help='rebuild the channel images even if they are '
                         'already present (else only absent ones are built)')
    sp.set_defaults(fn=cmd_ensure)

    sp = sub.add_parser('run', help='run the test workflow in the env')
    add_common(sp)
    sp.set_defaults(fn=cmd_run)

    sp = sub.add_parser(
        'logs',
        help='categorize and retrieve collected logs for troubleshooting')
    sp.add_argument('env', nargs='?', default=None,
                    help='env.yaml (or preset) path')
    sp.add_argument('--workdir', default=None,
                    help='state/logs dir to analyze (default ./<env-name>.env)')
    sp.add_argument('--ssh-key', default=None,
                    help='external provider: private key for root SSH '
                         '(default: ~/.ssh/id_rsa); used with --refresh')
    sp.add_argument('--list', action='store_true',
                    help='per-category summary (default when no --category)')
    sp.add_argument('--category', action='append', metavar='NAME',
                    help=f'category to print, repeatable; "all" for '
                         f'everything; names: {", ".join(CATEGORY_NAMES)}')
    sp.add_argument('--host', default=None,
                    help='only this host (default: all)')
    sp.add_argument('--pattern', default=None,
                    help='line-match regex, overrides the category default')
    sp.add_argument('--lines', type=int, default=DEFAULT_LINES,
                    help=f'max matched lines per file (default {DEFAULT_LINES})')
    sp.add_argument('--tail', type=int, default=DEFAULT_TAIL,
                         help=f'tail lines to show per file (default {DEFAULT_TAIL}, '
                         f'0 disables)')
    sp.add_argument('--all', action='store_true',
                    help='print whole files unfiltered')
    sp.add_argument('--json', action='store_true',
                    help='machine-readable summary (with --list)')
    sp.add_argument('--refresh', action='store_true',
                    help='re-collect logs from a live environment first')
    sp.set_defaults(fn=cmd_logs)

    sp = sub.add_parser(
        'tf-logs',
        help='fetch a Testing Farm request\'s job artifacts and parse them '
             'like `logs` (no env file needed)')
    sp.add_argument('request_id',
                    help='Testing Farm request id (from a `queue run` '
                         'transcript or tf_list)')
    sp.add_argument('--workdir', default=None,
                    help='where to store the artifacts (default '
                         './tf-<request-id>.env; reuse it to skip the '
                         're-download)')
    sp.add_argument('--tf-token', default=None,
                    help='Testing Farm API token (default: env '
                         'TESTING_FARM_API_TOKEN)')
    sp.add_argument('--tf-url', default=None,
                    help='Testing Farm API base URL '
                         '(default https://api.testing-farm.io)')
    sp.add_argument('--no-consoles', action='store_true',
                    help='do not fetch the per-stage console logs '
                         '(only the job workdir artifacts under logs/)')
    # the same parsing options as `logs`
    sp.add_argument('--list', action='store_true',
                    help='per-category summary (default when no --category)')
    sp.add_argument('--category', action='append', metavar='NAME',
                    help=f'category to print, repeatable; "all" for '
                         f'everything; names: {", ".join(CATEGORY_NAMES)}')
    sp.add_argument('--host', default=None,
                    help='only this host (default: all)')
    sp.add_argument('--pattern', default=None,
                    help='line-match regex, overrides the category default')
    sp.add_argument('--lines', type=int, default=DEFAULT_LINES,
                    help=f'max matched lines per file (default {DEFAULT_LINES})')
    sp.add_argument('--tail', type=int, default=DEFAULT_TAIL,
                    help=f'tail lines to show per file (default {DEFAULT_TAIL}, '
                         f'0 disables)')
    sp.add_argument('--all', action='store_true',
                    help='print whole files unfiltered')
    sp.add_argument('--json', action='store_true',
                    help='machine-readable summary (with --list)')
    sp.set_defaults(fn=cmd_tf_logs)

    sp = sub.add_parser(
        'migrate',
        help='generate presets from a PRCI definition file '
             '(ipatests/prci_definitions/*.yaml)')
    sp.add_argument('definition', help='PRCI definition YAML file')
    sp.add_argument('-o', '--out', default=None,
                    help='output dir (default: presets/prci/<definition>)')
    sp.add_argument('--jobs', action='append', metavar='NAME',
                    help='only migrate jobs whose name contains NAME '
                         '(repeatable)')
    sp.set_defaults(fn=cmd_migrate)

    sp = sub.add_parser(
        'check',
        help='parse + validate preset files without spawning containers '
             '(CI gating)')
    sp.add_argument('paths', nargs='*', default=None,
                    help='preset files or directories '
                         '(default: presets/ under ci/env)')
    sp.set_defaults(fn=cmd_check)

    spq = sub.add_parser(
        'queue', help='ordered preset queues + the queue supervisor')
    qsub = spq.add_subparsers(dest='queue_cmd', required=True)
    qrun = qsub.add_parser(
        'run', help='run a queue on pre-allocated runners '
                    '(ssh + podman + systemd)')
    qrun.add_argument('queue_file', help='queue YAML (ci/queues/*.yaml)')
    qrun.add_argument('--runner', action='append', required=True,
                      metavar='RUNNER',
                      help='runner (repeatable; one job at a time per '
                           'runner, jobs dequeued in queue order). Spec: '
                           'user@host[:port] = ssh runner; "local" = the '
                           'control node (no ssh); "testing-farm" = one TF '
                           'request per job')
    qrun.add_argument('--jobs', action='append', metavar='NAME',
                      help='substring filter on the job key (repeatable)')
    qrun.add_argument('--limit', type=int, default=None,
                      help='run at most N jobs')
    qrun.add_argument('--dry-run', action='store_true',
                      help='print the planned queue (and, for the '
                           'testing-farm runner, the request JSON per job) '
                           'and exit')
    qrun.add_argument('--keep-on-failure', action='store_true',
                      help='skip `down` when a job fails (env stays on the '
                           'runner for triage)')
    qrun.add_argument('--job-timeout', type=int, default=14400,
                      help='per-job remote timeout in seconds '
                           '(default 14400 = 4h)')
    qrun.add_argument('--outdir', default=None,
                      help='local artifacts dir (default ./<queue>.queue)')
    qrun.add_argument('--remote-ci', default='~/freeipa-ci/ci',
                      help='ci/ tree location on each runner; ~ expands '
                           'to the runner user\'s home (default '
                           '~/freeipa-ci/ci)')
    qrun.add_argument('--jobs-dir', default='~/jobs',
                      help='per-job workdir parent on each runner; ~ '
                           'expands to the runner user\'s home (default '
                           '~/jobs)')
    qrun.add_argument('--ssh-key', default=None, help='ssh identity file')
    qrun.add_argument('--no-bootstrap', action='store_true',
                      help='do not sync the ci/ tree to the runners '
                           '(the testing-farm runner always clones the '
                           'repo itself)')
    qrun.add_argument('--srpm', default=None, metavar='PATH',
                      help='SRPM (or its dist/srpms/ dir) produced by '
                           'ci/scripts/make-srpms.sh; shipped to each runner '
                           'and used to build the queue channel images that '
                           'are missing there (design §3.10, "build the '
                           'IPA RPMs ourselves"). With the testing-farm '
                           'runner this must be an HTTP(S) URL: the guest '
                           'downloads it at job time.')
    qrun.add_argument('--srpm-dir', default=None, metavar='PATH',
                      help='remote dir on each runner to ship the SRPM into '
                           '(default: <dirname --remote-ci>/srpm)')
    qrun.add_argument('--image-timeout', type=int, default=9000,
                      help='per-channel-image remote build timeout in '
                           'seconds (default 9000 = 2.5h)')
    # Testing Farm options (only used with --runner testing-farm)
    qrun.add_argument('--tf-token', default=None,
                      help='Testing Farm API token (default: env '
                           'TESTING_FARM_API_TOKEN)')
    qrun.add_argument('--tf-url', default='https://api.testing-farm.io',
                      help='Testing Farm API base URL')
    qrun.add_argument('--tf-repo-url', default=None,
                      help='git URL of this repo for the TF guest to clone '
                           '(default: the origin remote of this checkout)')
    qrun.add_argument('--tf-ref', default=None,
                      help='git ref for the TF guest (default: the HEAD '
                           'commit of this checkout)')
    qrun.add_argument('--tf-arch', default='x86_64',
                      help='TF guest architecture (default x86_64)')
    qrun.add_argument('--tf-compose', default='Fedora-44',
                      help='TF guest OS compose (default Fedora-44)')
    qrun.add_argument('--tf-plan', default='/ci/tmt/plans/freeipa-env',
                      help='tmt plan (node) name under the repo root '
                           '(default /ci/tmt/plans/freeipa-env)')
    qrun.add_argument('--tf-variable', action='append', default=[],
                      metavar='KEY=VALUE',
                      help='extra environment variable for the TF guest '
                           '(repeatable)')
    qrun.set_defaults(fn=cmd_queue)
    qgen = qsub.add_parser(
        'generate', help='generate a queue from a PRCI definition '
                         '(in PRCI job order)')
    qgen.add_argument('definition', help='PRCI definition YAML file')
    qgen.add_argument('-o', '--out', default=None,
                      help='output queue file (default: print to stdout)')
    qgen.set_defaults(fn=cmd_queue)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (PodmanError, ExternalError, EnvSpecError, VMBackendError,
            NestedError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
