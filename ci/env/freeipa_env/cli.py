"""freeipa-env CLI: up / run / down / show / logs over an env.yaml.

`logs` (D1) categorizes the collected artifacts and retrieves them per
category for CI issue triage; see loganalyze.py."""

import argparse
import os
import re
import shlex
import sys

from .envspec import EnvSpec, EnvSpecError, RunSpec
from .podman_provider import PodmanProvider, PodmanError
from .external_provider import ExternalProvider, ExternalError
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
        'migrate',
        help='generate presets from a PRCI definition '
             '(ipatests/prci_definitions/*.yaml)')
    sp.add_argument('definition', help='PRCI definition YAML file')
    sp.add_argument('-o', '--out', default=None,
                    help='output dir (default: presets/prci/<definition>)')
    sp.add_argument('--jobs', action='append', metavar='NAME',
                    help='only migrate jobs whose name contains NAME '
                         '(repeatable)')
    sp.set_defaults(fn=cmd_migrate)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (PodmanError, ExternalError, EnvSpecError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
