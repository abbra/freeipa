"""Log analysis (D1): categorize and retrieve collected CI logs.

Operates on the artifacts `freeipa-env run` / `down` leave in the env
workdir:

    <workdir>/nosetests.xml                          JUnit report
    <workdir>/logs/collect-<host>.journal.log        boot journal
    <workdir>/logs/run.log                           run console
    <workdir>/logs/collected/<host>/<host>-logs.tar.gz  daemon logs
    <workdir>/logs/collected/<host>/ipa-env/         framework tree
                                                     (incl. workflow
                                                     tarballs, per-test logs)

Daemon tarballs are selectively extracted (only the log paths that the
categories need; pki-tomcat backups excluded) into
<workdir>/logs/extracted/<host>/ and cached by mtime+size, so repeated
`logs` calls are cheap and the extraction stays small.

Categories (each carries a default line filter, overridable with
--pattern):

    tests      JUnit: totals + failed tests grouped by module
    run        streamed install/test/uninstall console
    install    ipaserver-install.log
    uninstall  ipaserver-uninstall.log
    ds         389-ds errors log
    httpd      httpd error_log (IPA framework errors, tracebacks)
    kra        KRA instance logs (pki)
    ca         CA instance logs (pki)
    kdc        krb5kdc.log
    samba      /var/log/samba (AD trust)
    dns        BIND runtime logs (/var/named/data)
    ipa        per-operation logs under /var/log/ipa/
    system     boot journal: failed units, OOM, segfaults

The install/uninstall categories also look at the workflow tarballs the
run script snapshots (de-duplicated by content). A --pattern override and
--all (whole files, unfiltered) are available for every file category.
"""

import hashlib
import json
import os
import re
import sys
import tarfile
import xml.etree.ElementTree as ET
from collections import OrderedDict
from collections import deque

DEFAULT_LINES = 30
DEFAULT_TAIL = 5

# paths kept when selectively extracting a daemon tarball
_KEEP_PREFIXES = (
    'var/log/dirsrv/',
    'var/log/httpd/',
    'var/log/ipa',          # the /var/log/ipa/ dir and ipa*-install.log
    'var/log/krb5kdc.log',
    'var/log/pki/pki-tomcat/kra/',
    'var/log/pki/pki-tomcat/ca/',
    'var/log/pki/pki-kra-spawn',
    'var/log/pki/pki-ca-spawn',
    'var/log/samba/',
    'var/named/data/',
    'tmp/',              # the <host>.journal.log captured into the tarball
)
_EXCLUDE_PREFIXES = (
    'var/log/pki/pki-tomcat/backup/',
    'var/log/pki/pki-tomcat/certs/',
)


class Category:
    def __init__(self, name, desc, prefixes=(), filere=None, match='',
                 journal=False, console=False, xunit=False,
                 case_sensitive=True, workflow=False):
        self.name = name
        self.desc = desc
        self.prefixes = prefixes          # coarse relpath prefixes
        self.filere = re.compile(filere) if filere else None
        self.match = re.compile(match,
                                 0 if case_sensitive else re.IGNORECASE)
        self.journal = journal
        self.console = console
        self.xunit = xunit
        # workflow: also (and primarily) search the run-base-tests.sh
        # workflow tarballs, de-duplicating identical snapshots by content
        self.workflow = workflow


CATEGORIES = [
    Category('tests', 'JUnit report: failed/errored tests, grouped by module',
             xunit=True),
    Category('run', 'Run console: streamed install/test/uninstall output',
             console=True,
             match=r'(FAILED|Traceback|exit code|'
                   r'\d+ (passed|failed|error)s? in |no tests ran|'
                   r'failed to|failed!|ERROR:|CRITICAL:|WARNING .*)'),
    Category('install', 'IPA server installer',
             prefixes=('var/log/ipaserver-install.log',),
             filere=r'^var/log/ipaserver-install\.log$',
             match=r' (ERROR|WARNING) ',
             workflow=True),
    Category('uninstall', 'IPA server uninstaller',
             prefixes=('var/log/ipaserver-uninstall.log',),
             filere=r'^var/log/ipaserver-uninstall\.log$',
             match=r' (ERROR|WARNING) ',
             workflow=True),
    Category('ds', 'Directory Server (389-ds) errors',
             prefixes=('var/log/dirsrv/',),
             filere=r'/errors$',
             match=r' - (ERR|CRIT|FATAL) - '),
    Category('httpd', 'HTTPD / IPA framework (error_log)',
             prefixes=('var/log/httpd/',),
             filere=r'error_log$',
             match=r'(ipa: (ERROR|CRITICAL)|Traceback|\[error\]|\[crit\]'
                   r'|\[alert\]|\[emerg\])'),
    Category('kra', 'KRA (pki) instance logs',
             prefixes=('var/log/pki/pki-tomcat/kra/',
                       'var/log/pki/pki-kra-spawn'),
             filere=r'(debug\.[^/]+\.log|selftests\.log|' 
                    r'pki-kra-spawn[^/]+\.log)$',
             match=r'(SEVERE|FATAL|ERROR|Exception)'),
    Category('ca', 'CA (pki) instance logs',
             prefixes=('var/log/pki/pki-tomcat/ca/',
                       'var/log/pki/pki-ca-spawn'),
             filere=r'(debug\.[^/]+\.log|selftests\.log|' 
                    r'pki-ca-spawn[^/]+\.log)$',
             match=r'(SEVERE|FATAL|ERROR|Exception)'),
    Category('kdc', 'KDC (krb5kdc)',
             prefixes=('var/log/krb5kdc.log',),
             filere=r'^var/log/krb5kdc\.log$',
             match=r'\((error|crit|fatal)\)'),
    Category('samba', 'Samba / AD trust',
             prefixes=('var/log/samba/',),
             match=r'(ERROR|FAILED|denied)'),
    Category('dns', 'DNS (BIND)',
             prefixes=('var/named/data/',),
             filere=r'(^|/)named(\.run|_journald)',
             match=r'(error|failed|refused|abandon)',
             case_sensitive=False),
    Category('ipa', 'IPA per-operation logs (/var/log/ipa/)',
             prefixes=('var/log/ipa/',),
             filere=r'\.log$',
             match=r'\t(ERROR|CRITICAL)\t'),
    Category('system', 'Boot journal: failed units, OOM, crashes',
             journal=True,
             match=r'(Failed to |failed with result|OOM|Out of memory'
                   r'|oom-kill|Killed process|segfault|core dumped'
                   r'|Assertion|timed out|watchdog)'),
]

CATEGORY_NAMES = [c.name for c in CATEGORIES]


# ---------------------------------------------------------------------------
# artifact discovery
# ---------------------------------------------------------------------------

class LogStore:
    """Find and (selectively) extract every log source under a workdir."""

    def __init__(self, workdir):
        self.workdir = workdir
        self.logdir = os.path.join(workdir, 'logs')
        self.collected = os.path.join(self.logdir, 'collected')
        self.extractdir = os.path.join(self.logdir, 'extracted')
        self.hosts = []
        if os.path.isdir(self.collected):
            self.hosts = sorted(
                d for d in os.listdir(self.collected)
                if os.path.isdir(os.path.join(self.collected, d)))

    # ---------------------------------------------------------------- sources
    def xunit_paths(self):
        cands = [os.path.join(self.workdir, 'nosetests.xml'),
                 os.path.join(self.logdir, 'nosetests.xml')]
        for h in self.hosts:
            cands.append(os.path.join(self.collected, h, 'ipa-env', 'logs',
                                      'nosetests.xml'))
        cands = [c for c in cands if os.path.isfile(c)]
        return self._dedupe_by_content(cands)

    def journal_paths(self, host):
        """Prefers the journal fetched at collection time; falls back to
        the copy captured inside the daemon tarball."""
        p = os.path.join(self.logdir, f'collect-{host}.journal.log')
        if os.path.isfile(p):
            return [p]
        out = []
        ext = self.extracted_dir(host)
        if ext:
            for q in (os.path.join(ext, 'tmp', f'{host}.journal.log'),
                     os.path.join(ext, f'{host}.journal.log')):
                if os.path.isfile(q):
                    out.append(q)
        return out

    def console_paths(self):
        p = os.path.join(self.logdir, 'run.log')
        return [p] if os.path.isfile(p) else []

    # ------------------------------------------------------------- extraction
    def _extract(self, tarball, dest):
        os.makedirs(dest, exist_ok=True)
        stamp = os.path.join(dest, '.extract-stamp')
        st = os.stat(tarball)
        key = f'{int(st.st_mtime)} {st.st_size}'
        if os.path.isfile(stamp):
            try:
                with open(stamp) as f:
                    if f.read().strip() == key:
                        return
            except OSError:
                pass
        with tarfile.open(tarball, 'r:gz') as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                name = m.name.lstrip('./')
                if name.startswith(_EXCLUDE_PREFIXES):
                    continue
                if not name.startswith(_KEEP_PREFIXES):
                    continue
                try:
                    try:
                        tf.extract(m, dest, filter='data')
                    except TypeError:      # older python without filters
                        tf.extract(m, dest)
                except (tarfile.TarError, OSError, KeyError):
                    pass
        with open(stamp, 'w') as f:
            f.write(key)

    def extracted_dir(self, host):
        """Extracted daemon tarball for the host (or None)."""
        tarball = os.path.join(self.collected, host, f'{host}-logs.tar.gz')
        if not os.path.isfile(tarball):
            return None
        dest = os.path.join(self.extractdir, host)
        try:
            self._extract(tarball, dest)
        except (tarfile.TarError, OSError) as e:
            print(f'warning: could not extract {tarball}: {e}',
                  file=sys.stderr)
            return None
        return dest if os.path.isdir(dest) else None

    def workflow_tarballs(self, host):
        """The run-base-tests.sh workflow tarballs from the ipa-env tree,
        extracted next to the daemon logs."""
        tree = os.path.join(self.collected, host, 'ipa-env')
        found = []
        for root, _dirs, names in os.walk(tree):
            for n in names:
                if n.endswith('.tar.gz'):
                    found.append(os.path.join(root, n))
        for t in sorted(found):
            base = os.path.basename(t)[:-len('.tar.gz')]
            dest = os.path.join(self.extractdir, host, f'wf-{base}')
            try:
                self._extract(t, dest)
            except (tarfile.TarError, OSError):
                continue
        return [os.path.join(self.extractdir, host, f'wf-{os.path.basename(t)[:-7]}')
                for t in found]

    def search_roots(self, cat, host):
        """Directories a category's files are looked up under for a host."""
        roots = []
        ext = self.extracted_dir(host)
        if ext:
            roots.append(ext)
        if cat.workflow:
            roots += self.workflow_tarballs(host)
        return roots

    # --------------------------------------------------------------- selection
    def category_files(self, cat, host):
        """Source files for one host (shared sources like run.log are
        returned as-is; callers use category_sources for the full list)."""
        if cat.xunit:
            return self.xunit_paths()
        if cat.journal:
            return self.journal_paths(host)
        if cat.console:
            return self.console_paths()
        files, seen = [], set()
        for root in self.search_roots(cat, host):
            for base, _dirs, names in os.walk(root):
                for n in names:
                    full = os.path.join(base, n)
                    rel = os.path.relpath(full, root)
                    if not any(rel.startswith(p) for p in cat.prefixes):
                        continue
                    if cat.filere and not cat.filere.search(rel):
                        continue
                    r = os.path.realpath(full)
                    if r in seen:
                        continue
                    seen.add(r)
                    files.append(full)
        if cat.workflow:
            # the daemon tarball and the workflow tarballs hold copies of
            # the same /var/log files; keep one per distinct content
            files = self._dedupe_by_content(files)
        return sorted(files)

    @staticmethod
    def _dedupe_by_content(files):
        by_hash, out = {}, []
        for f in files:
            try:
                with open(f, 'rb') as lf:
                    h = hashlib.md5(lf.read()).hexdigest()
            except OSError:
                h = os.path.realpath(f)
            if h in by_hash:
                continue
            by_hash[h] = f
            out.append(f)
        return out

    def category_sources(self, cat, hosts=None):
        """All source files of a category, de-duplicated."""
        hosts = hosts or self.hosts
        if cat.xunit:
            return self.xunit_paths()
        if cat.console:
            return self.console_paths()
        out, seen = [], set()
        for h in hosts:
            for f in self.category_files(cat, h):
                r = os.path.realpath(f)
                if r in seen:
                    continue
                seen.add(r)
                out.append(f)
        return sorted(out)


# ---------------------------------------------------------------------------
# file / report scanning
# ---------------------------------------------------------------------------

def scan_file(path, pattern, tail_n=8):
    """Return (total_lines, matched_lines, last tail_n lines)."""
    matched, total = [], 0
    tailbuf = deque(maxlen=max(tail_n, 1))
    try:
        with open(path, errors='replace') as f:
            for line in f:
                line = line.rstrip('\n')
                total += 1
                tailbuf.append(line)
                if pattern is None or pattern.search(line):
                    matched.append(line)
    except OSError as e:
        return 0, [f'<unreadable: {e}>'], []
    return total, matched, list(tailbuf)


def parse_xunit(path):
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == 'testsuite' else list(root)
    totals = {'tests': 0, 'failures': 0, 'errors': 0, 'skipped': 0,
              'time': 0.0}
    failures, skipped = [], []
    for s in suites:
        for k in ('tests', 'failures', 'errors', 'skipped'):
            v = s.get(k)
            if v:
                try:
                    totals[k] += int(v)
                except ValueError:
                    pass
        t = s.get('time')
        if t:
            try:
                totals['time'] += float(t)
            except ValueError:
                pass
        for tc in s.iter('testcase'):
            cls = tc.get('classname', '?')
            name = tc.get('name', '?')
            node = tc.find('failure')
            kind = 'failure'
            if node is None:
                node = tc.find('error')
                kind = 'error'
            if node is not None:
                failures.append((cls, name, kind,
                                 node.get('message') or '',
                                 node.text or ''))
            else:
                sk = tc.find('skipped')
                if sk is not None:
                    skipped.append((cls, name, sk.get('message') or ''))
    return totals, failures, skipped


def xunit_testcases(path):
    """Per-test-case records from a JUnit file, in document order.

    Each record: classname, name, file, line, time (float), status
    ('pass' | 'fail' | 'error' | 'skipped'), message, text. Unlike
    parse_xunit (which aggregates totals + failures for the terminal
    summary), this returns one row per test for the HTML report's
    per-test table; it leaves parse_xunit's return shape untouched.
    """
    root = ET.parse(path).getroot()
    out = []
    for tc in root.iter('testcase'):
        node = tc.find('failure')
        status = 'fail' if node is not None else None
        if status is None:
            node = tc.find('error')
            status = 'error' if node is not None else None
        if status is None:
            node = tc.find('skipped')
            status = 'skipped' if node is not None else 'pass'
        t = tc.get('time')
        try:
            dur = float(t) if t else 0.0
        except ValueError:
            dur = 0.0
        out.append({
            'classname': tc.get('classname', '?'),
            'name': tc.get('name', '?'),
            'file': tc.get('file', ''),
            'line': tc.get('line', ''),
            'time': dur,
            'status': status,
            'message': (node.get('message') if node is not None else '') or '',
            'text': (node.text if node is not None else '') or '',
        })
    return out


def load_results(workdir):
    """Per-stage tmt custom results from <workdir>/results.yaml, if present.

    Returns a list of stage dicts (name, result, note, start, end,
    duration, logs) in document order, or None when the file is absent
    (e.g. a local/ssh job that did not record a results.yaml). `note`
    and `logs` are lists of strings; the rest are strings (or '' when
    unset). The top-level `/` entry carries the job's overall result.
    """
    import yaml
    p = os.path.join(workdir, 'results.yaml')
    if not os.path.isfile(p):
        return None
    try:
        with open(p) as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        print(f'warning: could not read {p}: {e}', file=sys.stderr)
        return None
    if not isinstance(data, list):
        return None
    stages = []
    for item in data:
        if not isinstance(item, dict):
            continue

        def aslist(v):
            if v is None:
                return []
            if isinstance(v, (list, tuple)):
                return [str(x) for x in v]
            return [str(v)]

        stages.append({
            'name': item.get('name', ''),
            'result': item.get('result', ''),
            'note': aslist(item.get('note')),
            'start': item.get('start-time', ''),
            'end': item.get('end-time', ''),
            'duration': item.get('duration', ''),
            'logs': aslist(item.get('log')),
        })
    return stages


def overall_status(store, stages):
    """A coarse overall result for the report header.

    Prefers the tmt results when present: the top-level `/` result is
    authoritative, else any stage 'fail'/'warn' dominates. Without a
    results.yaml it falls back on the xunit failure/error counts.
    Returns (status, detail) with status in pass/fail/warn/skip/unknown.
    """
    if stages:
        top = next((s for s in stages if s['name'] == '/'), None)
        if top is not None:
            r = top['result'] or 'unknown'
            return (r, '; '.join(top['note']) or f'tmt result: {r}')
        res = [s['result'] for s in stages]
        if 'fail' in res:
            return 'fail', 'a stage reported result=fail'
        if 'warn' in res:
            return 'warn', 'a stage reported result=warn'
        return 'pass', f'{len(res)} stage(s) recorded, all passed'
    tests = fails = errs = 0
    for xp in store.xunit_paths():
        try:
            t, _f, _s = parse_xunit(xp)
        except (ET.ParseError, OSError):
            continue
        tests += t['tests']
        fails += t['failures']
        errs += t['errors']
    if fails or errs:
        return 'fail', f'{fails} failed / {errs} errored of {tests} tests'
    if tests:
        return 'pass', f'{tests} test(s) passed'
    return 'unknown', 'no results.yaml and no xunit report'

# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _rel(store, path):
    try:
        return os.path.relpath(path, store.workdir)
    except ValueError:
        return path


def _clip(line, n=300):
    return line if len(line) <= n else line[:n] + f'... <{len(line) - n} more>'


def _clip_lines(lines, n=2000):
    """Clip very long files' output to keep terminals sane."""
    if len(lines) <= n:
        return lines, 0
    return lines[:n], len(lines) - n


def render_list(store):
    """`freeipa-env logs` default view: the per-category summary."""
    print(f'workdir: {store.workdir}')
    print(f'hosts:   '
          f'{", ".join(store.hosts) if store.hosts else "(no collected logs)"}')
    xpaths = store.xunit_paths()
    xunit_failures = 0
    for xp in xpaths:
        try:
            t, f, s = parse_xunit(xp)
            xunit_failures += t['failures'] + t['errors']
            print(f'xunit:   {_rel(store, xp)} — {t["tests"]} tests, '
                  f'{t["failures"]} failed, {t["errors"]} errors, '
                  f'{t["skipped"]} skipped in {t["time"]:.1f}s')
        except (ET.ParseError, OSError) as e:
            print(f'xunit:   {_rel(store, xp)} (unreadable: {e})')
    if not store.hosts and not xpaths:
        print('no artifacts found — run `freeipa-env run` (or `down`) first')
        return
    print()
    print(f'{"category":10s} {"sources":>8s} {"matched":>8s}  description')
    print('-' * 72)
    for cat in CATEGORIES:
        sources, matched = 0, 0
        if cat.xunit:
            sources, matched = len(xpaths), xunit_failures
        else:
            for f in store.category_sources(cat):
                sources += 1
                _total, m, _t = scan_file(f, cat.match)
                matched += len(m)
        print(f'{cat.name:10s} {sources:8d} {matched:8d}  {cat.desc}')
    print()
    print('retrieve: freeipa-env logs --category NAME [--pattern REX] '
          '[--lines N] [--tail N] [--all]')
    print(f'categories: {", ".join(CATEGORY_NAMES)}')


def render_json(store):
    data = {'workdir': store.workdir, 'hosts': store.hosts,
            'xunit': [], 'categories': {}}
    for xp in store.xunit_paths():
        try:
            t, f, s = parse_xunit(xp)
            data['xunit'].append({
                'path': _rel(store, xp),
                'tests': t['tests'], 'failures': t['failures'],
                'errors': t['errors'], 'skipped': t['skipped'],
                'time': round(t['time'], 1),
                'failed_tests': [
                    {'class': c, 'name': n}
                    for c, n, _k, _m, _x in f],
            })
        except (ET.ParseError, OSError):
            data['xunit'].append({'path': _rel(store, xp),
                                  'error': 'unreadable'})
    for cat in CATEGORIES:
        matched = 0
        if cat.xunit:
            matched = sum(x.get('failures', 0) + x.get('errors', 0)
                          for x in data['xunit'] if isinstance(x, dict))
        else:
            for f in store.category_sources(cat):
                _total, m, _t = scan_file(f, cat.match)
                matched += len(m)
        data['categories'][cat.name] = {
            'sources': len(store.category_sources(cat)),
            'matched': matched, 'desc': cat.desc}
    print(json.dumps(data, indent=2))


def _show_xunit(store, cat, args):
    for xp in store.category_files(cat, None):
        try:
            totals, failures, skipped = parse_xunit(xp)
        except (ET.ParseError, OSError) as e:
            print(f'{_rel(store, xp)}: unreadable ({e})')
            continue
        print(f'== category: tests — {_rel(store, xp)}')
        print(f'  {totals["tests"]} tests: {totals["failures"]} failed, '
              f'{totals["errors"]} errors, {totals["skipped"]} skipped '
              f'in {totals["time"]:.1f}s')
        if not failures:
            print('  no failures')
            continue
        groups = OrderedDict()
        for cls, name, kind, msg, text in failures:
            groups.setdefault(cls, []).append((name, kind, msg, text))
        print('  failures by module:')
        for cls, items in groups.items():
            print(f'    {cls}: {len(items)}')
        tb = max(4, args.lines // 2)
        print('  details:')
        for cls, items in groups.items():
            print(f'  --- {cls}')
            for name, kind, msg, text in items:
                print(f'    {name} [{kind}]')
                for l in [l for l in msg.splitlines() if l.strip()][:3]:
                    print(f'      {_clip(l)}')
                tlines = [l for l in text.splitlines() if l.strip()]
                for l in tlines[-tb:]:
                    print(f'        {_clip(l)}')


def _show_file(store, path, cat, args, root):
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        rel = _rel(store, path)
    if args.all:
        total, matched, _t = scan_file(path, None)
        shown, more = _clip_lines(matched)
        print(f'  {rel} ({total} lines)')
        for l in shown:
            print(f'    {l}')
        if more:
            print(f'    ... {more} more lines')
        return
    if args.pattern:
        pattern = args.pattern_compiled
    else:
        pattern = cat.match
    total, matched, tail = scan_file(path, pattern, tail_n=max(args.tail, 1))
    if not matched:
        print(f'  {rel}: no matching lines ({total} total)')
        return
    print(f'  {rel}: {len(matched)} matching lines (of {total})')
    shown, more = _clip_lines(matched, args.lines)
    for l in shown:
        print(f'    {_clip(l)}')
    if more:
        print(f'    ... {more} more matching lines '
              f'(raise --lines or use --pattern to narrow, --all to dump)')
    if args.tail:
        print(f'  tail of {rel}:')
        for l in tail[-args.tail:]:
            print(f'    {_clip(l)}')


def _show_file_category(store, cat, args):
    print(f'== category: {cat.name} — {cat.desc}')
    if cat.journal:
        hosts = ([args.host] if args.host and args.host in store.hosts
                 else store.hosts)
        if args.host and args.host not in store.hosts:
            print(f'  unknown host {args.host!r} '
                  f'(available: {", ".join(store.hosts)})')
            return
        for h in hosts:
            files = store.journal_paths(h)
            if not files:
                print(f'host {h}: no journal')
                continue
            print(f'host: {h}')
            for f in files:
                _show_file(store, f, cat, args, store.logdir)
        return
    if cat.console:
        files = store.console_paths()
        if not files:
            print('  no run console (logs/run.log missing)')
            return
        for f in files:
            _show_file(store, f, cat, args, store.logdir)
        return
    hosts = ([args.host] if args.host and args.host in store.hosts
             else store.hosts)
    if args.host and args.host not in store.hosts:
        print(f'  unknown host {args.host!r} '
              f'(available: {", ".join(store.hosts)})')
        return
    for h in hosts:
        files = store.category_files(cat, h)
        if not files:
            print(f'host {h}: no sources')
            continue
        print(f'host: {h}')
        for f in files:
            roots = store.search_roots(cat, h)
            root = next((r for r in roots if f.startswith(r + os.sep)),
                        os.path.dirname(f))
            _show_file(store, f, cat, args, root)


def show_categories(store, catnames, args):
    names = CATEGORY_NAMES
    for name in catnames:
        if name not in names and name != 'all':
            print(f'error: unknown category {name!r} '
                  f'(known: {", ".join(names)})', file=sys.stderr)
            return 1
    for name in catnames:
        cats = ([c for c in CATEGORIES if c.name == name]
                if name != 'all' else CATEGORIES)
        for cat in cats:
            if cat.xunit:
                _show_xunit(store, cat, args)
            else:
                _show_file_category(store, cat, args)
            print()
    return 0
