"""Self-contained HTML job report (results.html).

Renders one offline-viewable results.html from a parsed workdir, reusing the
same LogStore / CATEGORIES / parse_xunit / scan_file machinery the terminal
`logs` command uses, so the report and the terminal view stay in lockstep.

Self-contained by design: all CSS is inlined, there is no CDN, no external
asset, and no JavaScript. Collapsing uses native <details>/<summary>, so the
file works when opened straight from the fetched artifacts directory on a
machine with no network.

The Per-test logs section carries, per test nodeid: (1) the pytest
per-test captured output (stdout/stderr + traceback) parsed from the
in-container ``pytest-html`` report (``report.html``; the test image runs
pytest with ``--html=... --self-contained-html`` and the report is collected
alongside the per-test log trees), and (2) links to the actual collected log
files for that test (the real ``var/log/**`` + ``journal``; config copies
excluded). Status is still joined from the xunit. Links are relative to the
report's own directory (``<workdir>/logs``), so they resolve both on the TF
artifact server and after a local ``tf-logs`` fetch. When no ``report.html``
was collected (e.g. an older image without pytest-html) the captured output
degrades to a note and the log links still show.
"""

import datetime
import html
import os
import sys

from .loganalyze import (CATEGORIES, CATEGORY_NAMES, LogStore, parse_xunit,
                         xunit_testcases, load_results, overall_status,
                         scan_file, ptest_status, parse_pytest_html)

# matched-line cap per source file, and per-line character cap, keep the
# generated report bounded even for very noisy runs.
_MATCH_CAP = 200
_LINE_CAP = 2000

_CSS = """
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #5f6368; --line: #e3e6ea;
  --panel: #f7f8fa; --accent: #0b5fff;
  --pass: #0a7d33; --pass-bg: #e5f4ea;
  --fail: #c22f2f; --fail-bg: #fbe9e9;
  --warn: #9a6700; --warn-bg: #fdf3d7;
  --skip: #5f6368;  --skip-bg: #eceff3;
  --info: #0b5fff;  --info-bg: #e8efff;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
  Helvetica, Arial, sans-serif; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 20px 24px 64px; }
h1 { font-size: 22px; margin: 0 0 2px; }
h2 { font-size: 17px; margin: 28px 0 8px; }
.sub { color: var(--muted); font-size: 13px; margin-bottom: 12px; word-break: break-all; }
.meta { color: var(--muted); font-size: 13px; margin-bottom: 6px; }
.meta a { color: var(--accent); text-decoration: none; }
.meta a:hover { text-decoration: underline; }
.badges { display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  margin: 10px 0 4px; }
.badge { display: inline-block; padding: 3px 11px; border-radius: 13px;
  font-size: 13px; font-weight: 600; line-height: 1.4; }
.badge-pass { color: var(--pass); background: var(--pass-bg); }
.badge-fail { color: var(--fail); background: var(--fail-bg); }
.badge-warn { color: var(--warn); background: var(--warn-bg); }
.badge-skip { color: var(--skip); background: var(--skip-bg); }
.badge-info { color: var(--info); background: var(--info-bg); }
.badge-unknown { color: var(--skip); background: var(--skip-bg); }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { font-weight: 600; color: var(--muted); font-size: 12.5px;
  text-transform: uppercase; letter-spacing: .03em; }
tr:last-child td { border-bottom: none; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums;
  white-space: nowrap; }
.mono, code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas,
  "Liberation Mono", monospace; }
code { background: var(--panel); padding: 1px 5px; border-radius: 4px;
  font-size: 12.5px; word-break: break-word; }
pre { margin: 0; padding: 10px 12px; background: var(--panel);
  border: 1px solid var(--line); border-radius: 6px; overflow-x: auto;
  font-size: 12.5px; line-height: 1.45; white-space: pre-wrap;
  word-break: break-word; }
details { border: 1px solid var(--line); border-radius: 8px; margin: 8px 0;
  background: var(--bg); }
details > summary { cursor: pointer; padding: 9px 12px; font-weight: 600;
  list-style: none; display: flex; gap: 10px; align-items: baseline; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "▸"; color: var(--muted);
  font-size: 12px; transition: transform .1s; }
details[open] > summary::before { transform: rotate(90deg); }
details > summary .muted { color: var(--muted); font-weight: 400;
  font-size: 13px; }
details .body { padding: 4px 12px 12px; }
.file { margin: 10px 0; }
.file > .path { font-size: 12.5px; color: var(--muted); margin-bottom: 4px; }
.note { color: var(--muted); font-size: 13px; }
.loglist { margin: 4px 0 0; }
.loglist a { color: var(--accent); text-decoration: none; font-family:
  ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 12.5px; word-break: break-all; }
.loglist a:hover { text-decoration: underline; }
.loglist .sz { color: var(--muted); font-size: 12px; }
.msg { color: var(--fail); font-weight: 600; }
.fail-detail { margin-top: 8px; }
.footer { margin-top: 40px; color: var(--muted); font-size: 12px;
  border-top: 1px solid var(--line); padding-top: 12px; }
"""

_STATUS_CLASS = {
    'pass': 'badge-pass', 'fail': 'badge-fail', 'error': 'badge-fail',
    'warn': 'badge-warn', 'skip': 'badge-skip', 'skipped': 'badge-skip',
    'unknown': 'badge-unknown', 'info': 'badge-info',
}


def _esc(s):
    return html.escape(str(s), quote=True)


def _status_badge(status, label=None):
    cls = _STATUS_CLASS.get(status, 'badge-unknown')
    return (f'<span class="badge {cls}">'
            f'{_esc(label if label is not None else status)}</span>')


def _clip_line(line):
    return line if len(line) <= _LINE_CAP else line[:_LINE_CAP] + '…'


def _human_size(n):
    """Compact byte size for a log-file link (``12 K``, ``1.2 M``)."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ''
    for unit in ('B', 'K', 'M', 'G'):
        if n < 1024.0 or unit == 'G':
            if unit == 'B':
                return f'{int(n)} {unit}'
            return f'{n:.1f} {unit}'
        n /= 1024.0
    return f'{int(n)} B'


def _clip_output(text, head=1200, tail=4000):
    """Bound a possibly very large per-test output block, keeping the head
    (setup/stderr) and the tail (the traceback). Truncation is marked."""
    text = text.replace('\r\n', '\n').rstrip('\n')
    if len(text) <= head + tail:
        return text
    omitted = len(text) - head - tail
    return (text[:head] + '\n…\n'
            f'[… {omitted} characters elided …]\n'
            + text[-tail:])

def _xunit_totals(store):
    """Aggregate xunit totals across (content-deduped) report files."""
    tot = {'tests': 0, 'failures': 0, 'errors': 0, 'skipped': 0, 'time': 0.0}
    for xp in store.xunit_paths():
        try:
            t, _f, _s = parse_xunit(xp)
        except Exception:
            continue
        for k in ('tests', 'failures', 'errors', 'skipped'):
            tot[k] += t[k]
        tot['time'] += t['time']
    return tot


def _xunit_testrows(store):
    """Per-test rows across the report files, de-duplicated by (class, name)."""
    rows, seen = [], set()
    for xp in store.xunit_paths():
        try:
            tcs = xunit_testcases(xp)
        except Exception:
            continue
        for tc in tcs:
            key = (tc['classname'], tc['name'])
            if key in seen:
                continue
            seen.add(key)
            rows.append(tc)
    return rows


def _stages_section(stages):
    if not stages:
        return ('<section><h2>Stages</h2>'
                '<p class="note">No <code>results.yaml</code> in the workdir '
                '(not recorded for this job — local/ssh runs, or a fetch that '
                'predates stage capture).</p></section>')
    rows = []
    for s in stages:
        name = s['name'] or '/'
        # top-level entry is the overall job result
        badge = _status_badge(s['result'] or 'unknown')
        start = s['start'].replace('T', ' ').rstrip('Z').replace('.000000', '')
        rows.append(
            '<tr>'
            f'<td><code>{_esc(name)}</code></td>'
            f'<td>{badge}</td>'
            f'<td class="num">{_esc(s["duration"] or "—")}</td>'
            f'<td class="num">{_esc(start or "—")}</td>'
            f'<td>{_esc(" ; ".join(s["note"]) or "—")}</td>'
            '</tr>')
    return ('<section><h2>Stages</h2><table>'
            '<tr><th>stage</th><th>result</th><th class="num">duration</th>'
            '<th class="num">started</th><th>note</th></tr>'
            + ''.join(rows) + '</table></section>')


def _tests_section(rows):
    if not rows:
        return ('<section><h2>Tests</h2>'
                '<p class="note">No xunit test cases found '
                '(<code>nosetests.xml</code> absent or empty).</p></section>')
    trs = []
    for tc in rows:
        badge = _status_badge(tc['status'])
        loc = f'{_esc(tc["file"])}:{tc["line"]}' if tc['file'] else '—'
        detail = ''
        if tc['status'] in ('fail', 'error', 'skipped'):
            msg = tc['message']
            text = tc['text']
            body = ''
            if msg:
                body += (f'<div class="msg">{_esc(_clip_line(msg))}</div>')
            if text:
                body += ('<div class="fail-detail"><pre>'
                         + _esc(_clip_text_tail(text)) + '</pre></div>')
            if not msg and not text:
                body = '<div class="note">no captured detail</div>'
            detail = (f'<tr><td colspan="4"><div class="fail-detail">'
                      f'{body}</div></td></tr>')
        trs.append(
            f'<tr><td><code>{_esc(tc["classname"])}</code></td>'
            f'<td><code>{_esc(tc["name"])}</code></td>'
            f'<td>{badge}</td>'
            f'<td class="num">{tc["time"]:.3f}s</td></tr>'
            + detail)
    return ('<section><h2>Tests</h2><table>'
            '<tr><th>module</th><th>test</th><th>result</th>'
            '<th class="num">time</th></tr>'
            + ''.join(trs) + '</table></section>')


def _clip_text_tail(text, tail=60):
    """Keep the head and the (longer) tail of a traceback; the tail carries
    the actual assertion/error."""
    lines = [l.rstrip() for l in text.splitlines()]
    if len(lines) <= tail + 2:
        return text
    head = lines[0]
    return head + '\n' + '…\n' + '\n'.join(lines[-tail:])


def _category_section(cat, store):
    """A collapsed <details> with each source file's matched lines."""
    if cat.xunit:
        return ''
    sources = store.category_sources(cat)
    matched_total = 0
    files_html = []
    for f in sources:
        total, matched, _tail = scan_file(f, cat.match)
        matched_total += len(matched)
        rel = _rel(store, f)
        if not matched:
            files_html.append(
                f'<div class="file"><div class="path">{_esc(rel)}</div>'
                f'<div class="note">no matching lines ({total} total)</div>'
                f'</div>')
            continue
        shown = matched[:_MATCH_CAP]
        more = len(matched) - len(shown)
        body = ''.join('<span class="ln">' + _esc(_clip_line(l)) + '\n</span>'
                       for l in shown)
        if more:
            body += f'<span class="note">… {more} more matching lines</span>'
        files_html.append(
            f'<div class="file"><div class="path">{_esc(rel)} '
            f'({len(matched)}/{total} lines)</div>'
            f'<pre>{body}</pre></div>')
    if not sources:
        inner = '<div class="note">no sources found</div>'
    else:
        inner = ''.join(files_html)
    return (
        f'<details><summary>Category: {_esc(cat.name)} '
        f'<span class="muted">{_esc(cat.desc)} — '
        f'{len(sources)} source(s), {matched_total} matched</span></summary>'
        f'<div class="body">{inner}</div></details>')


def _ptest_section(store):
    """Per-test logs: one collapsed block per framework nodeid, carrying
    (1) the pytest per-test captured output (stdout/stderr + traceback)
    parsed from the in-container pytest-html report, and (2) links to the
    collected log files for that test (real ``var/log/**`` + ``journal``,
    config copies excluded). Status is still joined from the xunit."""
    groups = store.ptest_groups()
    if not groups:
        return ('<section><h2>Per-test logs</h2>'
                '<p class="note">No per-test framework logs collected '
                '(this provider does not fetch the controller&#39;s '
                '<code>ipa-env/logs</code> tree, or it was empty).</p></section>')

    # pytest per-test captured output, keyed by the framework's mangled
    # nodeid (the per-test dir name). Only present when the image ran
    # pytest-html and the report was collected.
    logmap = {}
    ph = store.pytest_html_path()
    if ph:
        for nodeid, e in parse_pytest_html(ph).items():
            logmap[nodeid.replace('/', '-').replace('::', '-')] = e

    tcs = []
    for xp in store.xunit_paths():
        try:
            tcs.extend(xunit_testcases(xp))
        except Exception:
            continue

    blocks = []
    for test in sorted(groups):
        status = ptest_status(test, tcs)
        badge = _status_badge(status)
        pe = logmap.get(test)

        # (1) pytest captured output for this nodeid
        out_html = []
        out_html.append('<div class="file"><div class="path">pytest output</div>')
        if pe is not None:
            log = pe.get('log') or ''
            if log and log.strip():
                out_html.append('<pre>' + _esc(_clip_output(log)) + '</pre>')
            else:
                out_html.append('<div class="note">no captured output</div>')
            dur = pe.get('duration')
            res = pe.get('result')
            if dur or res:
                out_html.append(
                    f'<div class="note">pytest: {_esc(res)} · '
                    f'{_esc(dur)}</div>')
        elif ph is None:
            out_html.append(
                '<div class="note">no pytest captured output collected '
                '(the image predates pytest-html; re-run on an updated '
                'image to populate this block)</div>')
        else:
            out_html.append(
                '<div class="note">no per-test captured output for this '
                'entry (setup/teardown phase, or not in the pytest report)'
                '</div>')
        out_html.append('</div>')

        # (2) links to the collected log files, per host/phase
        file_html = out_html
        for e in sorted(groups[test], key=lambda x: (x['host'], x['phase'])):
            phs = f' · {_esc(e["phase"])}' if e['phase'] else ''
            file_html.append(
                f'<div class="file"><div class="path">host '
                f'{_esc(e["host"])}{phs}</div>')
            files = store.ptest_entry_log_files(e)
            if not files:
                file_html.append('<div class="note">no log files</div></div>')
                continue
            file_html.append('<div class="loglist">')
            for f in files:
                href = _rel(store, f)
                label = os.path.relpath(f, e['path'])
                try:
                    size = _human_size(os.path.getsize(f))
                except OSError:
                    size = ''
                sz = f' <span class="sz">{_esc(size)}</span>' if size else ''
                file_html.append(
                    f'<div><a href="{_esc(href)}">{_esc(label)}</a>{sz}</div>')
            file_html.append('</div></div>')

        blocks.append(
            f'<details><summary><code>{_esc(test)}</code> {badge}</summary>'
            f'<div class="body">{"".join(file_html)}</div></details>')
    return ('<section><h2>Per-test logs</h2>'
            '<p class="note">Per test nodeid: the pytest captured output '
            '(stdout/stderr + traceback from the in-image pytest-html '
            'report) and links to the collected log files for that test '
            '(real <code>var/log/**</code> + <code>journal</code>; config '
            'copies excluded). Status is joined from the xunit. Links are '
            'relative to this report&#39;s directory.</p>'
            + ''.join(blocks) + '</section>')


def _rel(store, path):
    """Relative path for a link in the report.

    The report lives in ``<workdir>/logs`` (see ``cli._emit_html``), and the
    log files it links to live under ``<workdir>/logs/...`` (the collected
    tree + the ptest log trees), so the base is the logdir, not the workdir.
    That keeps the identical relative link valid both on the TF artifact
    server and after a local ``tf-logs`` fetch.
    """
    try:
        return os.path.relpath(path, store.logdir)
    except ValueError:
        return path


def build_report(store, meta=None):
    """Build the full self-contained HTML document for a parsed workdir.

    ``meta`` may carry ``request_id`` and ``job_url`` for a header link.
    """
    meta = meta or {}
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S UTC')
    tot = _xunit_totals(store)
    rows = _xunit_testrows(store)
    stages = load_results(store.workdir)
    status, detail = overall_status(store, stages)

    hosts = ', '.join(store.hosts) if store.hosts else '(none collected)'
    badges = [_status_badge(status, detail or status)]
    if tot['tests']:
        badges.append(_status_badge(
            'fail' if (tot['failures'] or tot['errors']) else 'pass',
            f'{tot["tests"]} tests · {tot["failures"]} failed · '
            f'{tot["errors"]} errors · {tot["skipped"]} skipped · '
            f'{tot["time"]:.1f}s'))
    badges.append(_status_badge('info', f'{len(store.hosts)} host(s)'))

    req = ''
    if meta.get('job_url'):
        rid = meta.get('request_id', '')
        req = (f'<div class="meta">request: '
               f'<a href="{_esc(meta["job_url"])}">{_esc(rid)}</a></div>')
    elif meta.get('request_id'):
        req = (f'<div class="meta">request: {_esc(meta["request_id"])}</div>')

    cat_sections = ''.join(
        _category_section(cat, store)
        for cat in CATEGORIES if not cat.xunit and not cat.ptest)
    cat_names = ', '.join(c.name for c in CATEGORIES
                          if not c.xunit and not c.ptest)
    ptest_section = _ptest_section(store)

    title = (f'FreeIPA CI job report — {meta.get("request_id") or "local"}')
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, '
        'initial-scale=1">\n'
        f'<title>{_esc(title)}</title>\n<style>{_CSS}</style>\n</head>\n'
        '<body>\n<div class="wrap">\n'
        '<header>\n'
        '<h1>FreeIPA CI job report</h1>\n'
        f'<div class="sub">workdir: <code>{_esc(store.workdir)}</code></div>\n'
        f'<div class="sub">hosts: {_esc(hosts)} · generated {now}</div>\n'
        f'{req}\n'
        f'<div class="badges">{"".join(badges)}</div>\n'
        '</header>\n'
        f'{_stages_section(stages)}\n'
        f'{_tests_section(rows)}\n'
        f'{ptest_section}\n'
        '<section><h2>Log categories</h2>'
        '<p class="note">Matched lines per category, collapsed. '
        f'Categories: {_esc(cat_names)}.</p>\n'
        f'{cat_sections}\n</section>\n'
        '<div class="footer">Rendered offline from the collected artifacts '
        '(no network, no external assets). Per-test logs: pytest captured '
        'output (stdout/stderr + traceback) from the in-image pytest-html '
        'report, plus links to the collected per-test log files '
        '(real <code>var/log/**</code> + <code>journal</code>); per-test '
        'status/duration from the xunit; shared per-category logs below. '
        'Log-file links are relative to this report&#39;s directory.</div>\n'
        '</div>\n</body>\n</html>\n')


def render_html(store, out_path, meta=None):
    """Write results.html for a parsed workdir; returns the path."""
    doc = build_report(store, meta)
    d = os.path.dirname(os.path.abspath(out_path))
    if d and not os.path.isdir(d):
        os.makedirs(d)
    with open(out_path, 'w') as f:
        f.write(doc)
    return out_path


def render_batch_index(workdir, entries, out_path, meta=None):
    """Write an index page for a batch (multi-preset) TF request.

    A batch request yields one reportable workdir per preset; the parent
    ``results.html`` (default ``<workdir>/results.html``) is an index that
    links to each preset's ``<preset>/logs/results.html`` and shows its
    overall status (from the preset's ``results.yaml``), so the parent is
    not a near-empty single-job report. ``entries`` is a list of
    ``(key, subdir)`` tuples (``key`` is the preset name; ``subdir`` its
    reportable workdir). Self-contained (same inlined CSS, no network).
    Returns the path written.
    """
    meta = meta or {}
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S UTC')
    rows = []
    n_pass = n_fail = n_other = 0
    for key, subdir in entries:
        store = LogStore(subdir)
        status, detail = overall_status(store, load_results(subdir))
        if status in ('pass', 'skip'):
            n_pass += 1
        elif status == 'fail':
            n_fail += 1
        else:
            n_other += 1
        # preset key is '' for a legacy single-job request; that case is not
        # rendered through the index, so a bare label is always a preset name.
        rel = 'results.html' if key == '' else f'{key}/logs/results.html'
        label = key if key else '(top level)'
        rows.append(
            '<tr>'
            f'<td><a href="{_esc(rel)}"><code>{_esc(label)}</code></a></td>'
            f'<td>{_status_badge(status)}</td>'
            f'<td>{_esc(detail)}</td>'
            f'<td class="num">{len(store.hosts)} host(s)</td>'
            '</tr>')
    req = ''
    if meta.get('job_url'):
        rid = meta.get('request_id', '')
        req = (f'<div class="meta">request: '
               f'<a href="{_esc(meta["job_url"])}">{_esc(rid)}</a></div>')
    elif meta.get('request_id'):
        req = (f'<div class="meta">request: {_esc(meta["request_id"])}</div>')
    title = (f'FreeIPA CI batch report — {meta.get("request_id") or "local"}')
    doc = (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, '
        'initial-scale=1">\n'
        f'<title>{_esc(title)}</title>\n<style>{_CSS}</style>\n</head>\n'
        '<body>\n<div class="wrap">\n'
        '<header>\n'
        '<h1>FreeIPA CI batch report</h1>\n'
        f'<div class="sub">workdir: <code>{_esc(workdir)}</code></div>\n'
        f'<div class="sub">generated {now}</div>\n'
        f'{req}\n'
        '<div class="badges">'
        f'{_status_badge("pass", f"{n_pass} passed")}'
        + (f' {_status_badge("fail", f"{n_fail} failed")}' if n_fail else '')
        + (f' {_status_badge("info", f"{n_other} other")}' if n_other else '')
        + f' {_status_badge("info", f"{len(entries)} preset(s)")}'
        '</div>\n'
        '</header>\n'
        '<section><h2>Presets</h2>'
        '<p class="note">One row per preset in the batch request; open a row '
        'for that preset&#39;s full report (stages, tests, per-test logs, '
        'categories).</p>\n'
        '<table>'
        '<tr><th>preset</th><th>result</th><th>detail</th>'
        '<th class="num">hosts</th></tr>'
        + ''.join(rows) + '</table>\n</section>\n'
        '<div class="footer">Rendered offline from the collected artifacts '
        '(no network, no external assets).</div>\n'
        '</div>\n</body>\n</html>\n')
    d = os.path.dirname(os.path.abspath(out_path))
    if d and not os.path.isdir(d):
        os.makedirs(d)
    with open(out_path, 'w') as f:
        f.write(doc)
    return out_path
