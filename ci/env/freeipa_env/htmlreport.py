"""Self-contained HTML job report (results.html).

Renders one offline-viewable results.html from a parsed workdir, reusing the
same LogStore / CATEGORIES / parse_xunit / scan_file machinery the terminal
`logs` command uses, so the report and the terminal view stay in lockstep.

Self-contained by design: all CSS is inlined, there is no CDN, no external
asset, and no JavaScript. Collapsing uses native <details>/<summary>, so the
file works when opened straight from the fetched artifacts directory on a
machine with no network.

It is deliberately coarser than PRCI's pytest-html report (which is
generated in-container at run time with per-test captured stdout): here we
show per-test status + duration from the xunit and the shared per-category
logs. PRCI's per-test captured stdout needs pytest-html running in the image
(not added), and the framework's ``--logfile-dir`` per-test logs are only
collected on local/nested runs and not surfaced by any category.
"""

import datetime
import html
import os
import sys

from .loganalyze import (CATEGORIES, CATEGORY_NAMES, LogStore, parse_xunit,
                         xunit_testcases, load_results, overall_status,
                         scan_file)

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


def _rel(store, path):
    try:
        return os.path.relpath(path, store.workdir)
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
        for cat in CATEGORIES if not cat.xunit)
    cat_names = ', '.join(c.name for c in CATEGORIES if not c.xunit)

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
        '<section><h2>Log categories</h2>'
        '<p class="note">Matched lines per category, collapsed. '
        f'Categories: {_esc(cat_names)}.</p>\n'
        f'{cat_sections}\n</section>\n'
        '<div class="footer">Rendered offline from the collected artifacts '
        '(no network, no external assets). Coarser than PRCI\'s in-image '
        'pytest-html report: per-test status/duration from the xunit plus '
        'shared per-category logs, but no per-test captured stdout (that '
        'needs pytest-html in the image; the framework\'s --logfile-dir '
        'per-test logs are collected on local/nested runs but not surfaced '
        'by any category here).</div>\n'
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
