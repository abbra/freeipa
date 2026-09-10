"""Testing Farm transport for the queue supervisor (runner.py interface).

Runs queue jobs on the public Testing Farm (https://docs.testing-farm.io)
instead of on a pre-allocated ssh runner: each job becomes one TF request;
the provisioned guest (a VM, not our host) checks out the repo and runs the
tmt plan in ``ci/tmt`` (plan name ``freeipa-env``), whose script performs
the same up/run/down flow locally on the guest. No ssh, no root on any
host we control, no pre-allocated machine.

API (std urllib only — no third-party deps beyond PyYAML):

    POST /v0.1/requests          -> {"id": ...}
    GET  /v0.1/requests/<id>     -> {id, state, run:{artifacts}, result:{overall}}
    DELETE /v0.1/requests/<id>   -> cancel

Auth: ``Authorization: Bearer <token>``. Terminal states:
``complete``/``error``/``canceled``/``cancel-requested``; ``result.overall``
is ``passed``/``failed`` (``skipped`` counts as pass, like the TF clients).

SRPM: the guest is a fresh VM with no prebuilt images, so the queue's
``--srpm`` must be an HTTP(S) URL the guest can fetch (it downloads and
builds the channel image itself). A local SRPM path is rejected up front.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

from .runner import Runner, RunnerTransportError

DEFAULT_URL = 'https://api.testing-farm.io'
DEFAULT_COMPOSE = 'Fedora-44'
DEFAULT_ARCH = 'x86_64'
DEFAULT_PLAN = '/ci/tmt/plans/freeipa-env'
DEFAULT_POLL = 30  # seconds between GETs
TERMINAL_STATES = ('complete', 'error', 'canceled', 'cancel-requested')


class TfApiError(Exception):
    """A Testing Farm API call failed (network or non-2xx)."""


class TestingFarmClient:
    """Small stdlib client for the TF request API."""

    def __init__(self, token, url=DEFAULT_URL, timeout=30):
        self.token = token
        self.url = url.rstrip('/')
        self.timeout = timeout

    def _call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path, data=data, method=method,
            headers={'Authorization': f'Bearer {self.token}',
                     'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            detail = e.read().decode('utf-8', 'replace')[:500]
            raise TfApiError(f'{method} {path}: HTTP {e.code}: {detail}')
        except urllib.error.URLError as e:
            raise TfApiError(f'{method} {path}: {e.reason}')
        return json.loads(raw.decode()) if raw else {}

    def submit(self, body):
        """POST a request body; returns the request id."""
        return self._call('POST', '/v0.1/requests', body)['id']

    def get(self, request_id):
        return self._call('GET', f'/v0.1/requests/{request_id}')

    def cancel(self, request_id):
        self._call('DELETE', f'/v0.1/requests/{request_id}')

    def wait(self, request_id, deadline, interval=DEFAULT_POLL, log=None):
        """Poll until a terminal state or the deadline.

        Returns (state, overall, artifacts_url). ``log(line)`` receives one
        line per poll (the runner threads these into the job transcript).
        """
        while True:
            req = self.get(request_id)
            state = req.get('state') or '?'
            line = (f'== tf: state {state} '
                    f'(overall {(req.get("result") or {}).get("overall", "-")})')
            if log:
                log(line)
            if state in TERMINAL_STATES:
                return state, (req.get('result') or {}).get('overall'), \
                    (req.get('run') or {}).get('artifacts')
            if time.monotonic() >= deadline:
                return None, None, (req.get('run') or {}).get('artifacts')
            time.sleep(interval)


# --- artifacts -----------------------------------------------------------

_DATA_DIR_RE = re.compile(r'/ci/tmt/tests/freeipa-env-\d+/data/?$')


def data_dir(url):
    """True when ``url`` points at a tmt test data dir (…/freeipa-env-N/data).
    ``results.xml`` links both the data dir and its parent dir with
    trailing slashes, and every file under the dir as a file URL; only the
    file URLs are fetchable artifacts."""
    return bool(_DATA_DIR_RE.search((url or '').rstrip('/')))


def fetch_artifacts(request_id, workdir, token, url=DEFAULT_URL,
                    timeout=120, log=None, include_consoles=True):
    """Download a finished TF request's job artifacts into ``workdir`` in the
    local freeipa-env workdir layout (``workdir/logs/…``) so
    ``freeipa-env logs`` can parse them like a local/ssh job.

    The guest copies its job workdir's ``logs/`` tree into the tmt test data
    dir as ``artifacts/`` (see tf-runner.sh), and Testing Farm lists every
    uploaded file in the request's ``results.xml`` — so the file set (and the
    unpredictable ``work-…`` dir prefix) is read straight from the XML. Each
    ``…/data/artifacts/<rel>`` file is fetched to ``workdir/logs/<rel>``;
    the per-stage console logs are fetched to ``workdir/stages/`` (opt-out
    via ``include_consoles``). Returns the count of files written.
    """
    client = TestingFarmClient(token, url=url, timeout=timeout)
    req = client.get(request_id)
    xunit = (req.get('result') or {}).get('xunit_url')
    if not xunit:
        raise TfApiError(
            f'request {request_id}: no results.xml yet (state '
            f'{req.get("state") or "?"})')
    with urllib.request.urlopen(xunit, timeout=timeout) as r:
        xml = r.read().decode('utf-8', 'replace')
    hrefs = re.findall(r'href="([^"]+)"', xml)

    # results.xml lists some file hrefs more than once (the main results
    # list and the per-stage testcase log links); fetch each URL once.
    seen = set()

    def fetch(u, dest):
        if u in seen:
            return False
        seen.add(u)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with urllib.request.urlopen(u, timeout=timeout) as r, open(dest, 'wb') as f:
            f.write(r.read())
        return True

    n = 0
    for h in hrefs:
        if not h.startswith('http') or data_dir(h):
            continue
        if '/artifacts/' in h:
            rel = h.split('/artifacts/', 1)[1].lstrip('/')
            if not rel:
                continue
            if fetch(h, os.path.join(workdir, 'logs', rel)):
                n += 1
                if log:
                    log(f'  logs/{rel}')
        elif include_consoles and '/freeipa-env-1/data/' in h:
            base = os.path.basename(h.rstrip('/'))
            if base.endswith('.log'):
                if fetch(h, os.path.join(workdir, 'stages', base)):
                    n += 1
                    if log:
                        log(f'  stages/{base}')
    return n


def build_tf_request(cfg, job, timeout_s, srpm=None):
    """The TF request body for one queue job (pure; used by the runner and
    by ``--dry-run``). ``cfg``: repo_url, ref, arch, compose, plan,
    srpm_url, channel, extra_variables, skip_guest_setup. ``srpm`` is an
    explicit HTTP(S) SRPM URL (from ``--srpm``); when set it takes
    precedence over ``cfg['srpm_url']``."""
    variables = {
        'FREEIPA_PRESET': job.preset_rel,
        'FREEIPA_JOB_KEY': job.key,
        # the guest runs as its own root; keep the historical layout via ~
        'FREEIPA_WORKDIR': f'~/freeipa-jobs/{job.key}',
        'FREEIPA_JOB_TIMEOUT': str(timeout_s),
        # gluetool syncs the fmf tree to the guest as a plain file copy
        # (no .git, no submodule contents), so the guest clones the repo
        # itself for the on-guest SRPM build (see tf-runner.sh)
        'FREEIPA_REPO_URL': cfg['repo_url'],
        'FREEIPA_REPO_REF': cfg.get('ref') or 'HEAD',
    }
    if srpm:
        variables['FREEIPA_SRPM_URL'] = srpm
    if cfg.get('srpm_url'):
        variables['FREEIPA_SRPM_URL'] = cfg['srpm_url']
    if cfg.get('channel'):
        variables['FREEIPA_CHANNEL'] = cfg['channel']
    for k, v in (cfg.get('extra_variables') or {}).items():
        variables[str(k)] = str(v)
    env = {
        'arch': cfg.get('arch') or DEFAULT_ARCH,
        'os': {'compose': cfg.get('compose') or DEFAULT_COMPOSE},
        'variables': variables,
        'settings': {'pipeline': {'skip_guest_setup': True}},
    }
    body = {
        'test': {
            'fmf': {
                'url': cfg['repo_url'],
                'ref': cfg.get('ref') or 'HEAD',
                'path': '.',
                'name': cfg.get('plan') or DEFAULT_PLAN,
            },
        },
        'environments': [env],
    }
    return body


class TestingFarmRunner(Runner):
    """Queue runner backed by Testing Farm requests (one per job)."""
    kind = 'testing-farm'

    def __init__(self, cfg):
        cfg = dict(cfg or {})
        token = cfg.get('token') or ''
        if not token:
            raise RunnerTransportError(
                'testing-farm runner: no API token (set TESTING_FARM_API_TOKEN '
                'or pass --tf-token)')
        super().__init__('testing-farm')
        self.cfg = cfg
        self.client = TestingFarmClient(
            token, url=cfg.get('url') or DEFAULT_URL,
            timeout=cfg.get('api_timeout') or 30)
        self._request_id = None

    # -- interface ------------------------------------------------------
    def check(self):
        # No cheap API probe; the token's presence is the configuration
        # precondition (repo allowlisting is validated by the API at
        # submit time, which surfaces as a clear TFApiError).
        return (f'Testing Farm API {self.client.url} (plan '
                f'{self.cfg.get("plan") or DEFAULT_PLAN}, compose '
                f'{self.cfg.get("compose") or DEFAULT_COMPOSE})')

    def bootstrap(self, remote_ci):
        # TF clones the repo itself (test.fmf.url/ref) — nothing to sync.
        pass

    def ship_file(self, local, remote_dir):
        if local.startswith(('http://', 'https://')):
            self.cfg['srpm_url'] = local
        else:
            raise RunnerTransportError(
                'testing-farm runner: the guest is a fresh VM with no '
                'prebuilt images, so --srpm must be an HTTP(S) URL the '
                'guest can fetch (publish the SRPM somewhere reachable '
                'and pass that URL)')

    def resolve_images(self, remote_ci, preset_rels, timeout=600):
        # The guest resolves/builds its images at job time (the tmt test
        # script runs build.sh when FREEIPA_SRPM_URL is set).
        return 0, ''

    def build_channels(self, srpm, srpm_dir, channels, remote_ci,
                       image_timeout, log=None):
        # The TF guest builds its own channel images at job time.
        pass

    def make_step(self, remote_ci, jobs_dir, timeout_s, keep_on_failure):
        # The recipe's up/run/down steps are meaningless for TF: the whole
        # job is one request. run_job() is overridden instead; this just
        # satisfies the shared interface.
        raise RunnerTransportError('testing-farm runner: job steps run guest-side')

    def run_job(self, job, remote_ci, jobs_dir, timeout_s, keep_on_failure):
        body = build_tf_request(self.cfg, job, timeout_s)
        lines = []
        t0 = time.monotonic()
        wd = (jobs_dir or '~/.freeipa-jobs') + '/' + job.key
        result = {'job': job, 'runner': self.spec, 'status': 'FAIL',
                  'duration': 0.0, 'workdir': wd,
                  'up_rc': None, 'run_rc': None, 'down_rc': None,
                  'lines': lines, 'artifacts': None,
                  'tf_request': body}
        try:
            rid = self.client.submit(body)
        except TfApiError as e:
            lines.append(f'== tf: submit failed: {e}')
            result['duration'] = time.monotonic() - t0
            return result
        self._request_id = rid
        lines.append(f'== tf: request {rid} submitted '
                     f'({self.client.url})')
        deadline = t0 + timeout_s
        try:
            state, overall, artifacts = self.client.wait(
                rid, deadline, interval=self.cfg.get('poll_interval',
                                                     DEFAULT_POLL),
                log=lambda l: lines.append(l))
        except TfApiError as e:
            lines.append(f'== tf: poll failed: {e}')
            state, overall, artifacts = None, None, None
        finally:
            self._request_id = None
        result['duration'] = time.monotonic() - t0
        if artifacts:
            result['artifacts'] = artifacts
            lines.append(f'== tf: artifacts: {artifacts}')
        if state == 'error':
            result['run_rc'] = 2
        elif state in ('canceled', 'cancel-requested'):
            result['run_rc'] = 3
        elif state == 'complete':
            result['run_rc'] = 0 if overall in ('passed', 'skipped') else 1
        else:  # deadline reached (state None) or poll died
            lines.append(f'== tf: job timeout {timeout_s}s reached; '
                         'canceling the request')
            try:
                self.client.cancel(rid)
            except TfApiError as e:
                lines.append(f'== tf: cancel failed: {e}')
            result['run_rc'] = 124
        if result['run_rc'] == 0:
            result['status'] = 'PASS'
        return result

    def cancel(self):
        if self._request_id:
            try:
                self.client.cancel(self._request_id)
            except TfApiError:
                pass
