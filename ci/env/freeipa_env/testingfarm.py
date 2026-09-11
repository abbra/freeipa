"""Testing Farm transport for the queue supervisor (runner.py interface).

Runs queue jobs on the public Testing Farm (https://docs.testing-farm.io)
instead of on a pre-allocated ssh runner. A runner's whole job subsequence
becomes **one** TF request (M13): the provisioned guest (a VM, not our host)
checks out the repo, builds freeipa's SRPM and the channel images ONCE, and
reuses them across every preset in the batch -- then runs the same
up/run/down flow per preset (the tmt plan ``freeipa-env`` in ``ci/tmt``, whose
script ``tf-runner.sh`` drives one ``tf-job.sh`` child per preset). One
request per subsequence (instead of the old one request per job) is what
makes the prebuilt SRPM/channel image reusable: build once, run N presets.

No ssh, no root on any host we control, no pre-allocated machine.

API (std urllib only -- no third-party deps beyond PyYAML):

    POST /v0.1/requests          -> {"id": ...}
    GET  /v0.1/requests/<id>     -> {id, state, run:{artifacts}, result:{overall}}
    DELETE /v0.1/requests/<id>   -> cancel

Auth: ``Authorization: Bearer <token>``. Terminal states:
``complete``/``error``/``canceled``/``cancel-requested``; ``result.overall``
is ``passed``/``failed`` (``skipped`` counts as pass, like the TF clients).

SRPM: the guest is a fresh VM with no prebuilt images, so the queue's
``--srpm`` must be an HTTP(S) URL the guest can fetch (it downloads and builds
the channel images itself). A local SRPM path is rejected up front.

Per-preset status is NOT taken from the request's single ``overall``: the
guest writes a per-preset tmt ``results.yaml`` (``<key>/results.yaml``), and
the host maps it into each preset's own workdir, so the normal
``freeipa-env report``/``overall_status`` logic grades each preset.
"""

import json
import os
import re
import tarfile
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
        headers = {'Content-Type': 'application/json'}
        if self.token:
            # GETs (request state / artifacts) are public; submit (POST) and
            # cancel (DELETE) are what actually need the token.
            headers['Authorization'] = f'Bearer {self.token}'
        req = urllib.request.Request(
            self.url + path, data=data, method=method, headers=headers)
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

# an artifact href's path after the tmt test data dir (freeipa-env-N/data/):
# the reliable anchor for mapping into the local workdir, immune to the
# artifact-host URL prefix (which also contains the literal "/artifacts/").
_TMT_DATA_RE = re.compile(r'freeipa-env-\d+/data/')


def data_dir(url):
    """True when ``url`` points at a tmt test data dir (…/freeipa-env-N/data).
    ``results.xml`` links both the data dir and its parent dir with
    trailing slashes, and every file under the dir as a file URL; only the
    file URLs are fetchable artifacts."""
    return bool(_DATA_DIR_RE.search((url or '').rstrip('/')))


def _request_hrefs(request_id, token, url=DEFAULT_URL, timeout=120):
    """The file hrefs listed in a finished request's results.xml (deduped,
    http(s) only). Raises TfApiError when the request has no results.xml yet.
    Shared by fetch_artifacts / fetch_batch_artifacts."""
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
    out, seen = [], set()
    for h in hrefs:
        if h.startswith('http') and not data_dir(h) and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _fetch_once(url, dest, timeout, seen):
    """Download ``url`` to ``dest`` once; True when a file was written."""
    if url in seen:
        return False
    seen.add(url)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with urllib.request.urlopen(url, timeout=timeout) as r, open(dest, 'wb') as f:
        f.write(r.read())
    return True

def _extract_tarball(url, dest_dir, timeout, seen, log=None):
    """Download a ``.tar.gz`` href and extract it INTO ``dest_dir`` (so the
    archive's own top-level entries land there), then remove the archive.

    The guest packs its bulky per-host log tree (``logs/collected/``) into a
    single ``collected-logs.tar.gz`` per preset instead of publishing thousands
    of loose files; this restores that tree into ``workdir/<key>/logs/`` so
    ``freeipa-env logs``/``report`` see it exactly as a local job would.
    True when the archive was extracted.
    """
    if url in seen:
        return False
    seen.add(url)
    tmp = dest_dir + '.tmp.tgz'
    os.makedirs(dest_dir, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r, \
                open(tmp, 'wb') as f:
            f.write(r.read())
        with tarfile.open(tmp, 'r:gz') as tf:
            # 'data' filter (3.12+) blocks absolute paths, device nodes and
            # link targets escaping the tree; the guest only packs plain files.
            try:
                tf.extractall(path=dest_dir, filter='data')
            except TypeError:
                tf.extractall(path=dest_dir)
        return True
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def fetch_artifacts(request_id, workdir, token, url=DEFAULT_URL,
                    timeout=120, log=None, include_consoles=True):
    """Download a finished TF request's job artifacts into ``workdir`` in the
    local freeipa-env workdir layout so ``freeipa-env logs``/``report`` can
    parse it like a local/ssh job.

    Handles both layouts transparently:
    * a **batch** request (M13): the guest uploaded per-key subtrees
      (``…/data/artifacts/<key>/…``, ``…/data/<key>/results.yaml``); each is
      mapped to ``workdir/<key>/{logs,results.yaml,stages}`` so every preset
      gets its own reportable workdir (one ``results.html`` per preset).
    * a **legacy** single-job request (pre-batch): ``…/data/artifacts/…`` and
      a single ``…/data/results.yaml`` map straight into ``workdir``.

    Returns a dict ``{key: n_files}`` where ``''`` is the legacy/single job
    (a batch yields one entry per preset key).
    """
    hrefs = _request_hrefs(request_id, token, url, timeout)
    seen = set()
    per_key = {}

    def count(key):
        per_key[key] = per_key.get(key, 0) + 1
        return per_key[key]

    def fetch(u, dest, key):
        if _fetch_once(u, dest, timeout, seen):
            count(key)
            if log:
                log(f'  {os.path.basename(dest)}'
                    + (f' (in {key}/)' if key else ''))
            return True
        return False

    # Map each href by its path after the tmt test data dir. This anchors on
    # the data-dir marker (freeipa-env-N/data/), so the artifact-host URL
    # prefix can never be mistaken for a file or a per-key subdir.
    rels = []
    for h in hrefs:
        m = _TMT_DATA_RE.search(h)
        if not m:
            continue
        rel = h[m.end():]
        if rel:
            rels.append((h, rel))
    # batch keys = the dirs that carry their own <key>/results.yaml (the
    # reliable marker of the batch layout; artifacts/<head>/… alone cannot
    # distinguish batch from legacy, since legacy artifacts/controller/… also
    # has a first segment with more parts after it).
    keys = {rel.split('/')[0] for rel in (r for _h, r in rels)
            if len(rel.split('/')) == 2 and rel.endswith('/results.yaml')}
    batched = bool(keys)

    for h, rel in rels:
        parts = rel.split('/')
        base_name = parts[-1]
        if rel == 'results.yaml':
            fetch(h, os.path.join(workdir, 'results.yaml'), '')
        elif len(parts) == 2 and parts[1] == 'results.yaml' and \
                parts[0] in keys:
            fetch(h, os.path.join(workdir, parts[0], 'results.yaml'), parts[0])
        elif rel.startswith('artifacts/'):
            art = rel[len('artifacts/'):]
            if not art:
                continue
            if batched:
                head, _, rest = art.partition('/')
                if head in keys and rest:
                    if rest.endswith('.tar.gz'):
                        # the packed per-host log tree: extract into the
                        # preset's logs/ (restores logs/collected/…); the
                        # archive's top-level entry is "collected/".
                        if _extract_tarball(h, os.path.join(workdir, head,
                                                            'logs'), timeout,
                                            seen, log):
                            count(head)
                            if log:
                                log(f'  extracted {rest} (in {head}/)')
                    else:
                        fetch(h, os.path.join(workdir, head, 'logs', rest), head)
            else:
                fetch(h, os.path.join(workdir, 'logs', art), '')
        elif include_consoles and base_name.endswith('.log'):
            if len(parts) == 1:
                fetch(h, os.path.join(workdir, 'stages', base_name), '')
            elif len(parts) == 2 and parts[0] in keys:
                fetch(h, os.path.join(workdir, parts[0], 'stages', base_name),
                      parts[0])
    return per_key


def build_tf_request(cfg, jobs, timeout_s, srpm=None, copr=None,
                     copr_ipa=False, ipa_packages=None):
    """The TF request body for a **batch** of queue jobs (pure; used by the
    runner and by ``--dry-run``). One request carries the whole list; the
    guest builds its SRPM/channel images once and runs every preset (see
    tf-runner.sh). ``jobs`` is a list of QueueJob (a single job is fine).
    ``cfg``: repo_url, ref, arch, compose, plan, srpm_url, channel,
    extra_variables, skip_guest_setup. ``srpm`` is an explicit HTTP(S) SRPM
    URL (from ``--srpm``); when set it takes precedence over
    ``cfg['srpm_url']``. ``copr`` is a list of OWNER/PROJECT repos enabled
    on the guest's channel-image bakes (see tf-runner.sh); when set it is
    emitted as the space-joined ``FREEIPA_COPR_REPOS`` request variable."""
    job_list = [
        {'key': j.key, 'preset_rel': j.preset_rel} for j in jobs
    ]
    variables = {
        # the guest runs as its own root; keep the historical layout via ~
        'FREEIPA_WORKDIR_BASE': '~/freeipa-jobs',
        'FREEIPA_JOB_TIMEOUT': str(timeout_s),
        'FREEIPA_JOBS': json.dumps(job_list),
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
    if copr:
        variables['FREEIPA_COPR_REPOS'] = ' '.join(copr)
    if copr_ipa:
        # instead of building the IPA from a shipped SRPM, the guest installs
        # the IPA packages from the enabled COPR repos on its channel image
        # bakes (build.sh --ipa-from-copr); it skips the SRPM download/build
        # stage entirely. ipa_packages overrides the default dnf spec set.
        variables['FREEIPA_IPA_FROM_COPR'] = '1'
        if ipa_packages:
            variables['FREEIPA_IPA_PACKAGES'] = str(ipa_packages)
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
    """Queue runner backed by Testing Farm: ONE request per job subsequence.

    ``run_batch`` submits the runner's whole subsequence as a single TF
    request (build the SRPM/channel images once on the guest, reuse them
    across presets), waits for it, then fetches the per-preset artifacts back
    into per-key workdirs and returns one result dict per job.
    """
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
        # The guest resolves/builds its images at job time (tf-runner.sh
        # builds the SRPM + channel images when needed).
        return 0, ''

    def build_channels(self, srpm, srpm_dir, channels, remote_ci,
                       image_timeout, log=None, copr=None, copr_ipa=False,
                       ipa_packages=None):
        # The TF guest builds its channel images at job time.
        pass

    def make_step(self, remote_ci, jobs_dir, timeout_s, keep_on_failure):
        # The recipe's up/run/down steps are meaningless for TF: the whole
        # subsequence is one request. run_batch() is overridden instead; this
        # just satisfies the shared interface.
        raise RunnerTransportError('testing-farm runner: job steps run guest-side')

    def run_batch(self, jobs, remote_ci, jobs_dir, timeout_s, keep_on_failure):
        """Submit ``jobs`` as ONE TF request, wait, fetch per-preset
        artifacts, and return one result dict per job (same shape as
        ``Runner.run_job``). The request-level state/overall decides only
        request failures (submit/poll error, or a hard guest crash); each
        preset's own status is graded from its fetched ``results.yaml``."""
        body = build_tf_request(self.cfg, jobs, timeout_s,
                                copr=self.cfg.get('copr') or None,
                                copr_ipa=bool(self.cfg.get('copr_ipa')),
                                ipa_packages=self.cfg.get('ipa_packages'))
        base = (jobs_dir or '~/.freeipa-jobs') + '/tf-batch'
        shared = [
            f'== tf: batch of {len(jobs)} job(s): '
            + ', '.join(j.key for j in jobs),
        ]
        t0 = time.monotonic()
        results = [{
            'job': job, 'runner': self.spec, 'status': 'FAIL',
            'duration': 0.0, 'workdir': f'{base}/{job.key}',
            'up_rc': None, 'run_rc': None, 'down_rc': None,
            'lines': shared, 'artifacts': None,
            'tf_request': body,
        } for job in jobs]
        try:
            rid = self.client.submit(body)
        except TfApiError as e:
            shared.append(f'== tf: submit failed: {e}')
            for res in results:
                res['duration'] = time.monotonic() - t0
            return results
        self._request_id = rid
        shared.append(f'== tf: request {rid} submitted '
                      f'({self.client.url})')
        # The guest does a ONE-TIME SRPM + channel-image build (build_buffer)
        # and then runs every preset's up/run/down sequentially in the single
        # test; each preset gets its full per-job budget. So the batch
        # deadline scales with the batch, not with one job (a 2-preset batch
        # on a 4h per-job timeout needs ~10h, not 4h).
        build_buffer = 7200
        batch_deadline = build_buffer + timeout_s * len(jobs)
        deadline = t0 + batch_deadline
        shared.append(f'== tf: batch deadline {batch_deadline}s '
                      f'({build_buffer}s build buffer + '
                      f'{len(jobs)} x {timeout_s}s per job)')
        try:
            state, overall, artifacts = self.client.wait(
                rid, deadline, interval=self.cfg.get('poll_interval',
                                                     DEFAULT_POLL),
                log=shared.append)
        except TfApiError as e:
            shared.append(f'== tf: poll failed: {e}')
            state, overall, artifacts = None, None, None
        finally:
            self._request_id = None
        dur = time.monotonic() - t0
        for res in results:
            res['duration'] = dur
        if artifacts:
            for res in results:
                res['artifacts'] = artifacts
            shared.append(f'== tf: artifacts: {artifacts}')
        # request-level outcome -> run_rc for every preset in the batch
        if state == 'error':
            rc = 2
        elif state in ('canceled', 'cancel-requested'):
            rc = 3
        elif state == 'complete':
            rc = 0 if overall in ('passed', 'skipped') else 1
        else:  # deadline reached (state None) or poll died
            shared.append(f'== tf: batch timeout {batch_deadline}s reached; '
                          'canceling the request')
            try:
                self.client.cancel(rid)
            except TfApiError as e:
                shared.append(f'== tf: cancel failed: {e}')
            rc = 124
        for res in results:
            res['run_rc'] = rc
            if rc == 0:
                res['status'] = 'PASS'
        # fetch per-preset artifacts into per-key workdirs; a preset whose
        # results.yaml says fail (or whose fetch found nothing) is a FAIL.
        if rid and state != 'error':
            try:
                per_key = fetch_artifacts(rid, base, self.client.token,
                                          url=self.client.url,
                                          log=lambda l: shared.append(l))
            except TfApiError as e:
                shared.append(f'== tf: artifact fetch failed: {e}')
            else:
                from .loganalyze import load_results, overall_status
                for res in results:
                    key = res['job'].key
                    rw = res['workdir']
                    rw_local = os.path.expanduser(rw)
                    if per_key.get(key) or \
                            os.path.isfile(os.path.join(rw_local,
                                                        'results.yaml')):
                        stages = load_results(rw_local)
                        if stages:
                            st, _detail = overall_status(None, stages)
                        else:
                            st, _detail = 'fail', 'no results fetched'
                        res['status'] = 'PASS' if st in (
                            'pass', 'skip') else 'FAIL'
                        if res['run_rc'] == 0 and res['status'] == 'FAIL':
                            res['run_rc'] = 1
                    else:
                        res['status'] = 'FAIL'
                        res['run_rc'] = res['run_rc'] or 1
        return results

    def run_job(self, job, remote_ci, jobs_dir, timeout_s, keep_on_failure):
        # A single job is a one-job batch (same one-request code path).
        return self.run_batch([job], remote_ci, jobs_dir, timeout_s,
                              keep_on_failure)[0]

    def cancel(self):
        if self._request_id:
            try:
                self.client.cancel(self._request_id)
            except TfApiError:
                pass
