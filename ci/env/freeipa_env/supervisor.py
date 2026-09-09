"""Queue supervisor: run an ordered preset queue on runners.

A *runner* is a host that can execute jobs (``podman`` + systemd plus a
copy of the repo's ``ci/`` tree). Three transports (runner.py):
``user@host[:port]`` (ssh, pre-allocated), ``local`` (the control node),
and ``testing-farm`` (one TF API request per job; the guest runs the
tmt plan in ``ci/tmt``).

The supervisor:

  1. checks every runner (reachability + podman / API token),
  2. syncs the local ``ci/`` tree to ``--remote-ci`` (default
     ``~/freeipa-ci/ci``, expanded per user; Testing Farm clones the
     repo itself),
  3. when ``--srpm`` is given, ships it to each host runner and builds
     the queue's channel images there from it (freshness model: present
     images are left untouched), or records the SRPM URL for the TF
     guest to download;
  4. asks each host runner's provider to resolve every preset's
     build-channel image references (``freeipa-env resolve``; fail fast,
     and the resolved concrete images are recorded in the summary);
  5. schedules the queue: each runner pulls jobs from the front of the
     list, one at a time. A host job is ``freeipa-env up`` -> ``run`` ->
     ``down`` (down is skipped on failure with ``--keep-on-failure``),
     under a per-job ``timeout``; each job's full output is captured to
     a transcript in the out dir,
  6. writes ``summary.tsv`` / ``summary.md`` and prints a final table.

Remote paths are ``~/...`` by default — no runner is assumed to be root;
for a root ssh user ``~`` is exactly the historical ``/root/...``.

Ordering: with one runner the jobs run exactly in queue order; with N
runners each runner's subsequence preserves queue order (FIFO dequeue) —
the same semantics as a PRCI run queue spread over a pool of VMs.
"""

import os
import shlex
import threading
import time

from .runner import REPO_CI_DIR, RunnerTransportError


class SupervisorError(Exception):
    pass


def _fmt_dur(secs):
    secs = int(secs)
    m, s = divmod(secs, 60)
    h, m = divmod(m, 60)
    return f'{h:d}:{m:02d}:{s:02d}' if h else f'{m:d}:{s:02d}'


class Supervisor:
    def __init__(self, queue, runners, outdir, job_timeout=14400,
                 keep_on_failure=False, remote_ci='~/freeipa-ci/ci',
                 jobs_dir='~/jobs', bootstrap=True, srpm=None,
                 srpm_dir=None, image_timeout=9000):
        self.queue = queue
        self.runners = runners
        self.outdir = outdir
        self.job_timeout = job_timeout
        self.keep_on_failure = keep_on_failure
        self.remote_ci = remote_ci
        self.jobs_dir = jobs_dir
        self.bootstrap = bootstrap
        # build-our-own-RPMs lane (design §3.10): an SRPM produced on the
        # control node (ci/scripts/make-srpms.sh) is shipped to each host
        # runner and used to build the queue's channel images there before
        # any job starts; for the TF runner it is recorded as an HTTP(S)
        # URL the guest downloads.
        self.srpm = srpm
        self.srpm_dir = srpm_dir
        self.image_timeout = image_timeout
        self._lock = threading.Lock()
        self._results = []
        self._logf = None

    # -- logging ------------------------------------------------------
    def _log(self, msg):
        line = f'== [{time.strftime("%H:%M:%S")}] {msg}'
        print(line, flush=True)
        with self._lock:
            if self._logf:
                self._logf.write(line + '\n')
                self._logf.flush()

    # -- setup --------------------------------------------------------
    def _validate_presets(self):
        """Parse every preset in the queue up front (fail fast on a bad
        file or spec); image references are resolved later, on the
        runners, by the provider."""
        from .envspec import EnvSpec, EnvSpecError
        for job in self.queue.jobs:
            if not os.path.isfile(job.path):
                raise SupervisorError(
                    f'preset not found: {job.path} '
                    f'(queue {self.queue.path})')
            try:
                EnvSpec.from_file(job.path)
            except EnvSpecError as e:
                raise SupervisorError(f'{job.preset_rel}: {e}')

    @staticmethod
    def _parse_resolve(out):
        """Parse '<ref> <concrete> <id>' lines -> {ref: (concrete, id)} (dedup)."""
        by_ref = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('== '):
                continue
            parts = line.split()
            if len(parts) == 3:
                by_ref.setdefault(parts[0], (parts[1], parts[2]))
        return by_ref

    def setup(self):
        self._validate_presets()
        os.makedirs(os.path.join(self.outdir, 'transcripts'), exist_ok=True)
        self._logf = open(os.path.join(self.outdir, 'queue.log'), 'a')
        self._log(f'queue {self.queue.name}: {len(self.queue.jobs)} job(s), '
                  f'{len(self.runners)} runner(s): '
                  f'{", ".join(r.spec for r in self.runners)}')
        for r in self.runners:
            self._log(f'[{r.spec}] ok: {r.check()}')
        if self.bootstrap:
            for r in self.runners:
                if r.kind == 'testing-farm':
                    self._log(f'[{r.spec}] bootstrap: not needed (the TF '
                              'pipeline clones the repo itself)')
                    continue
                self._log(f'[{r.spec}] syncing {REPO_CI_DIR}/ -> '
                          f'{self.remote_ci}/')
                r.bootstrap(self.remote_ci)
        if self.srpm:
            for r in self.runners:
                if r.kind == 'testing-farm':
                    r.ship_file(self.srpm, self.srpm_dir)  # records the URL
                    self._log(f'[{r.spec}] SRPM URL recorded for the TF guest')
                    self._log(f'[{r.spec}] channel images: built by the TF '
                              'guest at job time (no prebuild)')
                    continue
                self._ship_srpm(r)
                self._log(f'[{r.spec}] shipped SRPM -> {self.srpm_dir}/')
                r.build_channels(self._remote_srpm(self.srpm_dir),
                                 self.srpm_dir, self._channels_needed(),
                                 self.remote_ci, self.image_timeout,
                                 log=self._runner_log(r))
        # image resolution is a provider task: ask each host runner to
        # resolve every distinct preset's build channels against its local
        # image store (fail fast before any job starts). Channels the SRPM
        # preflight just built now resolve; any still-missing channel fails
        # here. The TF guest resolves at job time instead.
        self._resolve_all()

    def _runner_log(self, r):
        def log(msg):
            self._log(f'[{r.spec}] {msg}')
        return log

    def _resolve_all(self):
        self._resolved = {}
        presets = sorted({j.preset_rel for j in self.queue.jobs})
        for r in self.runners:
            if r.kind == 'testing-farm':
                self._log(f'[{r.spec}] image resolution: deferred to the '
                          'TF guest (job time)')
                continue
            rc, out = r.resolve_images(self.remote_ci, presets)
            if rc != 0:
                headers = [l for l in out.splitlines()
                           if l.startswith('== ')]
                which = headers[-1][3:] if headers else '?'
                err = [l for l in out.splitlines()
                       if l.strip() and not l.startswith('== ')]
                self._log(f'[{r.spec}] IMAGE RESOLUTION FAILED: {which}')
                raise SupervisorError(
                    f'runner {r.spec}: cannot resolve images for '
                    f'{which}: {(err[-1] if err else "").strip()}\n'
                    f'(build the image there first: ci/images/build.sh, '
                    f'or `podman load` a saved tarball)')
            self._resolved[r.spec] = self._parse_resolve(out)
            for ref, (concrete, img_id) in self._resolved[r.spec].items():
                self._log(f'[{r.spec}] image {ref} -> {concrete} '
                          f'({img_id[:12]})')

    # -- build our own RPMs (design §3.10) ----------------------------
    def _channels_needed(self):
        """Distinct abstract channel names referenced by the queue's presets
        (short form: ``current`` / ``next`` / ``previous``); empty if the
        presets only pin explicit image references."""
        from .envspec import EnvSpec
        from .image import channel_name
        names = set()
        for job in self.queue.jobs:
            try:
                spec = EnvSpec.from_file(job.path)
            except Exception:
                continue  # _validate_presets already surfaced bad files
            for h in spec.hosts:
                ref = spec.podman_image(h)
                cname = channel_name(ref)
                if cname:
                    names.add(cname)
        return sorted(names)

    def _remote_srpm(self, srpm_dir):
        """Runner-side path of the shipped SRPM (a file or a dir holding
        one). ``srpm_dir`` may be ``~/...``; the ssh remote shell expands
        it (the local runner does it in its own methods)."""
        base = os.path.basename((self.srpm or '').rstrip('/'))
        if base.endswith('.src.rpm'):
            return f'{srpm_dir}/{base}'
        return srpm_dir

    def _ship_srpm(self, r):
        """Ship the control-node SRPM (file or dir) to the runner."""
        src = self.srpm
        if os.path.isdir(src):
            src += '/'
        r.ship_file(src, self.srpm_dir)

    # -- scheduling ---------------------------------------------------
    def run(self):
        self.setup()
        self._jobs = self.queue.jobs
        self._idx = 0
        threads = [threading.Thread(target=self._worker, args=(r,),
                                    name=r.spec) for r in self.runners]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return self._summary()

    def _worker(self, r):
        while True:
            with self._lock:
                if self._idx >= len(self._jobs):
                    return
                i = self._idx
                self._idx += 1
            job = self._jobs[i]
            self._log(f'[{r.spec}] START {i + 1}/{len(self._jobs)} '
                      f'{job.key} ({job.preset_rel})')
            res = r.run_job(job, self.remote_ci, self.jobs_dir,
                            self.job_timeout, self.keep_on_failure)
            tpath = os.path.join(
                self.outdir, 'transcripts',
                f'{job.key}.{r.spec.replace("@", "_").replace(".", "_")}.log')
            with open(tpath, 'w') as f:
                f.write('\n'.join(res['lines']) + '\n')
            self._log(f'[{r.spec}] {res["status"].upper()} {job.key} in '
                      f'{_fmt_dur(res["duration"])} '
                      f'(workdir {res["workdir"]})')
            with self._lock:
                self._results.append((i, job, r.spec, res))

    # -- reporting ----------------------------------------------------
    def _summary(self):
        self._results.sort(key=lambda x: x[0])
        rows = []
        for i, job, spec, res in self._results:
            rows.append({
                'index': i + 1,
                'job': job.key,
                'preset': job.preset_rel,
                'runner': spec,
                'status': res['status'],
                'duration': _fmt_dur(res['duration']),
                'workdir': res['workdir'],
                'note': job.note or '',
            })
        with open(os.path.join(self.outdir, 'summary.tsv'), 'w') as f:
            f.write('index\tjob\tpreset\trunner\tstatus\tduration\t'
                    'workdir\tnote\n')
            for r in rows:
                f.write('\t'.join(str(r[k]) for k in
                                  ('index', 'job', 'preset', 'runner',
                                   'status', 'duration', 'workdir',
                                   'note')) + '\n')
        n_pass = sum(1 for r in rows if r['status'] == 'PASS')
        n_fail = len(rows) - n_pass
        # drop runners with no resolved images (e.g. nested providers defer
        # resolution to the provisioned VM) so they don't emit empty tables
        resolved = {r: b for r, b in getattr(self, '_resolved', {}).items()
                    if b}
        with open(os.path.join(self.outdir, 'summary.md'), 'w') as f:
            f.write(f'# Queue {self.queue.name}: {n_pass} passed, '
                    f'{n_fail} failed, {len(rows)} total\n\n')
            if resolved:
                f.write('## Resolved images\n\n')
                f.write('Presets name a build channel (never a build); '
                        'each runner\'s provider resolved it against its '
                        'local image store.\n\n')
                for rspec, by_ref in resolved.items():
                    f.write(f'### {rspec}\n\n')
                    f.write('| channel | resolved to | image id |\n')
                    f.write('|---|---|---|\n')
                    for ref, (concrete, img_id) in by_ref.items():
                        f.write(f'| {ref} | {concrete} | `{img_id[:12]}` |\n')
                    f.write('\n')
            f.write('## Jobs\n\n')
            f.write('| # | job | runner | status | duration | workdir |\n')
            f.write('|---|-----|--------|--------|----------|---------|\n')
            for r in rows:
                f.write(f'| {r["index"]} | {r["job"]} | {r["runner"]} | '
                        f'{r["status"]} | {r["duration"]} | '
                        f'`{r["workdir"]}` |\n')
            f.write('\nTranscripts: `' +
                    os.path.join(self.outdir, 'transcripts') +
                    '`; full log: `queue.log`.\n')
        self._log(f'RESULTS: {n_pass} passed, {n_fail} failed '
                  f'(summary: {os.path.join(self.outdir, "summary.md")})')
        return 0 if n_fail == 0 else 1
