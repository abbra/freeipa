"""Queue supervisor: run an ordered preset queue on pre-allocated runners.

A *runner* is a pre-allocated host with ssh + podman + systemd (e.g. one
of the lab VMs), addressed as ``user@host``. The supervisor:

  1. checks every runner (ssh reachability + podman),
  2. rsyncs the local ``ci/`` tree to ``--remote-ci`` (default
     ``/root/freeipa-ci/ci``) on each runner,
  3. verifies every image the queue needs is present on every runner,
  4. schedules the queue: each runner pulls jobs from the front of the
     list, one at a time. A job is ``freeipa-env up`` -> ``run`` ->
     ``down`` (down is skipped on failure with ``--keep-on-failure``),
     under a per-job remote ``timeout``; each job's full output is
     captured to a transcript in the out dir,
  5. writes ``summary.tsv`` / ``summary.md`` and prints a final table.

Ordering: with one runner the jobs run exactly in queue order; with N
runners each runner's subsequence preserves queue order (FIFO dequeue) —
the same semantics as a PRCI run queue spread over a pool of VMs.
"""

import os
import shlex
import subprocess
import threading
import time

from .queue import ENVROOT

REPO_CI_DIR = os.path.dirname(ENVROOT)  # ci/


class SupervisorError(Exception):
    pass


class Runner:
    def __init__(self, spec, ssh_key=None):
        self.spec = spec  # user@host
        self.ssh_key = ssh_key
        self._base = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
                      '-o', 'ServerAliveInterval=20', '-o', 'ServerAliveCountMax=3']
        if ssh_key:
            self._base += ['-i', ssh_key]
        self._base += [spec]

    def ssh(self, cmd, timeout=600):
        """Run a shell command on the runner; returns (rc, combined_out)."""
        p = subprocess.run(self._base + [cmd],
                           capture_output=True, text=True, timeout=timeout)
        out = p.stdout or ''
        if p.stderr:
            out += ('\n' if out else '') + p.stderr
        return p.returncode, out

    def check(self):
        rc, out = self.ssh(
            "command -v podman >/dev/null 2>&1 && "
            "podman --version | head -1 || { echo 'podman not found'; exit 1; }",
            timeout=45)
        if rc != 0:
            raise SupervisorError(f'runner {self.spec}: {out.strip()}')
        return out.strip()

    def bootstrap(self, remote_ci):
        """rsync the local ci/ tree to the runner."""
        args = ['rsync', '-az', '--delete']
        if self.ssh_key:
            args += ['-e', 'ssh -i ' + shlex.quote(self.ssh_key) +
                     ' -o BatchMode=yes -o ConnectTimeout=15']
        args += [REPO_CI_DIR + '/', f'{self.spec}:{remote_ci}/']
        p = subprocess.run(args, capture_output=True, text=True)
        if p.returncode != 0:
            raise SupervisorError(
                f'runner {self.spec}: rsync failed: {p.stderr.strip()}')

    def has_image(self, image):
        rc, _ = self.ssh(f'podman image inspect {shlex.quote(image)} '
                         '>/dev/null 2>&1')
        return rc == 0

    def run_job(self, job, remote_ci, jobs_dir, timeout_s,
                keep_on_failure):
        """up -> run -> down one job on the runner; result['lines'] holds
        the transcript."""
        cli = f'{remote_ci}/env/freeipa-env'
        envfile = f'{remote_ci}/env/{job.preset_rel}'
        wd = f'{jobs_dir}/{job.key}'
        lines = []
        t0 = time.monotonic()
        result = {'job': job, 'runner': self.spec, 'status': 'FAIL',
                  'duration': 0.0, 'workdir': wd,
                  'up_rc': None, 'run_rc': None, 'down_rc': None}

        def step(name, cmd, timed=True):
            full = (f'timeout -k 120 {timeout_s} bash -c '
                    + shlex.quote(cmd)) if timed else cmd
            lines.append(f'== {name}: {full}')
            rc, out = self.ssh(full, timeout=timeout_s + 300)
            lines.append(out)
            return rc

        result['up_rc'] = step(
            'up', f'cd {remote_ci} && {cli} up {envfile} --workdir {wd}')
        if result['up_rc'] != 0:
            # best-effort cleanup of the partially created environment
            result['down_rc'] = step(
                'down (cleanup after up failure)',
                f'cd {remote_ci} && {cli} down {envfile} --workdir {wd}',
                timed=False)
            result['duration'] = time.monotonic() - t0
            result['lines'] = lines
            return result
        result['run_rc'] = step(
            'run', f'cd {remote_ci} && {cli} run {envfile} --workdir {wd}')
        if keep_on_failure and result['run_rc'] != 0:
            lines.append(f'== down: SKIPPED (--keep-on-failure; workdir {wd} '
                         'left on the runner for triage)')
        else:
            result['down_rc'] = step(
                'down', f'cd {remote_ci} && {cli} down {envfile} --workdir {wd}',
                timed=False)
        result['duration'] = time.monotonic() - t0
        result['status'] = 'PASS' if result['run_rc'] == 0 else 'FAIL'
        result['lines'] = lines
        return result


def _fmt_dur(secs):
    secs = int(secs)
    m, s = divmod(secs, 60)
    h, m = divmod(m, 60)
    return f'{h:d}:{m:02d}:{s:02d}' if h else f'{m:d}:{s:02d}'


class Supervisor:
    def __init__(self, queue, runners, outdir, job_timeout=14400,
                 keep_on_failure=False, remote_ci='/root/freeipa-ci/ci',
                 jobs_dir='/root/jobs', bootstrap=True):
        self.queue = queue
        self.runners = runners
        self.outdir = outdir
        self.job_timeout = job_timeout
        self.keep_on_failure = keep_on_failure
        self.remote_ci = remote_ci
        self.jobs_dir = jobs_dir
        self.bootstrap = bootstrap
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
    def _images(self):
        """Images required by the queue (read from the presets)."""
        from .envspec import EnvSpec, EnvSpecError
        imgs = set()
        for job in self.queue.jobs:
            if not os.path.isfile(job.path):
                raise SupervisorError(
                    f'preset not found: {job.path} '
                    f'(queue {self.queue.path})')
            try:
                spec = EnvSpec.from_file(job.path)
            except EnvSpecError as e:
                raise SupervisorError(f'{job.preset_rel}: {e}')
            imgs.add(spec.image)
        return sorted(i for i in imgs if i)

    def setup(self):
        self._images()  # validates every preset up front
        os.makedirs(os.path.join(self.outdir, 'transcripts'), exist_ok=True)
        self._logf = open(os.path.join(self.outdir, 'queue.log'), 'a')
        self._log(f'queue {self.queue.name}: {len(self.queue.jobs)} job(s), '
                  f'{len(self.runners)} runner(s): '
                  f'{", ".join(r.spec for r in self.runners)}')
        for r in self.runners:
            self._log(f'[{r.spec}] ok: {r.check()}')
        if self.bootstrap:
            for r in self.runners:
                self._log(f'[{r.spec}] rsyncing {REPO_CI_DIR}/ -> '
                          f'{r.spec}:{self.remote_ci}/')
                r.bootstrap(self.remote_ci)
        missing = {}
        for img in self._images():
            for r in self.runners:
                if not r.has_image(img):
                    missing.setdefault(r.spec, []).append(img)
        if missing:
            for spec, imgs in missing.items():
                self._log(f'[{spec}] MISSING IMAGE: {", ".join(imgs)}')
            raise SupervisorError(
                'required images missing on one or more runners '
                '(build/pull them there first, e.g. podman pull or '
                '`podman load` of a saved tarball)')

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
        with open(os.path.join(self.outdir, 'summary.md'), 'w') as f:
            f.write(f'# Queue {self.queue.name}: {n_pass} passed, '
                    f'{n_fail} failed, {len(rows)} total\n\n')
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
