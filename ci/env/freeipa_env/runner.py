"""Runner transports for the queue supervisor.

A *runner* is a host that can execute a queued job (``podman`` + systemd
plus a copy of the repo's ``ci/`` tree). The supervisor drives every
runner through one small interface::

    check()                          -> description str (SupervisorError)
    bootstrap(remote_ci)             -> sync the local ci/ tree to the runner
    ship_file(local, remote_dir)     -> ship one file (the SRPM) to the runner
    resolve_images(remote_ci, rels, timeout) -> (rc, out)
    run_job(job, remote_ci, jobs_dir, timeout_s, keep_on_failure)
                                       -> result dict (status, rcs, lines)
    cancel()                         -> best-effort teardown (default no-op)

Three transports (mirroring the backend pattern of vmbackend.py):

* ``SshRunner`` (spec ``user@host[:port]``) — a pre-allocated runner
  reached over ssh (key-based or via the ssh agent). No root assumption:
  remote paths are written ``~/...`` (unquoted) so the *remote* shell
  expands them against the ssh user's home — for a root user that is
  exactly the historical ``/root/...`` paths, which keeps old setups
  working unchanged.
* ``LocalRunner`` (spec ``local``) — the control node is the runner: no
  ssh at all. The same job flow (up -> run -> down) runs as local
  subprocesses. ``~/...`` paths are expanded against the local user's
  home. Requires ``podman`` on the control node.
* ``TestingFarmRunner`` (spec ``testing-farm``) — no ssh and no
  pre-allocated host: each job becomes one Testing Farm request (HTTP
  API); the provisioned guest checks out the repo and runs the tmt plan
  in ``ci/tmt`` which performs the identical up/run/down flow there.
  See ``testingfarm.py``.

All transports share the job recipe (``up`` -> ``run`` -> ``down`` under
a per-job ``timeout``; ``down`` is unbounded and must complete) so queue
semantics — and the transcript/summary shapes — are transport-neutral.
"""

import os
import shlex
import shutil
import subprocess
import time

from .queue import ENVROOT

REPO_CI_DIR = os.path.dirname(ENVROOT)  # the ci/ directory


class Runner:
    """Base class; the supervisor only knows this interface."""

    kind = 'abstract'

    def __init__(self, spec):
        self.spec = spec
        self.ssh_key = None

    def check(self):
        raise NotImplementedError

    def bootstrap(self, remote_ci):
        raise NotImplementedError

    def ship_file(self, local, remote_dir):
        raise NotImplementedError

    def resolve_images(self, remote_ci, preset_rels, timeout=600):
        raise NotImplementedError

    def build_channels(self, srpm, srpm_dir, channels, remote_ci,
                       image_timeout, log=None, copr=None, copr_ipa=False,
                       ipa_packages=None):
        raise NotImplementedError

    def make_step(self, remote_ci, jobs_dir, timeout_s, keep_on_failure):
        """A RunnerStep executing job commands on this transport."""
        raise NotImplementedError

    def run_job(self, job, remote_ci, jobs_dir, timeout_s,
                keep_on_failure):
        return _run_job_recipe(self, job, remote_ci, jobs_dir, timeout_s,
                               keep_on_failure)

    def cancel(self):
        """Best-effort teardown of an in-flight job (default no-op)."""

    def _resolve_cmd(self, remote_ci, preset_rels):
        """The standard ``freeipa-env resolve`` loop, as one shell command.
        Output: '== <preset>' header lines then '<ref> <concrete> <id>'."""
        cli = f'{remote_ci}/env/freeipa-env'
        ps = ' '.join(shlex.quote(p) for p in preset_rels)
        return (f'for p in {ps}; do '
                f"printf '== %s\\n' \"$p\" && cd {remote_ci}/env && "
                f'{cli} resolve "$p" || exit 1; done')


class _SubprocessStep:
    """Executes job command strings via subprocess.

    ``base_argv`` prepends argv (the ssh target); ``None`` runs locally.
    """

    def __init__(self, base_argv=None):
        self._base = base_argv or []

    def run(self, cmd, timeout=600):
        argv = self._base + [cmd]
        # With no base argv the command string is a shell pipeline
        # (timeout ... bash -c ...) and must run through a local shell.
        p = subprocess.run(argv if self._base else cmd,
                           shell=not self._base, capture_output=True,
                           text=True, timeout=timeout)
        out = p.stdout or ''
        if p.stderr:
            out += ('\n' if out else '') + p.stderr
        return p.returncode, out


class SshRunner(Runner):
    """A pre-allocated ``user@host[:port]`` reached over ssh."""
    kind = 'ssh'

    def __init__(self, spec, ssh_key=None):
        super().__init__(spec)
        self.ssh_key = ssh_key
        self._base = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
                      '-o', 'ServerAliveInterval=20', '-o', 'ServerAliveCountMax=3']
        if ':' in spec.rsplit('@', 1)[-1]:
            host, _, port = spec.rpartition(':')
            self._base += ['-p', port]
        if ssh_key:
            self._base += ['-i', ssh_key]
        self._base += [spec]

    def ssh(self, cmd, timeout=600):
        """Run a shell command on the runner; returns (rc, combined_out)."""
        return _SubprocessStep(self._base).run(cmd, timeout=timeout)

    def _rsync(self, local, remote):
        args = ['rsync', '-az', '--partial']
        if self.ssh_key:
            args += ['-e', 'ssh -i ' + shlex.quote(self.ssh_key) +
                     ' -o BatchMode=yes -o ConnectTimeout=15']
        args += [local, f'{self.spec}:{remote}']
        p = subprocess.run(args, capture_output=True, text=True)
        if p.returncode != 0:
            raise RunnerTransportError(
                f'runner {self.spec}: rsync failed: {p.stderr.strip()}')

    # -- interface ------------------------------------------------------
    def check(self):
        rc, out = self.ssh(
            "command -v podman >/dev/null 2>&1 && "
            "podman --version | head -1 || { echo 'podman not found'; exit 1; }",
            timeout=45)
        if rc != 0:
            raise RunnerTransportError(f'runner {self.spec}: {out.strip()}')
        return out.strip()

    def bootstrap(self, remote_ci):
        """rsync the local ci/ tree to the runner (``~/...`` expands
        remotely against the ssh user's home)."""
        self._rsync(REPO_CI_DIR + '/', f'{remote_ci}/')

    def ship_file(self, local, remote_dir):
        src = local if not os.path.isdir(local) else local + '/'
        self._rsync(src, remote_dir)

    def resolve_images(self, remote_ci, preset_rels, timeout=600):
        return self.ssh(self._resolve_cmd(remote_ci, preset_rels),
                        timeout=timeout)

    def build_channels(self, srpm, srpm_dir, channels, remote_ci,
                       image_timeout, log=None, copr=None, copr_ipa=False,
                       ipa_packages=None):
        _build_channels_on(self, srpm, srpm_dir, channels, remote_ci,
                           image_timeout, log, copr, copr_ipa=copr_ipa,
                           ipa_packages=ipa_packages)

    def _exec(self, cmd, timeout=600):
        return self.ssh(cmd, timeout=timeout)

    def _path(self, p):
        # keep ~/... unquoted: the remote shell expands it.
        return p

    def make_step(self, remote_ci, jobs_dir, timeout_s, keep_on_failure):
        return _SubprocessStep(self._base)


class LocalRunner(Runner):
    """The control node is the runner: no ssh, subprocesses + local copies.

    Runner-style paths (``~/...``) are expanded against the local user's
    home. Requires ``podman`` on the control node.
    """
    kind = 'local'

    def __init__(self, spec='local', ssh_key=None):
        super().__init__(spec or 'local')

    def _p(self, path):
        return os.path.expanduser(path)

    def _sh(self, cmd, timeout=600):
        return _SubprocessStep().run(cmd, timeout=timeout)

    # -- interface ------------------------------------------------------
    def check(self):
        rc, out = self._sh(
            "command -v podman >/dev/null 2>&1 && "
            "podman --version | head -1 || { echo 'podman not found'; exit 1; }",
            timeout=45)
        if rc != 0:
            raise RunnerTransportError(f'local runner: {out.strip()}')
        return out.strip()

    def bootstrap(self, remote_ci):
        """Copy the local ci/ tree to the runner location (local copy)."""
        dst = self._p(remote_ci)
        try:
            shutil.copytree(REPO_CI_DIR, dst, dirs_exist_ok=True)
        except OSError as e:
            raise RunnerTransportError(
                f'local runner: copy to {dst} failed: {e}')

    def ship_file(self, local, remote_dir):
        dst = self._p(remote_dir)
        try:
            os.makedirs(dst, exist_ok=True)
            if os.path.isdir(local):
                shutil.copytree(local, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(local, dst)
        except OSError as e:
            raise RunnerTransportError(
                f'local runner: copy of {local} failed: {e}')

    def resolve_images(self, remote_ci, preset_rels, timeout=600):
        return self._sh(self._resolve_cmd(self._p(remote_ci), preset_rels),
                        timeout=timeout)

    def build_channels(self, srpm, srpm_dir, channels, remote_ci,
                       image_timeout, log=None, copr=None, copr_ipa=False,
                       ipa_packages=None):
        _build_channels_on(self, self._p(srpm), srpm_dir, channels,
                           remote_ci, image_timeout, log, copr,
                           copr_ipa=copr_ipa, ipa_packages=ipa_packages)

    def _exec(self, cmd, timeout=600):
        return self._sh(cmd, timeout=timeout)

    def _path(self, p):
        # the local shell expands ~/... itself; expand anyway so the
        # transcript shows the concrete path.
        return os.path.expanduser(p)

    def make_step(self, remote_ci, jobs_dir, timeout_s, keep_on_failure):
        return _SubprocessStep()


class RunnerTransportError(Exception):
    """A runner is unreachable, misconfigured, or rejected an operation."""


def _build_channels_on(r, srpm, srpm_dir, channels, remote_ci,
                       image_timeout, log, copr=None, copr_ipa=False,
                       ipa_packages=None):
    """Build the queue's channel images on the runner from the shipped SRPM
    (design §3.10). Freshness model: a channel image already present is left
    untouched; only absent channels are built (bounded by image_timeout).
    The build runs build.sh (compiling the SRPM, or, in copr_ipa mode,
    installing the IPA packages from the enabled COPR repos), exactly as the
    local ``freeipa-env ensure`` path does. Fail fast on error."""
    from .imagemake import build_sh_argv
    if not channels:
        if log:
            log('no build channels in the queue; skipping image build')
        return
    for cname in channels:
        imgref = f'freeipa-ci/full:{cname}'
        rc, out = r._exec(
            f'podman image inspect {shlex.quote(imgref)} '
            '>/dev/null 2>&1 && echo PRESENT || echo ABSENT',
            timeout=60)
        if 'PRESENT' in out:
            if log:
                log(f'channel {cname} image present; leaving untouched')
            continue
        argv = build_sh_argv(srpm, cname, tool='podman', copr=copr,
                             copr_ipa=copr_ipa, ipa_packages=ipa_packages)
        cmd = ('cd ' + r._path(remote_ci) + ' && bash images/build.sh '
               + ' '.join(shlex.quote(a) for a in argv))
        if log:
            if copr_ipa:
                log(f'building channel {cname} image with IPA from '
                    f'COPR repos {" ".join(copr or [])} (may take a while)')
            else:
                log(f'building channel {cname} image from SRPM {srpm} '
                    '(may take a while)')
        full = (f'timeout -k 120 {image_timeout} bash -c '
                + shlex.quote(cmd))
        rc, out = r._exec(full, timeout=image_timeout + 300)
        if rc != 0:
            tail = [l for l in out.splitlines() if l.strip()][-1:]
            raise RunnerTransportError(
                f'channel build failed ({rc}) for channel {cname!r}\n'
                f'{(tail[0] if tail else "").strip()}')
        if log:
            log(f'built channel {cname} (image freeipa-ci/full:{cname})')


def make_runner(spec, ssh_key=None, tf_cfg=None):
    """Build the runner for a spec: ``user@host[:port]`` (ssh, the
    default), ``local`` (the control node), or ``testing-farm`` (one API
    request per job; see ``testingfarm.TestingFarmRunner``)."""
    spec = spec.strip()
    if spec == 'local':
        return LocalRunner(spec)
    if spec == 'testing-farm':
        from .testingfarm import TestingFarmRunner
        return TestingFarmRunner(tf_cfg or {})
    if '@' in spec:
        return SshRunner(spec, ssh_key=ssh_key)
    raise RunnerTransportError(
        f'unknown runner spec {spec!r}: expected user@host[:port] (ssh), '
        f'"local", or "testing-farm"')


def _run_job_recipe(runner, job, remote_ci, jobs_dir, timeout_s,
                    keep_on_failure):
    """The transport-neutral up -> run -> down recipe; returns the result
    dict the supervisor has always produced (``lines`` is the transcript,
    each step logged as its exact command + combined output)."""
    if runner.kind == 'local':
        # local subprocesses need expanded paths; remote (ssh) paths keep
        # their ~/... for the remote shell to expand.
        remote_ci = os.path.expanduser(remote_ci)
        jobs_dir = os.path.expanduser(jobs_dir)
    cli = f'{remote_ci}/env/freeipa-env'
    envfile = f'{remote_ci}/env/{job.preset_rel}'
    wd = f'{jobs_dir}/{job.key}'
    step = runner.make_step(remote_ci, jobs_dir, timeout_s, keep_on_failure)
    lines = []
    t0 = time.monotonic()
    result = {'job': job, 'runner': runner.spec, 'status': 'FAIL',
              'duration': 0.0, 'workdir': wd,
              'up_rc': None, 'run_rc': None, 'down_rc': None}

    def do(action, cmd, timed=True):
        full = (f'timeout -k 120 {timeout_s} bash -c '
                + shlex.quote(cmd)) if timed else cmd
        lines.append(f'== {action}: {full}')
        rc, out = step.run(full, timeout=timeout_s + 300 if timed else 1800)
        lines.append(out)
        return rc

    try:
        result['up_rc'] = do(
            'up', f'cd {remote_ci} && {cli} up {envfile} --workdir {wd}')
        if result['up_rc'] != 0:
            # best-effort cleanup of the partially created environment
            result['down_rc'] = do(
                'down (cleanup after up failure)',
                f'cd {remote_ci} && {cli} down {envfile} --workdir {wd}',
                timed=False)
            result['duration'] = time.monotonic() - t0
            result['lines'] = lines
            return result
        result['run_rc'] = do(
            'run', f'cd {remote_ci} && {cli} run {envfile} --workdir {wd}')
        if keep_on_failure and result['run_rc'] != 0:
            lines.append(f'== down: SKIPPED (--keep-on-failure; workdir {wd} '
                         'left on the runner for triage)')
        else:
            result['down_rc'] = do(
                'down', f'cd {remote_ci} && {cli} down {envfile} --workdir {wd}',
                timed=False)
    except subprocess.TimeoutExpired:
        lines.append(f'== ERROR: job step exceeded {timeout_s}s; '
                     'transcript above, environment possibly left up')
    result['duration'] = time.monotonic() - t0
    result['status'] = 'PASS' if result.get('run_rc') == 0 else 'FAIL'
    result['lines'] = lines
    return result
