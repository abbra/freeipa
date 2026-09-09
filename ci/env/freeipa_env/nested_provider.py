"""Nested provider (design doc §3.9): get a VM, run the env in it.

Composes an outer VM backend (``vmbackend.VMBackend`` — the "get a VM"
cloud-API half) with an inner provider (default ``podman`` — the "run the
env in the VM" half).  The inner environment is the *same* EnvSpec with
``provider`` set to the inner type and the ``vm:`` block stripped; the
nested provider materializes it, ships it to the provisioned VM, and
drives the inner provider there by re-invoking ``freeipa-env up/run/down
<inner-spec> --workdir <remote>`` over ssh.  The whole validated podman
flow runs unchanged — just on a VM acquired through the API.

The nested provider runs on the *control node* (a CI machine that has the
cloud API creds + ssh).  ``up`` provisions its own VM(s) and persists the
handles to ``<workdir>/nested-state.json`` so that a later, separate
``freeipa-env down`` invocation knows what to tear down.
"""

import json
import os
import shlex

import yaml

from . import queue
from .vmbackend import (VMHandle, make_backend, rsync_from, rsync_to,
                        ssh_run)


class NestedProvider:
    def __init__(self, spec, workdir, args=None):
        self.spec = spec
        self.workdir = workdir
        self.args = args
        self.backend = make_backend(spec.vm)
        self.inner_type = (spec.inner or 'podman').strip()
        self.logdir = os.path.join(workdir, 'logs')
        self._state_path = os.path.join(workdir, 'nested-state.json')
        self._vms = []

    # ------------------------------------------------------------- vm config
    def _cfg(self, key, default=None):
        return (self.spec.vm or {}).get(key, default)

    def _remote_ci(self):
        return self._cfg('remote_ci', '/root/freeipa-ci/ci')

    def _remote_env(self):
        return os.path.join(self._remote_ci(), 'env')

    def _remote_workdir(self):
        return self._cfg('remote_workdir',
                         f'/root/ciwork/{self.spec.name}')

    # -------------------------------------------------------------- inner spec
    def _inner_doc(self):
        """The inner EnvSpec dict: same spec, inner provider, no vm block."""
        d = {k: v for k, v in self.spec.raw.items()}
        d['provider'] = self.inner_type
        d.pop('vm', None)
        d.pop('inner', None)
        return d

    def _write_inner_file(self):
        os.makedirs(self.workdir, exist_ok=True)
        path = os.path.join(self.workdir, 'inner-env.yaml')
        with open(path, 'w') as f:
            yaml.safe_dump(self._inner_doc(), f, default_flow_style=False,
                           sort_keys=False)
        return path

    # ------------------------------------------------------------------ state
    def _load_state(self):
        if not os.path.exists(self._state_path):
            return None
        with open(self._state_path) as f:
            return json.load(f)

    def _save_state(self, remote_workdir):
        state = {
            'vms': [v.to_dict() for v in self._vms],
            'remote_workdir': remote_workdir,
            'inner': self.inner_type,
            'name': self.spec.name,
        }
        with open(self._state_path, 'w') as f:
            json.dump(state, f, indent=2)

    def _clear_state(self):
        if os.path.exists(self._state_path):
            os.remove(self._state_path)

    def _primary(self):
        return self._vms[0]

    def _inner_abs(self, state):
        return os.path.join(state['remote_workdir'], 'inner-env.yaml')

    def _load_vms(self):
        if self._vms:
            return
        state = self._load_state()
        if not state or not state.get('vms'):
            raise NestedError(
                'no provisioned VMs recorded (did `up` succeed? state file '
                f'{self._state_path} is missing)')
        self._vms = [VMHandle.from_dict(d) for d in state['vms']]
        self._state = state

    # --------------------------------------------------------------- remote op
    def _remote_cmd(self, state, verb):
        env = self._remote_env()
        return (f'cd {shlex.quote(env)} && ./freeipa-env {verb} '
                f'{shlex.quote(self._inner_abs(state))} '
                f'--workdir {shlex.quote(state["remote_workdir"])}')

    def _ssh_stream(self, vm, cmd, logname, timeout=None):
        os.makedirs(self.logdir, exist_ok=True)
        logpath = os.path.join(self.logdir, logname)
        print(f'== vm {vm.target}: {cmd}')
        return ssh_run(vm, cmd, stream=True, log_path=logpath,
                       timeout=timeout)[0]

    # ---------------------------------------------------------------- bootstrap
    def _bootstrap(self, vm):
        """Ship the ci/ tree + inner spec to the VM, ensure the image."""
        local_ci = os.path.dirname(queue.ENVROOT)          # ci/
        remote_ci_parent = os.path.dirname(self._remote_ci())
        print(f'== vm {vm.target}: rsync ci/ tree '
              f'({local_ci} -> {remote_ci_parent})')
        rsync_to(vm, local_ci, remote_ci_parent)
        state_rwd = self._remote_workdir()
        ssh_run(vm, f'mkdir -p {shlex.quote(state_rwd)}', check=True)
        inner_local = os.path.join(self.workdir, 'inner-env.yaml')
        rsync_to(vm, inner_local,
                 os.path.join(state_rwd, 'inner-env.yaml'))
        # ensure the image the inner env needs is present on the VM
        ref = self._cfg('image_ref')
        if ref:
            rc, _ = ssh_run(vm,
                            f'podman image inspect {shlex.quote(ref)} '
                            f'--format {{.Id}}', check=False)
            if rc != 0:
                print(f'== vm {vm.target}: image {ref} missing, pulling')
                ssh_run(vm, f'podman pull {shlex.quote(ref)}',
                        check=True, log_path=os.path.join(
                            self.logdir, 'image-pull.log'))
        print(f'== vm {vm.target}: bootstrap complete')

    # ------------------------------------------------------------------ up/down
    def up(self):
        count = int(self._cfg('count', 1) or 1)
        timeout = int(self._cfg('ready_timeout', 600))
        os.makedirs(self.logdir, exist_ok=True)
        print(f'== nested provider: provisioning {count} VM(s) via '
              f'{self.backend.describe()}')
        self._vms = self.backend.provision(count)
        for v in self._vms:
            self.backend.wait_ready(v, timeout=timeout)
        state_rwd = self._remote_workdir()
        self._save_state(state_rwd)
        inner = self._write_inner_file()
        print(f'== inner spec (provider: {self.inner_type}): {inner}')
        if self.inner_type == 'podman' and count > 1:
            print(f'== note: the podman inner env runs on the first VM; '
                  f'{count - 1} extra VM(s) are provisioned and released '
                  f'with it')
        primary = self._primary()
        self._bootstrap(primary)
        cmd = self._remote_cmd({'remote_workdir': state_rwd}, 'up')
        rc = self._ssh_stream(primary, cmd, 'nested-up.log')
        if rc != 0:
            raise NestedError(
                f'inner `freeipa-env up` failed on {primary.target} '
                f'({rc}); VM(s) left provisioned — run `freeipa-env down` '
                f'to release them (or keep for triage)')
        print(f'== nested environment {self.spec.name} is up on '
              f'{primary.target}')

    def down(self, collect=True):
        self._load_vms()
        state = self._state
        primary = self._primary()
        ok = True
        if collect:
            rc = self._ssh_stream(
                primary, self._remote_cmd(state, 'down'), 'nested-down.log')
            if rc != 0:
                print(f'== inner `freeipa-env down` on {primary.target} '
                      f'failed ({rc}); continuing to release VMs')
                ok = False
            # fetch the remote workdir (logs, xunit, collected) back
            try:
                os.makedirs(self.logdir, exist_ok=True)
                rsync_from(primary, state['remote_workdir'] + '/',
                           self.workdir)
                self._fetch_xunit(state)
            except Exception as e:          # noqa: BLE001
                print(f'== artifact fetch-back failed: {e}')
        for v in self._vms:
            try:
                self.backend.terminate(v)
            except Exception as e:          # noqa: BLE001
                print(f'== terminate {v.target} failed: {e}')
        self._clear_state()
        self._vms = []
        print(f'== nested environment {self.spec.name} torn down')
        if not ok:
            raise NestedError('inner down reported a failure (see above)')

    def _fetch_xunit(self, state):
        # collect the inner env's xunit (if any) to <workdir>/logs/nosetests.xml
        candidates = []
        collected = os.path.join(self.workdir, 'logs', 'collected')
        if os.path.isdir(collected):
            for d in os.listdir(collected):
                p = os.path.join(collected, d, 'nosetests.xml')
                if os.path.isfile(p):
                    candidates.append(p)
        src = max(candidates, key=os.path.getmtime) if candidates else None
        if src:
            dst = os.path.join(self.logdir, 'nosetests.xml')
            import shutil
            shutil.copyfile(src, dst)
            print(f'== xunit: {src} -> {dst}')

    # -------------------------------------------------------------------- run
    def copy_to_controller(self, local, remote):
        # the inner provider (on the VM) does its own copy at run time
        pass

    def run_in_controller(self, cmd, env=None, log='run.log', timeout=None):
        """Drive the inner `freeipa-env run` on the primary VM.

        ``cmd``/``env`` from the CLI are intentionally ignored: the inner
        provider recomputes the identical test selection from the inner
        spec (which mirrors this spec, including any --run override)."""
        self._load_vms()
        state = self._state
        primary = self._primary()
        rc = self._ssh_stream(primary,
                              self._remote_cmd(state, 'run'),
                              'nested-run.log', timeout=timeout)
        return rc

    # ------------------------------------------------------------------- misc
    def resolve_images(self):
        # the VM does not exist yet at resolve time; the inner provider
        # resolves the image on the VM during `up`. Read-only, returns {}.
        print(f'== nested provider: image resolution deferred to the '
              f'provisioned VM at `up` time (backend: '
              f'{self.backend.describe()})')
        return {}

    def collect_logs(self):
        # logs are fetched back by down(); nothing local to collect
        pass

    def show(self):
        if not self._vms:
            state = self._load_state()
            if state and state.get('vms'):
                self._vms = [VMHandle.from_dict(d) for d in state['vms']]
        if not self._vms:
            print('== no nested environment is up')
            return
        for i, v in enumerate(self._vms):
            tag = ' (primary)' if i == 0 else ''
            print(f'vm[{i}] {v.target} id={v.id or "-"}{tag} '
                  f'[{self.backend.describe()}]')
        state = self._load_state()
        if state:
            self._ssh_stream(self._primary(),
                             self._remote_cmd(state, 'show'),
                             'nested-show.log')


class NestedError(Exception):
    pass
