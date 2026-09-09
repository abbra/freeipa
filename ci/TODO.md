# CI modernization — implementation TODO

Implementation of `doc/designs/ci_modernization.md`. Validation host:
`root@192.168.122.215` (Fedora 44, podman 5.8.4, 2 vCPU / 4 GB). Target
validation workload: the Azure **BASE_XMLRPC** job (`test_xmlrpc`, ignoring
`test_xmlrpc/test_dns_plugin.py`, 1 master / 0 replicas / 0 clients).

## A. Image pipeline (`ci/images`)

- [x] A1 `base/Dockerfile` — fedora-toolbox:44, systemd as PID 1, sshd,
  firewalld installed-but-masked (design §2: active firewalld REJECTs
  inter-container traffic), resolved masked, multi-user.target,
  STOPSIGNAL RTMIN+3
- [x] A2 `full/Dockerfile` — base + dev-build IPA RPMs, with a repo-pinning
  hook (`PIN_SPECS`) for frozen repo snapshots
- [x] A3 `build.sh` — builds base+full from a directory of RPMs, tags
  `freeipa-ci/full:<dist>-<sha>` (and `<dist>` alias), include/exclude
  filters for the RPM set
- [x] A4 Validation on 192.168.122.215: full image builds and boots to
  systemd `running`

## B. Provisioner (`ci/env`)

- [x] B1 `freeipa_env/envspec.py` — `env.yaml` schema (provider, hosts with
  optional `address` for external attach, resources, run spec)
- [x] B2 `freeipa_env/podman_provider.py` — `up`: dual-stack podman network,
  containers (caps/seccomp/mem from Azure's docker-compose), systemd wait,
  /etc/hosts + hostname + resolv.conf, controller SSH keypair,
  nis-domainname container override, multihost config YAML
- [x] B3 podman `down` (journal + log collection, destroy) and `show`
- [x] B4 `freeipa_env/external_provider.py` — `up` = attach/validate (SSH,
  hostname, dist, IPA state, ports), same config YAML, `down` =
  collect-don't-destroy; `--ssh-key` for operator keys
- [x] B5 `run` base mode: `scripts/run-base-tests.sh` — faithful port of
  `ipatests/azure/scripts/azure-run-base-tests.sh` (install master w/ KRA,
  `ipa-run-tests ... --with-xunit`, uninstall x2, log collection)
- [x] B6 `run` integration mode — exec `ipa-run-tests` in the controller with
  `IPATEST_YAML_CONFIG`
- [x] B7 `presets/base-xmlrpc.yaml` — the Azure BASE_XMLRPC job as a preset
- [x] B8 `freeipa-env` CLI wiring (up/run/down/show) + `ci/env/README.md`

## C. Validation: BASE_XMLRPC on 192.168.122.215

- [x] C1 Build `freeipa-ci/full:44` via `ci/images/build.sh`
- [x] C2 `freeipa-env up presets/base-xmlrpc.yaml`
- [x] C3 `freeipa-env run presets/base-xmlrpc.yaml` — master install
  (DNS+KRA), `test_xmlrpc` run, uninstall x2
- [x] C4 `freeipa-env down` — journal/log artifacts in the workdir
- [x] C5 External provider smoke check on the host itself (attach/validate,
  no destructive ops)
- [x] C6 Record results; correct design doc where reality differs

## D. Log analysis (`freeipa-env logs`, D1)

- [x] D1a `freeipa_env/loganalyze.py` — selective tarball extraction
  (dirsrv, httpd, ipa*, krb5kdc, pki kra/ca, samba, named, in-tarball
  journal; pki-tomcat backups excluded) into `logs/extracted/<host>/`,
  cached by mtime+size; 13 categories with per-category line filters
  (tests/run/install/uninstall/ds/httpd/kra/ca/kdc/samba/dns/ipa/system);
  JUnit parse with failures grouped by module (message + traceback tail);
  workflow-tarball snapshots for install/uninstall de-duplicated by content
- [x] D1b CLI `logs` subcommand: default per-category summary, `--category`
  (repeatable, `all`), `--pattern`, `--lines`, `--tail`, `--all`, `--host`,
  `--json`, `--refresh` (re-collect from a live env)
- [x] D1c `collect_logs` robustness: a failed collection (dead container /
  unreachable host) never clobbers previously collected artifacts (podman
  journal fetch + external tarball now write-on-success only)
- [x] D1d Validated on 192.168.122.215 against the BASE_XMLRPC artifacts of
  build `8f33c1304` (summary + all 13 categories + pattern/json/host/refresh
  paths); docs updated (README, design §3.2/§3.6)

## E. Full Azure-CI recreation (16 jobs, image `44-b1af1d8bb`)

- [x] E1 New RPM set from the fixed tree (`b1af1d8bb`, version
  `4.14.0.dev202609080859+gitb1af1d8bb`): 24 packages including
  `freeipa-server-trust-ad` + `freeipa-client-samba`, built against
  samba 4.24.6 (no version conflict anymore — samba 4.24.6 is the
  current F44 repo state; the 4.24.5 rotation that broke resolution is
  gone from the repos).
- [x] E2 Samba in the image: `full/Dockerfile` installs `python3-samba`
  (server-side bindings for the xmlrpc idrange tests) + `sudo` (client
  sudo job); the IPA trust packages come from the RPM set and pull
  samba 4.24.6 cleanly. No PIN_SPECS needed.
- [x] E3 Presets for all 16 Azure jobs: `presets/base-xmlrpc.yaml`
  (xmlrpc job) + `presets/azure/*.yaml` (15 more: base unit job + the 14
  gating jobs from `gating-fedora.yml`), mirroring Azure host sets, test
  selections, deselects (sudo) and per-role memory limits.
- [x] E4 `cli.py`: `run.args`/`ignore`/`deselect` values are shlex-quoted
  when rendered into the shell-expanding env vars (multi-word pytest `-k`
  expressions survive).
- [x] E5 Image `freeipa-ci/full:44-b1af1d8bb` built + verified in-image
  (samba 4.24.6, trust-ad, client-samba, sudo, fixed test expectations).
- [x] E6 Run all 16 jobs on 192.168.122.215 via the sequential runner
  (artifacts `/root/jobs/<job>/`, summary `/root/jobs/summary.tsv`).
  **Final: 16/16 PASS.** Validation status: see below.

### E6 progress (2026-09-08)

| job | status | notes |
|-----|--------|-------|
| topologies | PASS | 28/28 (smoke-tested the integration pipeline before the queue) |
| xmlrpc | PASS | 2636 tests, 0 failures, 13 skipped, 26 min total (samba/idrange now pass) |
| unit | PASS | 1261 tests, 0 failures, 39 skipped (re-run green after the
  `container=podman` fix; first-pass failure was
  `test_ipaplatform/test_tasks.py::test_detect_container` — runc
  defaults the container env var to `oci`, disagreeing with
  `systemd-detect-virt`) |
| kerberos-flags | PASS | 5/5, master+client, 7.5 min |
| netgroup | PASS | 7/7, 8 min |
| membermanager | PASS | 8/8, 7.7 min |
| service-permissions | PASS | 5/5, 6 min |
| simple-replication | PASS | 6/6, 17 min — first 2-host job |
| sudo | PASS | 87 tests, 0 failures, 1 skipped (re-run green after the
  `--deselect` argv fix) |
| external-ca-install | PASS | 3/3 |
| external-ca-constraints | PASS | 1/1 |
| external-ca-profile-scenarios | PASS | 12/12 |
| external-ca-self-external-self | PASS | 5/5 (3-host env) |
| external-ca | PASS | 2/2, 15 min (3-host env) |
| caless-to-ca-full | PASS | 3/3, 15 min |
| forced-client-reenrollment | PASS | 9/9, 16 min (3-host env) |

**Final totals: 16/16 PASS** (initial pass 14/16). Both first-pass
failures were CI-harness bugs, fixed and re-run green — no FreeIPA
test failures at all. Every job ran the full install → test → uninstall
loop on `freeipa-ci/full:44-b1af1d8bb`. Wall-clock: 14-job queue ≈ 2.7 h
serial on 2 vCPU / 8 GB, plus ~60 min for the two reruns.

Fixes made during the first full pass:
1. `write_config` now emits the exact multihost YAML shape of
   `ipa-test-config-template.yaml` (FQDN `name`, `external_hostname`,
   no `type` key on hosts — pytest_multihost rejects extra keys).
2. `_setup_resolvconf` always writes a forwarder for the master
   (default 8.8.8.8, same as the framework's DNSFORWARD default):
   podman leaves `/etc/resolv.conf` empty, and the multihost
   `PlainFileResolver` rejects an empty file ("Resolver manager could
   not be detected").
3. Unit preset: `setup_dns`/`setup_kra`/`forwarder` (the Azure base
   runner always installs `--setup-dns --setup-kra`; without a
   forwarder the installer's DNS check fails in the container).
4. `-e container=podman` at container creation (runc defaults to
   `container=oci`, which disagreed with
   `test_ipaplatform/test_tasks.py::test_detect_container`).
5. `cli.py` integration mode: `--ignore`/`--deselect` options are
   emitted as separate argv entries (a space-joined `"--deselect x"`
   string is shlex-quoted into one bogus test path).

## Results (2026-09-08, host 192.168.122.215)

Image: `freeipa-ci/full:44-8f33c1304` (1.99 GB; IPA dev build
`4.14.0.dev202609080257+git8f33c1304-0.fc44`; KRA now part of the main
`freeipa-server` package — no separate `freeipa-server-kra` subpackage;
`freeipa-server-trust-ad` / `freeipa-client-samba` excluded — samba 4.24.5
no longer in the F44 updates repo; see repo-pinning note below). Host RAM
raised 3.9 GB → 7.9 GB after an OOM crash in the first run.

| Step                          | Duration      |
|-------------------------------|---------------|
| `build.sh` (base + full)      | ~2 min        |
| `freeipa-env up` (network, container, systemd wait, sshd, config) | ~40 s |
| `ipa-server-install` (DNS+KRA) in `run` | ~5 min    |
| `test_xmlrpc` (2636 tests + 13 skipped, test_dns_plugin.py ignored) | 11 min 11 s |
| `ipa-server-install --uninstall` x2 in `run` | ~1 min  |
| `freeipa-env down` (journal + Azure-parity daemon tarball, stop, rm, net rm) | <5 s |

Suite result: **16 failed, 2607 passed, 13 skipped, 0 errors in 671.10s
(11:11)**. Deterministic: a second full run of the same build produced
identical numbers. All 16 failures analysed against the source tree at
`8f33c1304` — **none are environment bugs**; 14 are stale test expectations
introduced by two test commits in the dev branch, 2 are the known samba
environment gap:

1. `test_permission_bindtype` ×10 (0001, 0005-0006, 0008, 0011-0016) —
   commit `585084e6e` ("tests: xmlrpc: cover the permission authentication
   checks") re-baselined the test from `write`+anonymous to
   `read`+anonymous but left stale write-baseline expectations in the
   transition steps: `ipapermright=[u'write']` where the permission is now
   `read` (0005/0008/0011/0013/0015), `allow (write) ...` ACI strings where
   the server renders `allow (read) ...` (0006/0012/0014/0016 aci_show), and
   0001 drops the 13032 `MissingTargetAttributesinPermission` expectation
   that the server still emits (right='read'; `make_aci` warns for any
   read/write/search/compare right without attributes). Server behaviour is
   correct and unchanged since 2022 (`dc73813b8`); the test expectations
   are wrong.
2. `test_selfservice` ×4 (add_1002-style negative tests) — commit
   `998126e08` ("tests: xmlrpc: expect the hardened self-service ACIs")
   updated the show/find ACI expectations to the compound bind rule
   `(userdn = "ldap:///self" and userdn = "ldap:///all")` but the ACL Syntax
   **error-message** expectations (e.g. line ~806,
   `r'...all\22;)'`) are missing the closing paren the server now emits:
   server: `...userdn = \22ldap:///all\22);):`, test: `...\22ldap:///all\22;):`.
   Server rendering is correct (ipalib commit `941c151be`);
   expectations incomplete.
3. `test_range::test_range` ×2 (idrange_add with `ipanttrusteddomainsid`,
   0025/0026) — **environment gap, expected**: `validate_trusted_domain_sid`
   requires `import ipaserver.dcerpc` to succeed, which needs the `samba`
   python module (`python3-samba`). The image excludes trust-ad and samba
   4.24.5 rotated out of the F44 rolling repo, so the flag is False and the
   server raises `NotFound: Cannot perform SID validation without Samba 4
   support`. The test itself injects a fake trusted domain via
   `ipatests/test_xmlrpc/mock_trust.py` (MockLDAP), so no real AD is needed
   — only the python bindings. Fix = pin `python3-samba` (or
   `freeipa-server-trust-ad`) into the image via `PIN_SPECS`; deferred
   per project decision (samba work out of scope for this validation).

Artifacts (workdir): `nosetests.xml` (JUnit, 643 KB, from the container's
`$IPA_TESTS_LOGSDIR` = `/root/ipa-env/logs`), `logs/collect-master1.journal.log`
(27k lines), `logs/collected/master1/master1-logs.tar.gz` (Azure-parity
daemon set: dirsrv, httpd, ipa*, krb5kdc, pki, samba, /var/named/data +
boot journal), `logs/collected/master1/ipa-env/logs/` (workflow tarballs:
`ipaserver_install_logs.tar.gz` 4.9 MB, `ipaserver_uninstall_logs.tar.gz`,
`systemd_journal.log`, `nosetests.xml`), `logs/run.log`, per-step logs.

### Previous build (for reference)

`freeipa-ci/full:44-962ac6d0e`: **2106 passed, 124 failed, 13 skipped,
405 errors in 8:54** (and identically on re-run, 8:44). Failures were in the
product under test, not the environment:

- 344 server-side `InternalError` — `AttributeError: 'Principal' object has
  no attribute 'replace'` in `ipaserver/plugins/service.py` `get_dn()` on the
  new managed-permissions path (`baseldap.enforce_managed_permissions` →
  `rights_allow` → `_probe_effective_rights`).
- ~100 `ACIError: Insufficient access` for admin (e.g. `user_show`) and
  `ca_add`/`ca_del` — modernized-ACI behaviour changes.
- Remainder: cascades from the above (`DuplicateEntry`, `NotFound`) and
  assorted assertion deltas.

The 39-commit window between the builds includes the baseldap
managed-permissions rework (`fa2555cfd`, `dd317d3fd`, `fbb80bb5f`,
`8f33c1304`) and the hardened-ACI changes (`941c151be` ipalib,
`998126e08`/`585084e6e` tests) that fixed the Principal/replacement
InternalError and the Insufficient-access cluster — empirically, the 405
errors and ~108 unrelated failures are gone, leaving the 16 analysed above.

## F. PRCI definition migration (`freeipa-env migrate`)

Goal: stop hand-maintaining PRCI YAML — convert every existing PRCI
job into a freeipa-env preset so the new system inherits the whole
current coverage inventory (gating + nightlies).

- [x] F1: `freeipa_env/prci.py` — PRCI definition → preset conversion
  (topology grammar `ipaserver` / `master[_Nrepl]_Mclient` / `ad_*` /
  `adroot_adchild_adtree_*` → host roles; topology memory split evenly
  into per-role `resources`; `test_suite` → `run.tests`; class → mode;
  Build + ipa_ipa_trust skipped with reasons; AD hosts → external
  placeholders, RFC 5737 addresses, EDIT-ME footer).
- [x] F2: `freeipa-env migrate <def.yaml> [-o DIR] [--jobs NAME]` CLI
  subcommand + per-definition `MIGRATED.md` report.
- [x] F3: podman provider AD support: `write_config` renders separate
  `AD` / `AD_SUBDOMAIN` / `AD_TREEDOMAIN` domains (framework WinHost;
  host dict `name`/`ip`/`role` only, per `BaseHost.from_dict`);
  `_setup_hosts` writes `/etc/hosts` entries for external hosts into
  every IPA container (IPA↔AD name resolution without AD DNS).
- [x] F4: all 11 PRCI definitions migrated and committed under
  `ci/env/presets/prci/` — 1301 presets (gating 31, nightly-latest 185,
  nightly-previous 185, nightly-rawhide 185, selinux/testing variants,
  389ds 48, pki 91, sssd 20, temp-commit 1).
- [x] F5: validation on 192.168.122.215:
  - all 1301 generated presets parse via `EnvSpec.from_file`;
  - `up` on `prci/gating/test_ipahealthcheck_adtrust.yaml` renders the
    correct four-domain multihost config (IPA + AD + AD_SUBDOMAIN +
    AD_TREEDOMAIN) and `getent` resolves all AD placeholder FQDNs in the
    IPA containers; `down` leaves the external AD hosts in place;
  - `prci/gating/simple_replication.yaml` full end-to-end run:
    **6/6 passed** (install master+replica, replication, tests,
    uninstall; 15:39), image `freeipa-ci/full:44` = b1af1d8bb build.

Notes: PRCI has no single-IPA-host RunPytest jobs, so every migrated
RunPytest/RunADTests preset is `mode: integration`; RunWebuiTests presets
are `mode: base` with a browser/selenium note (the CI image does not
include a browser). AD admin defaults (`Administrator`/`Secret123`)
match the PRCI AD template.

## G. Run queues + supervisor (`freeipa-env queue`)

Goal: run the migrated coverage in the same order Azure and PRCI use —
ordered preset queues driven by a supervisor over pre-allocated runners
(ssh + podman + systemd hosts).

- [x] G1: `freeipa_env/queue.py` — queue files (ordered `jobs:` list of
  preset paths relative to `ci/env/`; directory entries expand sorted;
  per-job dicts with notes) + `generate_prci_queue()`.
- [x] G2: `freeipa_env/supervisor.py` — runner check (ssh + podman),
  rsync of the local `ci/` tree to `--remote-ci` (default
  `/root/freeipa-ci/ci`), fail-fast image presence check, shared-FIFO
  scheduling (one job at a time per runner, jobs dequeued in queue
  order), per-job `up` → `run` → `down` under a remote `timeout`
  (default 4 h), per-job workdir `/root/jobs/<job-key>`, transcripts,
  `summary.tsv`/`summary.md`/`queue.log`, exit 0 iff all passed;
  `--keep-on-failure` skips `down` for triage.
- [x] G3: CLI `freeipa-env queue run QUEUE --runner USER@HOST [...]`
  (`--jobs`, `--limit`, `--dry-run`, `--job-timeout`, `--outdir`,
  `--remote-ci`, `--jobs-dir`, `--ssh-key`, `--no-bootstrap`) and
  `freeipa-env queue generate PRCI.YAML -o OUT` (reuses the migrate
  mapping via the new `prci.iter_jobs()`; skipped jobs become comments).
- [x] G4: all 12 queues committed under `ci/queues/`: `azure.yaml` (16
  jobs; Azure ran them in parallel, order conventional) + one per PRCI
  definition in the definition's job order — gating 31, nightly-latest
  185, nightly-previous 185, nightly-rawhide 185, selinux/testing
  variants 185 each, pki 91, 389ds 48, sssd 20, temp-commit 1.
- [x] G5: e2e validation on 192.168.122.215: 2-job queue
  (azure kerberos-flags + netgroup) over 1 runner — **2/2 PASS**
  (6:40 + 7:38), full artifacts per job on the runner, summary +
  transcripts locally.

## H. Logical image references + provider resolution

Goal: presets must not pin a build. They carry a **logical image
reference** (`image: freeipa-ci/full:44` = *the newest full image for
dist 44* — the rolling tag `ci/images/build.sh` re-points at every
build; the exact build stays under `freeipa-ci/full:44-<sha>` for
provenance). Presets stay provider-agnostic: **resolving the reference
to a concrete image is a provider task**.

- [x] H1: all 1301+16 presets now use the rolling reference (azure
  presets de-pinned from `44-b1af1d8bb` to `44`; prci presets already
  rolling).
- [x] H2: `PodmanProvider.resolve_images()` — read-only; for each
  distinct host image ref, `podman image inspect` → id → all tags on
  that id → most-specific (longest) tag; raises with a build-
  instructions message if the ref is absent; `up()` calls it first and
  prints `== image: <ref> -> <concrete> (<short id>)`. `External
  Provider.resolve_images()` → {} (external hosts run their own IPA;
  image refs ignored).
- [x] H3: `freeipa-env resolve ENV.YAML` — provider verb that performs
  just the resolution; prints `<ref> <concrete> <image_id>` lines,
  exit 0 iff every reference resolves (external: `no image references`).
  `_podman()` now raises `PodmanError` (not a traceback) when the tool
  binary is missing.
- [x] H4: supervisor preflight — the local image list is gone; each
  runner is asked to resolve every distinct preset's refs via remote
  `freeipa-env resolve` (one ssh round trip per runner, stops at the
  first unresolvable preset); resolutions are logged per runner and
  recorded in `summary.md` ("Resolved images" tables, logical →
  concrete → id).
- [x] H5: e2e on 192.168.122.215: preflight logs `image
  freeipa-ci/full:44 -> localhost/freeipa-ci/full:44-b1af1d8bb
  (db266cd23ffd)`; 2-job queue (kerberos-flags + netgroup) **2/2 PASS**.

## I. Abstract build channels

Goal: make the preset image reference *even more* abstract — an **abstract
build channel** mirroring PRCI's per-file build generation. PRCI already
does this: each definition file references one of the next/current/previous
builds (via its `job_prefix` / `Build` job) and every job in the file uses
that one build. Presets therefore name a **channel**, never a build:

* `freeipa-current`  — newest build of the current release
* `freeipa-next`     — the next release (PRCI `fedora-rawhide`)
* `freeipa-previous` — the previous release (PRCI `fedora-previous`)

The build step publishes the channel tag (`build.sh --channel NAME` tags
`freeipa-ci/full:<channel>` alongside the immutable `<dist>-<sha>` tag);
the **provider** maps the channel name to its podman tag and resolves it to
the concrete image on the host at `up` time. External provider ignores it.

- [x] I1: `freeipa_env/image.py` — `CHANNELS` (channel → podman tag),
  `channel_tag()`, `is_channel()`, `channel_from_prefix()` (PRCI prefix →
  channel: `*previous*` → previous, `*rawhide*` → next, else current).
- [x] I2: `prci.py` — generated presets' `image:` is now the channel
  derived from the definition's `job_prefix` (no more hardcoded dist tag).
  All 1301 prci presets regenerated: 931 `freeipa-current` (fedora-latest
  + component channels), 185 `freeipa-previous` (nightly-previous), 185
  `freeipa-next` (nightly-rawhide). Deterministic: the *only* line
  changed is `image:`.
  (Plus the 16 hand-written azure presets → `freeipa-current`.)
- [x] I3: `PodmanProvider.resolve_images()` maps a channel to its podman
  tag before inspecting; explicit image refs pass through unchanged.
  `build.sh --channel NAME` (default `current`) tags `freeipa-ci/full:
  <channel>`.
- [x] I4: azure presets + base-xmlrpc now use `image: freeipa-current`.
- [x] I5: e2e on 192.168.122.215: `podman tag ... freeipa-ci/full:
  current`; `freeipa-env resolve` prints `freeipa-current -> freeipa-ci/
  full:44-b1af1d8bb (<id>)`; 2-job queue **2/2 PASS**.

## J. Nested providers (get a VM, run the env in it)

Goal: support cloud deployments where the test VMs exist only **through an
API**. A **nested provider** (`provider: nested`) composes an outer **VM
backend** ("get a VM") with an inner provider (default `podman`, "run the
env in the VM"). It is the supervisor's pre-allocated runner generalized:
the runner is acquired by the backend on demand and released on `down`.
The inner environment is the same spec with `provider` set to `inner` and
the `vm:` block stripped — the `hosts:` become containers in the provisioned
VM and the whole validated podman flow runs there.

- [x] J1: `freeipa_env/vmbackend.py` — `VMHandle` (ssh target: user@host[:port]
  + key + id + meta) + `VMBackend` interface (`provision` / `wait_ready` /
  `terminate`) + ssh/rsync helpers.
- [x] J2: backends — `ssh` (pre-allocated pool; "no real API" reference),
  `command` (shell out to provision/deprovision scripts — the generic
  cloud-API integration point), `openstack` (concrete real-API example on the
  `openstack` CLI: server create/show/delete + floating IPs).
- [x] J3: `freeipa_env/nested_provider.py` — `NestedProvider` composes a
  backend + inner provider: `up` (provision → wait → rsync ci/ + inner spec →
  inner `freeipa-env up` → persist `<workdir>/nested-state.json`), `down` (inner
  `down` → rsync artifacts back → release VMs → clear state), `run` (inner
  `freeipa-env run` on the primary VM), `resolve` (deferred to the VM),
  `show`.
- [x] J4: `envspec.py` — `provider: nested` + `vm:` (backend config) +
  `inner:` (inner provider, default podman) fields, validated; `cli.py`
  `make_provider` dispatches to `NestedProvider`; `main()` catches the new
  error types; `resolve` message made provider-generic.
- [x] J5: example preset `presets/nested-example.yaml` +
  `examples/nested/{get-vm.sh,drop-vm.sh}`; README + design doc §3.9.
- [x] J6: e2e on 192.168.122.215 (as the "provisioned VM" via the `command`
  backend stub): `up` (provision → bootstrap → inner podman up) → `run`
  (`test_integration/test_pki_config_override.py::TestPKIConfigOverride`
  **1 passed in 349s**) → `down` (inner down → logs + xunit fetched back
  locally → deprovisioned via the command backend → state cleared). Full
  nested lifecycle validated; host left clean (0 containers).

## K. Preset validation (`freeipa-env check`)

Goal: CI-gate the 1300+ presets (migrated PRCI, Azure, nested) without
spawning anything. A preset change must not silently break a queue.

- [x] K1: `freeipa_env/checker.py` — `check_spec()` (per-provider read-only
  sanity: podman image/channels, nested backend + inner, external addresses),
  `check_file()` (YAML + EnvSpec + checks), `discover()` / `check_paths()`
  (default: all presets under `ci/env/presets`).
- [x] K2: `freeipa-env check [paths ...]` subcommand — prints one line per
  failing preset + a summary; exit 0 iff every preset is sound and no path
  is missing. Validated: all 1319 presets pass; negative fixtures (bad YAML,
  unknown channel, unknown vm backend, missing master, external w/o address)
  are all flagged; good podman/nested/explicit-image presets pass.

## L. Build the IPA RPMs ourselves

Goal: stop depending on RPMs delivered by a build farm. Compile the IPA
binary RPMs from the same git snapshot in a dedicated build image on the
same host that bakes the test image, so build and test share one distro
repo snapshot and a delivered RPM's dependency (samba) can no longer drift
out of resolution (design §3.10; see also the §2 repo-pinning limitation
below — the self-build lane makes it unrepresentable).

- [x] L1: `ci/scripts/make-srpms.sh` — control-node helper: submodule init,
  autoreconf if needed, configure (same triplet as makerpms.sh), `make
  srpms`; prints the absolute `dist/srpms/*.src.rpm`.
- [x] L2: `ci/images/build/Dockerfile` — `freeipa-ci/build:<dist>` = base +
  toolchain + every `BuildRequires` from freeipa.spec.in (x86_64 full
  server), baked once per dist; and `ci/images/build.sh --srpm <path>` —
  `rpmbuild --nocheck --rebuild` the SRPM in that container, collect the
  binary RPMs, and bake `freeipa-ci/full:<dist>` from them (tagged with the
  channel; mutually exclusive
  with `--rpms`).
- [x] L3: `freeipa_env/imagemake.py` + envspec `build:` block — the
  provider glue: `ensure_channels()` ensures each abstract channel's full
  image is present (builds the absent / forced ones from `build.srpm` via
  the shared `build_sh_argv`), `PodmanProvider.up()` calls it before
  resolution, `freeipa-env ensure ENV.YAML [--build]` does just the build
  half. `image.channel_name()` exposes the short channel for build.sh.
- [x] L4: supervisor `--srpm` — `queue run --srpm <file|dir>` ships the
  SRPM to each runner and builds any channel image the runner is missing
  (freshness model) before resolution; fail fast on a build failure.
  Env files without `build.srpm` / queue runs without `--srpm` are
  unchanged.
- [x] L5: end-to-end smoke on 192.168.122.215 (2026-09-09) — built the
  build image (every F44 package name resolves; needed `rpm-build`,
  `gettext`/`gettext-devel`, `xmlrpc-c-devel` added), ran
  `build.sh --srpm <srpm> --channel current`: `rpmbuild --nocheck
  --rebuild` produced 46 binary RPMs (12 noarch + 34 x86_64) and the
  full image `freeipa-ci/full:current` (== `full:44`) was baked from
  them. A/B against the delivered-RPM image of the same commit
  (`full:44-b1af1d8bb`): identical freeipa-server version, identical
  systemd unit set; both boot to `multi-user.target` with sshd/avahi up.

## M. Runner transports + Testing Farm

Goal: decouple the queue supervisor from a pre-allocated ssh runner pool. A
runner is now a transport (`freeipa_env/runner.py`): `user@host[:port]`
(ssh, the default), `local` (the control node), or `testing-farm` (each job
is one public Testing Farm request that provisions its own guest and builds
everything on it — no ssh, no root on any host we control). Design §3.11.

- [x] M1: `freeipa_env/runner.py` — `Runner` interface + `SshRunner`
  (extracted from the supervisor's ssh path), `LocalRunner` (local
  subprocesses + `~/...` expansion), `make_runner(spec)` dispatch
  (`local` / `testing-farm` / `user@host[:port]`); the transport-neutral
  `up` → `run` → `down` recipe + shared remote-channel build
  (`_build_channels_on`).
- [x] M2: `supervisor.py` — takes runner objects instead of building ssh
  argv; bootstrap/resolve/run/summary work per runner kind; runner-style
  `~/...` paths de-rooted for non-root users.
- [x] M3: `freeipa_env/testingfarm.py` — `TestingFarmClient` (stdlib
  urllib: submit/get/cancel/wait over `api.testing-farm.io` v0.1) +
  `TestingFarmRunner.run_job` (one request per job; poll to a terminal
  state under `--job-timeout`, cancel at the deadline; PASS ⇔ `complete`
  + overall `passed`; artifacts URL in the transcript).
- [x] M4: `cli.py` `queue run --runner` accepts the three transports;
  `--tf-token`/`TESTING_FARM_API_TOKEN`, `--tf-url`, `--tf-repo-url`
  (default `remote.origin.url`), `--tf-ref` (default `HEAD`), `--tf-arch`,
  `--tf-compose`, `--tf-plan`, `--tf-variable K=V`; `--dry-run` prints the
  per-job request JSON.
- [x] M5: `ci/tmt/` + `./.fmf` — the fmf root, the
  `freeipa-env` plan (discover `^/ci/tmt/tests/`, `prepare: how: install`
  of `git` + `podman` + `curl` + the autotools toolchain + every
  `BuildRequires` of freeipa.spec.in, `execute: how: tmt` — the synta
  pattern) and the `freeipa-env` test (`tf-runner.sh`, duration 6h).
- [x] M6: `tf-runner.sh` — on-guest full flow: channel + dist from the
  preset; when no `FREEIPA_SRPM_URL` is given the guest clones the repo
  itself (`git clone --recursive` + `git checkout` of
  `FREEIPA_REPO_URL`/`FREEIPA_REPO_REF`, passed as request variables —
  TF's pipeline syncs the fmf tree to the guest as a plain file copy, no
  `.git` and no submodule contents) and builds the SRPM there
  (`autoreconf -i`, `./configure` with the spec's rpm flags, `make
  srpms`); channel image via `ci/images/build.sh --srpm`; then the same
  `freeipa-env up` → `run` → `down` recipe; exit with `run`'s status.
- [x] M7: control-node verification: `bash -n` on the guest script,
  `tmt plans lint` clean, `tmt run discover` selects the test,
  `--dry-run` request JSON correct (channel `freeipa-current`, dist 44,
  plan, no `FREEIPA_SRPM_URL`).
- [x] M8: e2e on public Testing Farm (2026-09-09): real requests against
  the `github-abbra` `modrnize-ci` branch for the `test_kerberos_flags`
  gating job. Submission 1 errored: `tmt.extra_args.prepare:
  ['--continue']` is not a valid tmt option and aborted the plan; fixed,
  plus a poller crash (TF returns `"result": null` before completion).
  Submission 2 failed in 0.4s: `FATAL: no .git in TMT_TREE` — TF's
  gluetool pipeline rsyncs only the `git ls-files`-tracked tree to the
  guest with `.git` excluded, so it has no `.git` and no submodule
  contents; the on-guest build cannot run on it. Fixed by passing
  `FREEIPA_REPO_URL`/`FREEIPA_REPO_REF` to the guest and cloning on the
  guest (`8238e6a21`); the request submitted after that fix is the one
  tracked here. Submission 3 (`a2f1f2a3`) then proved the on-guest
  recipe: recursive clone (with the `install/freeipa-webui` submodule),
  `autoreconf -i`, `./configure`, `make srpms`, and the base-image bake
  all succeeded on the guest, and it failed at the build image —
  `ci/images/build/Dockerfile` was hidden by the in-tree `build/`
  gitignore rule, so the file-copy tree had no `ci/images/build/`
  context. Fixed by tracking the Dockerfile under a targeted negation
  (`f57b8fff8`). Submission 4 (`adedf10a`) then PASSED in 21:53: the
  guest built the SRPM, baked `freeipa-ci/build:44` +
  `freeipa-ci/full:current`, brought up the 3-host env, and
  `test_kerberos_flags` passed (test time 1074s).
- [x] M9: per-stage results + artifact exposure on TF (2026-09-09): the
  `freeipa-env` tmt test now declares `result: custom` (tmt 1.77+), so the
  outcome is read from `$TMT_TEST_DATA/results.yaml` instead of the exit
  code. A new `ci/tmt/tests/freeipa-env/stage-lib.sh` (sourced by
  `tf-runner.sh`) records each stage of the job (`srpm-build`,
  `image-build`, `env-up`, `test-run`, `env-down`) with its own live
  console log (tee'd, so long stages stay live on the console), then
  writes one results.yaml entry per stage plus a parent entry for the whole
  test. After the recipe the job workdir artifacts (run console,
  `nosetests.xml`, collected per-host logs) are copied to
  `$TMT_TEST_DATA/artifacts/`. Because TF uploads the whole tmt workdir,
  `results.xml` now shows each stage as its own `<testcase>` with a
  downloadable log, and the job artifacts are downloadable under
  `.../data/artifacts/`. A results.yaml is also written from an EXIT trap
  on early death (bad preset / failing `up`), so a failed run still surfaces
  per-stage results. Schema details baked in (verified against tmt 1.77.0):
  notes single-quoted (an unquoted colon makes YAML parse a dict and
  hard-fails validation), timestamps carry fractional seconds, durations are
  `HH:MM:SS`. Verified end-to-end: request `42e4c6a3` (branch `modrnize-ci`
  @ `480bc1f46`) PASSED in 23:28 with all 6 testcases present (parent +
  5 stages, each `passed`) and every stage log + artifact resolving.

## Known limitations / follow-ups

- **Repo pinning**: the validation image was built against a rolling F44
  updates repo; samba 4.24.5→4.24.6 rotation broke trust-ad resolution
  (documented in the design). CI builds must use frozen repo snapshots —
  `build.sh` accepts `PIN_SPECS` for this.
- **xunit path**: `ipa-run-tests` sets `IPATEST_XUNIT_PATH` from `$PWD`
  before chdir. `run-base-tests.sh` uses `mkdir -p "$IPA_TESTS_LOGSDIR"`
  (not `mkdir`, which would fail in a container where the parent doesn't
  exist) so the `pushd` succeeds and JUnit lands at
  `/root/ipa-env/logs/nosetests.xml` (Azure-parity); the CLI fetches it
  from there first, with `/root/nosetests.xml` and the ipatests package
  dir as fallbacks.
- **Status (2026-09-08)**: phases A/B/C complete; both builds validated
  end to end; 16 remaining failures fully diagnosed (14 stale test
  expectations in the dev tree, 2 deferred samba environment gap);
  stale image `44-962ac6d0e` pruned from the VM (disk 70% → 64%). Phase D
  (log analysis mode `freeipa-env logs`) implemented and validated against
  the BASE_XMLRPC artifacts.
- **chronyd** must be active (unmasked) in the base image: the installer
  without `--no-ntp` restarts it; it harmlessly tracks the host clock.
- External provider: validated against the host itself (F44 detection,
  dev-build IPA detection, port probing, collect-only down, `--ssh-key`).
  No destructive operations performed.
