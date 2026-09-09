# Modern FreeIPA CI: container-based, catalog-driven test infrastructure

## Overview

FreeIPA currently runs its CI in two disconnected systems:

* **PR-CI (PRCI)** — the pre-podman, Beaker/BeakerLib-based system. A PR triggers
  a `build` job plus a large DAG of test jobs (see
  `ipatests/prci_definitions/gating.yaml` and `nightly_latest.yaml`). Every
  test job provisions real VMs from a *topology* (e.g. `master_1repl_1client`,
  4 vCPU / 8 GB), SSHes into them, installs IPA, runs one pytest module or
  class, collects logs, and tears down. Topology-to-job mapping is maintained
  by hand in ~10 large YAML files (~10 000 lines) that `prci_checker.py`
  validates. Nested virtualization, VM cloning and 1–2 h job timeouts make
  this slow and expensive; AD-trust tests additionally need Windows VMs.
* **Azure CI** — Azure Pipelines agents (Ubuntu VMs) that build RPMs, bake a
  systemd-enabled container image (`Dockerfiles/Dockerfile.build.fedora`,
  image `freeipa-azure-builder`), and run test slices via
  `scripts/azure-run-tests.sh`: a `podman-compose` environment per "project"
  (1 master + N replicas + M clients), up to `MAX_CONTAINER_ENVS = 5`
  environments packed per agent VM, pytest executed *inside* the master
  container against the sibling containers over SSH. The job matrix is
  generated statically by `scripts/generate-matrix.py` from
  `azure_definitions/*.yml`. This is already much faster than PRCI, but the
  tooling is a bash/Jinja/docker-compose v2 composition, the packing is
  static, there is no flake management, no per-run scheduling, no Windows/AD
  lane, and SELinux-enforcing and FIPS variants are not covered at all.

Scale of the suite today: 77 integration test modules, 171 test classes
(`test_integration/`), ~1600 test methods, plus unit-level suites
(`test_cmdline`, `test_ipalib`, `test_ipaserver`, `test_webui`, …).

The central observation is that **the test framework is already decoupled
from the infrastructure**:

* `ipatests/pytest_ipa/integration/` (built on `pytest_multihost`) describes a
  topology declaratively (`num_replicas`, `num_clients`, `num_ad_domains`,
  `topology`, `domain_level`, `fips_mode`, `required_extra_roles`) and
  connects to already-provisioned hosts purely over SSH using a *multihost
  config* that can be injected as plain YAML via `IPATEST_YAML_CONFIG`
  (`env_config.py`) or legacy env vars (`MASTER_env1`, `REPLICA_env1`, …).
* Nothing in the 171 test classes knows *where* the hosts run. PRCI gives
  them VMs; Azure gives them containers. Both just export hostnames/IPs.

So the modernization is not a test-suite rewrite. It is replacing the
*provisioning + scheduling layer* with:

1. a **test catalog** — the single declarative source of truth for *what*
   runs *where* (replaces hand-written PRCI YAML and Azure matrix YAML),
2. an **image pipeline** — layered, registry-published container images with
   IPA installed (generalizes the Azure `freeipa-azure-builder` image),
3. an **environment provisioner** (`freeipa-env`) — a small, stable API to
   spawn/destroy IPA server/client (and helper) systems in a controllable
   way, replacing both PRCI topology→VM mapping and the
   `podman-compose` + `setup_containers.py` ad hoc logic,
4. an **orchestrator** — a self-hosted runner pool with a queue, dynamic
   packing, flake-aware retries and artifact store (replaces PRCI job DAGs
   and Azure matrix jobs).

## Goals and non-goals

Goals:

* **Speed**: PR gate feedback in tens of minutes, not hours; nightly full
  suite in ~2–4 h instead of an overnight VM farm run.
* **Control**: one declarative API to spawn any IPA topology (master,
  replicas, clients, AD, helper roles) on any runner, with pinned images,
  dist, domain level, FIPS mode, IPv6, resource limits — from CI, from a
  developer laptop, or from another project.
* **Maintainability**: no hand-maintained job lists; topology/tier/resource
  requirements are derived from the test code itself; adding a test requires
  no CI YAML changes.
* **Coverage**: keep everything PRCI does today (SELinux enforcing, FIPS,
  AD trust, component-integration nightlies) in the new system.

Non-goals:

* Rewriting the test framework or the 171 test classes.
* Moving to a public CI (GitHub/GitLab) — the infra stays self-hosted.
* Replacing packaging/RPM build tooling (COPR/build farm). CI consumes
  produced RPMs.

## Architecture

```
                +--------------------------------------------------+
 PR push  ---> |                CI entrypoint (hook)               |
                +--+---------------------------+--------------------+
                   |                           |
                   v                           v
        +------------------+        +---------------------------+
        | Build pipeline   |        | Lint / static / unit lane |
        | RPMs per dist     |        | (plain container, no env) |
        +--------+---------+        +---------------------------+
                 | RPMs
                 v
        +------------------+          +----------------------------------+
        | Image pipeline   |  --->    | Container registry               |
        | layered images    |          | freeipa-ci/... : channel/dist/commit tags|
        +--------+---------+          +----------------------------------+
                 |
                 v
        +------------------+          +----------------------------------+
        |  Test catalog    |  ----->  | Orchestrator (scheduler + queue) |
        | (auto-generated) |  packing | flake retry/quarantine, artifacts|
        +------------------+          +---------------+------------------+
                                                    |
                                   runner pool (Fedora + podman)
                                                    |
                  +--------------------------------------------------+
                  | freeipa-env (the provisioner, runs on each runner)|
                  |  - podman networks, systemd containers, SSH       |
                  |  - injects IPATEST_YAML_CONFIG, runs ipa-run-tests|
                  +--------------------------------------------------+
```

Every moving part is *boring technology*: podman, a Python scheduler
service, a SQLite/Postgres results DB, an S3-like artifact store. No
kubernetes, no Mesos.

## 1. Test catalog

The catalog is the only file humans review; everything else is generated.

A tool (`ci/catalog.py`, run in a container) does:

1. `pytest --collectonly` over `ipatests/` inside a standard image,
2. reads class attributes from each collected class
   (`num_replicas`, `num_clients`, `num_ad_domains`, `num_trusted_domains`,
   `topology`, `domain_level`, `fips_mode`, `required_extra_roles`),
3. merges static metadata from a small hand-written overlay
   (`ci/catalog_overlay.yaml`: tiers, known-slow, quarantine, resource
   overrides),
4. emits `ci/catalog.json` (committed; CI fails a PR that changes tests
   without updating the catalog, same spirit as `makeaci`/`makeapi`).

Catalog entry shape:

```yaml
- id: test_integration/test_hbac_functional.py::TestHBACFunctional
  tier: 1                 # 0 = no-server fast, 1 = integration, 2 = heavy
  hosts: {master: 1, replica: 1, client: 3}
  extra: []               # ad:1, keycloak:1, external_ca:1, ...
  topology: star          # when the class sets cls.topology
  domain_level: null
  fips: false
  dists: [f44, f43, rawhide]      # from overlay; default: all current
  selinux: permissive        # permissive | enforcing | both
  timeout: 5400
  last_runtime: 1434          # seconds, updated by the orchestrator
  flake: 0.02                 # rolling window, maintained by orchestrator
```

Derived presets (also generated, stored under `ci/presets/`):

* `gate.yaml` — the PR gate: tier-1 classes that touch the changed code
  (file→test map from the catalog) plus a fixed smoke set (master install,
  client install, replication, ACI/API check). Target: ≤ 30 min.
* `full-f44.yaml`, `full-f43.yaml`, `rawhide.yaml` — nightlies.
* `selinux-enforcing.yaml`, `fips.yaml` — variant nightlies (the PRCI
  `nightly_latest_selinux.yaml`, `nightly_latest.yaml` … equivalents).
* `component-sssd.yaml`, `component-pki.yaml`, `component-389ds.yaml` —
  the existing copr-based integration nightlies (`nightly_latest_sssd.yaml`,
  …).
* `ad-trust.yaml` — the AD-heavy subset (today `RunADTests` in PRCI).

What this kills: the 10,000-line hand-written PRCI YAML, the
`prci_jobs_spec.yaml`/`prci_checker.py` contract, and the Azure
`generate-matrix.py` + `azure_definitions/*.yml` matrices. A new test module
is picked up by the catalog generator automatically; no CI edit, no review
of job YAML.

## 2. Image pipeline

Layered images, published to the internal registry (Quay), built per PR /
per dist. Layers are designed so the expensive parts never rebuild:

```
freeipa-ci/fedora-base:44                 # systemd, openssh, dnf cache warm,
                                          # debuginfo, python3 + pytest toolchain
  └── freeipa-ci/server:44-<sha>          # + all server RPMs from this commit
        └── freeipa-ci/full:44-<sha>      # + client RPMs (most envs want both)
              (also tagged freeipa-ci/full:44 — the rolling dist tag — and
               freeipa-ci/full:<channel> — the build channel, e.g. :current)
```

Three tag families on the same image:
* **`<dist>-<sha>`** — immutable provenance tag.
* **`<dist>`** — rolling dist pointer, re-pointed by every build.
* **`<channel>`** — the build generation pointer (`current` / `next` /
  `previous`), re-pointed by `build.sh --channel NAME`.

Presets name a **channel**, never a build — `image: freeipa-current` /
`freeipa-next` / `freeipa-previous`, mirroring PRCI where each definition
file references one build generation and every job in it uses that one
build. **Resolving a channel to a concrete image is a provider task** (the
podman provider maps the channel to its podman tag and resolves it against
the local image store at `up` time; the external provider ignores it —
external hosts run their own IPA). A preset may also name an explicit image
reference (passed through) to pin a specific build.

* Base is rebuilt weekly / on dist upgrade; server/full are thin (one `rpm -i`
  layer on top, `dnf install --downloadonly` of the PR RPMs from the build
  farm URL — the same inputs PRCI's `Build` job already produces).
* The base **must be `registry.fedoraproject.org/fedora-toolbox:<dist>`** —
  the plain `fedora` image has no systemd, and systemd-as-PID-1 is the whole
  model. (Same base the Azure `Dockerfile.build.fedora` already uses.)
* **Repo pinning**: the build resolves IPA's RPM dependencies against the
  live distro repos, which move forward under us. This bit us immediately in
  the proof-of-concept: the dev build's `freeipa-server-trust-ad` requires
  `libgse-private-samba.so(SAMBA_4.24.5_PRIVATE_SAMBA)` while the repo had
  already moved to samba 4.24.6, so the image build was unresolvable. CI
  image builds must therefore run against a **frozen repo snapshot**
  (per-build repo pinning), not the rolling repos.
* **`firewalld` must be masked in the CI image.** Inside a container the
  IPA install does not bind `eth0` to a firewalld zone, but an active
  firewalld still hooks the netfilter tables, and the default-zone
  `default=drop` policy **REJECTs inter-container traffic** (observed:
  client → master 389/88/53 refused until `systemctl mask firewalld` +
  `nft flush ruleset`). Network isolation in CI comes from the podman
  network, not from per-host firewalls.
* Multi-arch: x86_64 + aarch64 runners; arm nightlies.
* Image tags: `<dist>-<commit-sha>` (PR/merge commits) and `<dist>-latest`
  (branch head). Environments always pin an explicit tag; the catalog
  generator pins the *test tree* revision to the same commit.
* The base image absorbs everything `Dockerfile.build.fedora` does today
  (mask `systemd-resolved`, `ConditionVirtualization` overrides, sshd
  hardening, `STOPSIGNAL`), so the existing, already-proven
  systemd-in-container approach is kept as-is.

What this kills: the per-PR "install 100+ RPMs inside the VM/agent" step of
Azure and the PRCI build→test RPM copy dance; image builds become ~1 min on
top of a cached base instead of ~15–20 min per job.

## 3. Environment provisioner (`freeipa-env`)

This is the heart of the design: **the controllable way to spawn IPA
server/client systems.**

### 3.1 Input: a topology file

```yaml
# env.yaml — one per scheduled test group
domain: ipa.test
provider: podman         # podman (default): created env | external: attached,
                         # pre-created elsewhere (all hosts need `address`)
dist: f44
image: freeipa-current         # build channel; resolved by the provider
domain_level: 1
fips: false            # userspace FIPS, per existing fips.py
ipv6: true
selinux: permissive
hosts:
  - {role: master,  name: master1}
  - {role: replica, name: replica1}
  - {role: client,  name: client1}
  - {role: ad,      name: ad1, image: freeipa-ci/win2022:std, os: windows}
  # a host with an explicit address is attached, not created — valid in
  # both providers (e.g. a Windows AD VM bridged into the env network):
  # - {role: ad, name: ad1, address: 192.0.2.20, user: Administrator, os: windows}
options:
  dnf_cache: shared              # node-level shared dnf/krb5 cache volume
  journal_stream: true           # stream journal to the artifact store
  # preinstalled: true           # external envs arriving with IPA already
                                 # installed: per-class install/uninstall no-op
```

### 3.2 Lifecycle

```
freeipa-env up   env.yaml        # ~20-60 s
freeipa-env run  env.yaml -- pytest <args>   # exec in the controller
freeipa-env down env.yaml        # collect logs, destroy network+containers
freeipa-env show env.yaml        # status / IP table (for debugging)
freeipa-env logs env.yaml        # categorize + retrieve collected logs
```

`up`:

1. creates a podman **network** `env-<id>` (IPv4 + IPv6 subnets, RFC1918,
   no external exposure) and one container per `hosts` entry from the
   pinned image (systemd PID 1, the exact capability/seccomp set from the
   current `docker-compose.yml`, per-role CPU/memory limits),
2. waits for `multi-user.target` (reuses `wait-for-systemd.sh` logic),
3. writes `/etc/hosts`, hostname, resolv.conf (master IPs as forwarders —
   same as `setup_containers.py`, but as one code path),
4. generates the SSH keypair, distributes `authorized_keys`,
5. **emits the multihost YAML** and exports `IPATEST_YAML_CONFIG` — i.e. it
   produces exactly the artifact `env_config.config_from_env()` already
   understands (this is precisely what Azure's
   `ipa-test-config-template.yaml` renders today, now generalized),
6. streams `journalctl -f` from each host into per-run artifact files.

`run` executes `ipa-run-tests` (the existing wrapper) inside the
**controller** — by default the master container (which already has the full
IPA + pytest toolchain, as Azure does); envs without a master (unit-tier
envs) get a thin `freeipa-ci/tester` controller image instead.

`down` collects the standard `CLASS_LOGFILES` set, tar+ships it to the
artifact store, then `podman network rm` + container removal (measured at
1.6 s for a master+client pair — see §8). The uninstall step is part of the
workflow under test, not a teardown optimization: the framework's uninstall
finalizer runs as the last phase of the run (install → test → uninstall),
exactly like on a VM, and its duration lands in the results DB with the rest
of the workflow metrics. The container is only destroyed *after* uninstall
has completed.

**Pre-created (external) environments.** `freeipa-env run` also works
against environments provisioned elsewhere — VMs reserved from Beaker or a
lab, bare-metal, an existing Windows AD forest, a partner's test rig. The
contract does not change: the framework consumes the multihost YAML over
SSH, so an external env is anything that can present the same SSH-reachable
host list.

* **Declaration**: `provider: external`, or per-host `address:` (+`user`,
  `port`, `dist`, `os` as needed). A host with `address` is attached, not
  created; podman envs may mix created and attached hosts (e.g. containers
  + a Windows AD VM — podman networks are host bridges, so a VM NIC lands
  on the same L2 segment).
* **`up` = attach, not provision**: validate SSH reachability as the given
  user, check hostname/dist/OS against the preset's expectations, verify
  inter-host reachability on the ports the suite needs (22, 53, 88, 389,
  636, 80/443), confirm the expected IPA state (installed or not), then
  emit the same multihost YAML. `up` mutates nothing; the only writes that
  ever happen on an external host are the `prepare_host`-class ones the
  framework already performs on *every* host (test dir + env file).
* **`run` is unchanged**: same `IPATEST_YAML_CONFIG`, same controller
  semantics. The controller is the env's master when it carries the pytest
  toolchain; otherwise the orchestrator node is the controller — multihost
  is SSH-based, so an external controller is a first-class citizen, no
  agent needed.
* **`down` = collect, don't destroy**: log collection + report only; the
  env is returned to whoever owns it (the reservation system sees a clean
  release, not a teardown).
* **Pre-installed envs**: when the env arrives with IPA already installed
  (persistent lab, long-running AD-trust matrix), per-class
  install/uninstall must become no-ops. The framework already expresses
  install/uninstall as per-class classmethods
  (`IntegrationTest.install` / `.uninstall`), so individual classes can
  override them today; the additive piece is an env-level
  `preinstalled: true` flag in the multihost config that the `mh` wiring
  honors by skipping the per-class install/uninstall calls.
* **Scheduling**: an external env consumes no runner capacity (no
  containers, no podman network) — only a controller slot — so the
  orchestrator schedules it independently of the podman runner pool. Lanes
  that cannot be containerized (SELinux enforcing, kernel FIPS, real
  Windows AD) are `provider: external` envs against Beaker/lab
  reservations; the catalog marks the classes that need them.

### 3.3 Roles beyond master/replica/client

* `ad` — Windows containers (`podman` on a Windows-capable runner, or a
  pre-provisioned Windows VM attached to the same podman network) for
  AD-trust classes; as a cheaper substitute, a **Samba 4 DC** container
  (`samba-ad:18`) which satisfies the majority of trust scenarios
  (join, group mapping, replication) — the SSSD project runs exactly this.
  Catalog marks each AD test class with which variant it needs.
* `keycloak` / `idp` (existing `create_keycloak.py`), `external_ca`
  (existing `create_external_ca.py`/`create_bridge.py` helpers), `krb5kdc`
  (standalone KDC) become first-class roles; today they are bolted on via
  ad-hoc helpers in the test code.
* arbitrary `extra` hosts (`required_extra_roles`) map 1:1 to containers,
  preserving `TESTHOST_<role>_envN` semantics for the legacy env-var path.

### 3.4 Control surface (why "controllable")

* **Reproducible**: for podman envs the env is a pure function of
  `env.yaml` and the image tag (pinned image + dist + domain_level + fips
  flag); for external envs the attach-time validation records what was
  observed (dist, IPs, IPA state) so the run is reproducible against that
  snapshot and a drifting system fails `up` loudly instead of the tests.
* **Local**: the same CLI runs on a developer laptop (podman + a `podman
  machine` VM) — "reproduce job 4821" becomes
  `freeipa-env up ci/presets/gate/env-4821.yaml`.
* **Observable**: every run has one ID; network, container list, journal
  streams and collected logs are keyed by it and browsable.
* **Bounded**: per-role CPU/mem defaults from the catalog (e.g. client
  1 vCPU/512 MB like Azure's `IPA_TESTS_CLIENT_MEM_LIMIT`), hard per-runner
  capacity so the scheduler never overpacks.
* **Re-entrant**: `up` is idempotent; a crashed scheduler can re-adopt a
  live environment by ID.

### 3.5 What it replaces

* PRCI: topology→VM provisioning, `RunPytest/RunPytest2/RunPytest3/RunADTests`
  class plumbing, BeakerLib log push.
* Azure: `azure-run-tests.sh`, `setup_containers.py`,
  `docker-compose.yml`, `seccomp.json` handling, the `IPA_TESTS_*_<id>`
  variable jungle, `generate-matrix.py`.

### 3.6 Log analysis (`freeipa-env logs`)

Resolving CI issues is a first-class use case, so the collected artifacts
are not left as raw tarballs: `freeipa-env logs` turns them into a triage
view without the operator having to know the layout.

* **Input**: the workdir artifacts (`nosetests.xml`, `logs/run.log`,
  per-host journal, the Azure-parity daemon tarball, the framework tree
  with the workflow tarballs). Daemon tarballs are **selectively**
  extracted (dirsrv, httpd, `ipa*`, krb5kdc, pki kra/ca, samba, named;
  pki-tomcat backups excluded) into `logs/extracted/<host>/`, cached by
  mtime+size — repeated analysis is instant and the on-disk footprint stays
  small.
* **Categories** with a default severity filter each, overridable per call:
  `tests` (JUnit: totals + failed tests with message and traceback tail,
  grouped by module), `run` (the streamed console), `install`/`uninstall`
  (installer logs, also from the workflow-tarball snapshots, de-duplicated
  by content), `ds`, `httpd` (framework ERROR lines + tracebacks, debug
  noise excluded), `kra`/`ca`, `kdc`, `samba`, `dns`, `ipa` (per-operation),
  `system` (journal: failed units, OOM, segfaults).
* **Retrieval**: the default view is a per-category summary (sources +
  interesting-line counts) so the triage starts from "which category is
  hot"; `--category NAME [--host H] [--pattern REX] [--lines N] [--tail N]
  [--all]` retrieves the matching lines (or whole files) of a category;
  `--json` exposes the summary for tooling; `--refresh` re-collects from a
  still-live environment before analyzing. A failed collection never
  clobbers previously collected artifacts (write-on-success only).

### 3.7 PRCI definition migration (`freeipa-env migrate`)

Existing PRCI definitions (`ipatests/prci_definitions/*.yaml`) are not
rewritten by hand: `freeipa-env migrate <definition>.yaml [-o DIR] [--jobs
NAME]` converts every job to a preset under `presets/prci/<definition>/`
(plus a `MIGRATED.md` report), so the new system inherits the existing
coverage inventory directly.

* **Topology → hosts**: `ipaserver` → one master (base mode);
  `master[_Nrepl]_Mclient` → master/replica/client hosts (integration mode
  for multi-host topologies); AD tokens (`ad`, `adroot_adchild_adtree`) add
  **external** AD hosts with roles `ad`/`ad_subdomain`/`ad_treedomain`.
* **Topology memory → per-role limits**: PRCI numbers are per-topology
  totals; the migration splits them evenly (rounded to 100 MiB, 512 MiB
  floor) into the preset's per-role `resources`.
* **test_suite → `run.tests`**; **class** selects the mode (`RunPytest*` →
  integration, `RunWebuiTests` → base with a browser/selenium note);
  `Build` jobs and `ipa_ipa_trust` topologies are skipped with reasons.
* **AD hosts stay external**: PRCI provisions the AD DCs itself; the
  migration emits RFC 5737 placeholder addresses + FQDNs marked EDIT ME.
  The podman provider renders them into the multihost config as separate
  `AD`/`AD_SUBDOMAIN`/`AD_TREEDOMAIN` domains (framework `WinHost`) and
  writes `/etc/hosts` entries into the IPA containers so AD name resolution
  works without AD DNS on the container network.

All 11 current definitions (gating + 10 nightlies, 1301 jobs) are
migrated and committed under `ci/env/presets/prci/`; a regenerated
`gating/simple_replication` ran end-to-end on the validation host
(6/6 passed), and a 3-AD-domain preset renders the correct four-domain
multihost config.

### 3.8 Run queues and the supervisor (`freeipa-env queue`)

Running the migrated coverage needs PRCI/Azure-style run queues: ordered
lists of presets executed by a supervisor over a pool of pre-allocated
runners (ssh + podman + systemd hosts).

* **Queue files** (`ci/queues/`): `azure.yaml` (the 16 Azure jobs; Azure
  ran them in parallel, so the order is conventional) plus one per PRCI
  definition, each in the definition's job order (generated with
  `freeipa-env queue generate <def>.yaml`). A queue is an ordered `jobs:`
  list of preset paths (relative to `ci/env/`), a directory entry
  expanding to all its presets sorted, or per-job dicts with notes. Each
  preset names only a build channel (`freeipa-current` / `freeipa-next` /
  `freeipa-previous`).
* **Supervisor** (`freeipa-env queue run <queue> --runner user@host …`):
  validates every preset, checks each runner, rsyncs the `ci/` tree, and
  asks each runner's provider to resolve every distinct preset's image
  references (remote `freeipa-env resolve`; fail fast on a missing image
  before any job starts; resolutions recorded per runner in
  `summary.md`). Scheduling is a shared FIFO: each runner pulls jobs from the
  front of the list, one at a time — `up` → `run` → `down` under a per-job
  remote timeout, per-job workdir, per-job transcript. Results land in
  `summary.tsv` / `summary.md` + `queue.log`; exit code 0 iff all passed.
  With one runner the queue order is exactly the run order; with N
  runners each runner's subsequence preserves queue order (FIFO dequeue),
  the same shape as a PRCI run queue over a VM pool. `--keep-on-failure`
  leaves a failed environment up for triage.

This is the concrete first instance of the §4 orchestrator's scheduling
primitive (single machine, ssh + rsync, no results DB yet).

## 4. Orchestrator

A small Python service (single deployment; SQLite→Postgres as it grows):

* **Queue** with priorities: PR gate > merge-queue > nightly > experiments.
  Nightly jobs are *preemptible* (pause at class granularity; containers of
  an in-flight class finish, the rest of the nightly resumes later).
* **Packing**: bins test classes into environments, not jobs. A class needs
  `(hosts, extra, fips, domain_level, selinux, dist)`; classes with
  *compatible* requirements share one environment (same image, same topology
  superset) and run sequentially inside it — this generalizes Azure's
  5-envs-per-VM packing from static YAML to dynamic, duration-aware bin
  packing (LPT on `last_runtime` from the results DB). The `mh` fixture is
  class-scoped, so a class's domain is already built once per class; packing
  at class granularity loses nothing.
* **Runner pool**: Fedora nodes with podman, tagged by capacity class
  (`small`: 2 envs, `standard`: 5 envs, `large`: 3 envs + topology,
  `windows`: AD). ~10 standard nodes ≈ 50 concurrent envs.
* **Flake management**: per-class rolling pass/fail + duration stats;
  `flake` score auto-quarantines (moves to a quarantine preset with
  retry×3); a PR that fixes a quarantined test un-quarantines it.
* **Artifacts**: junit XML + per-class log tarballs + journal streams to the
  artifact store; a report page per run with pass/fail/flaky/timeout and
  links into per-class logs (replaces PRCI's per-job pages and Azure
  pipeline logs).

Estimated nightly cost: 171 classes ≈ 28–40 envs after packing (most classes
are master+1 replica; a few are 3-client or multi-replica) → on 50
concurrent envs the *execution* wave is ~1; with install time included
(master install 2–4 min per env is the dominant per-env cost) the whole
full nightly ≈ 1.5–3 h vs an all-night PRCI run. PR gate: ~10–14 envs,
2 waves on a 5-node slice + 10 min build → **~30–45 min end-to-end**,
dominated by the single `ipa-server -r` install in each env — the one
constant we accept (it tests the thing we ship).

## 5. Use cases

**5.1 Developer opens a PR.** Hook builds RPMs (farm) → images. Lint/unit
lane starts immediately in a plain container. Catalog diff selects the gate
preset (changed files → touched classes + smoke set). Scheduler packs into
≤ 14 envs, runs them in ~30–45 min, posts a comment with the drill-down
report. A red class shows the class, its env ID, links to journal + logs;
`freeipa-env up <env>` reproduces it locally.

**5.2 Nightly.** For each dist (f44, f43, rawhide): full catalog; variant
runs (selinux-enforcing, fips) reuse the same catalog with a variant flag.
Component nightlies (sssd/pki/389ds copr builds) point `image` at
`<component>-ci` overlay images; the catalog `component-*` presets run only
the tagged subset (today's `nightly_latest_sssd.yaml` etc.).

**5.3 AD trust.** Classes marked `ad: samba` run in the standard pool with a
Samba DC container (the common case, now covered in *every* CI, not only
PRCI). Classes marked `ad: windows` schedule onto the small `windows`
runner pool. Both share one `env.yaml` shape.

**5.4 Developer on a laptop.** `freeipa env up --class
test_integration/test_dns.py::TestDNS` — one command, full topology, no
Beaker, no Azure, no VMs.

## 6. Repository layout

New top-level `ci/` directory (all of it is build/test tooling, *not*
packaged into FreeIPA):

```
ci/
  catalog.py                  # generator (collectonly -> catalog.json)
  catalog.json                # committed, generated
  catalog_overlay.yaml        # hand-maintained metadata (tiers, quirk overrides)
  presets/*.yaml              # generated presets (gate, full-*, variant-*, component-*)
  images/
    base/Dockerfile           # per dist (fedora-toolbox + systemd + toolchain)
    server/Dockerfile         # + server RPMs   (parameter: dist, build_url)
    full/Dockerfile           # + client RPMs
  env/                        # the freeipa-env provisioner (python package)
    freeipa_env/...           # + image.py (build channels), queue.py, supervisor.py
    cli.py                    # `freeipa-env up/run/down/show/logs/migrate/queue/resolve`
    presets/prci/             # migrated PRCI definitions (11 defs, 1301 presets)
  queues/                     # ordered run queues (azure + 11 PRCI definitions)
  orchestrator/               # scheduler service, results db, report
  runners/                    # node provisioning (podman setup, capacity tags)
  scripts/                    # hook -> trigger, report posting
```

In `ipatests/`: only small additive changes — catalog-friendly markers where
class attributes are not enough, the env-level `preinstalled` flag (per-class
install/uninstall no-op, §3.2), and eventual deletion of
`ipatests/azure/` and `ipatests/prci_definitions/` after cutover.
`ipa-run-tests`, the `pytest_ipa/integration` framework, and all test
modules stay untouched.

## 7. Migration plan

* **Phase 0 — foundation (no behavior change).** Land `ci/env`
  (provisioner, podman *and* external/attach providers) + `ci/images`
  base/server/full Dockerfiles; run it against one dist and a handful of
  classes as a manual script; prove the systemd-container model at scale (it
  is already proven at Azure's scale, so this is porting, not inventing).
  Landing the attach provider here matters for cutover: lanes that cannot
  move to containers yet keep running on externally provisioned VMs through
  the exact same `up`/`run`/`down` CLI.
* **Phase 1 — catalog + orchestrator v1.** `catalog.py` + static packing;
  gate preset runs on the new infra *in parallel* with PRCI/Azure (both
  report to the PR). Flip the PR gate over.
* **Phase 2 — nightlies.** Move full/variant/component nightlies; start
  collecting the duration/flake DB; enable dynamic packing and quarantine.
* **Phase 3 — decommission.** Remove `ipatests/azure/`,
  `ipatests/prci_definitions/`, the PRCI Beaker jobs and Azure pipelines;
  keep the PRCI-style YAMLs archived for reference.

## 8. Proof-of-concept: measured on a real runner

The core loop of this design was validated end-to-end on a 2 vCPU / 4 GB
Fedora 44 host with podman 5.8.4, using the in-tree dev build
(4.14.0.dev…git962ac6d0e) packaged from this worktree's lineage:

| Step | Command / action | Time |
| --- | --- | --- |
| Image build | `podman build` (fedora-toolbox:44 + 19 IPA RPMs, deps from repos) | ~2–3 min, once per commit |
| Network | `podman network create --subnet 10.89.0.0/24 --subnet 2001:db8:1::/64` | <1 s |
| Boot master | `podman run` (caps ALL, seccomp unconfined, systemd PID 1) → `systemctl is-system-running = running` | ~10 s |
| SSH | controller (master) keygen → client `authorized_keys`, ssh master→client | ~2 s |
| Master install | `ipa-server-install -U -a … -p … -r IPA.TEST -n ipa.test --setup-dns --forwarder 8.8.8.8 --no-ntp` (DS + CA + KDC + bind) | **4 min 11 s** |
| Boot client | second container, resolv.conf → master bind | ~10 s |
| Client install | `ipa-client-install -U --domain ipa.test --realm IPA.TEST --server master1.ipa.test -p admin -w Secret123` over ssh from master | **13.6 s** |
| Functional | `kinit` from client, `id jdoe` (SSSD), `ipa user-find` / `ipa host-find` (RPC) | pass |
| Infra teardown (post-uninstall) | `podman stop` + `podman rm` + `podman network rm` | **1.6 s** |

Findings that shape the design:

* **Uninstall stays in the loop**: uninstall is part of the workflow under
  test (install → test → uninstall), even in disposable containers. The 1.6 s
  figure above is only the *infrastructure* teardown that happens after the
  uninstall phase has run.
* **Installer CLI conventions** (long-established, not new in this branch):
  the entry point is `ipa-server-install` with `-a ADMIN_PASSWORD`,
  `-p DM_PASSWORD`, `-n DOMAIN` (`-d` is `--debug`), and single-label realms
  have been rejected for years by the RFC 952/1123 realm validation. CI envs
  must therefore use two-label realms (`IPA.TEST` for domain `ipa.test`) —
  the multihost framework's `domain.upper()` convention already satisfies
  this, but hand-written scripts and docs that pass single-label realms (e.g.
  `IPATEST`) must be checked.
* **`--server` must be the master FQDN**, not the zone apex (the apex has no
  A record; libldap reports `cannot connect … No such file or directory`).
  This matches what `tasks.install_client()` already passes
  (`'--server', master.hostname`).
* Client enrollment is ~14 s once the CA/DNS are reachable — the per-environment
  cost is dominated by the single `ipa-server-install`, exactly as the design
  assumes; on faster runners (4+ vCPU) that constant shrinks proportionally.

### 8.1 Full BASE_XMLRPC job through `freeipa-env`

The Azure **BASE_XMLRPC** job (1 master, DNS+KRA, `test_xmlrpc` with
`test_xmlrpc/test_dns_plugin.py` ignored) was run unmodified through the
final tooling (`ci/images/build.sh` → `freeipa-env up` → `run` → `down`) on
the same 2 vCPU host (RAM raised 4 GB → 8 GB after an OOM crash in the first
run), image `freeipa-ci/full:44-8f33c1304` (1.99 GB; dev build
`4.14.0.dev202609080257+git8f33c1304-0.fc44`; in this build KRA is part
of the main `freeipa-server` package — no separate `freeipa-server-kra`
subpackage):

| Step | Time |
| --- | --- |
| `build.sh` (base + full) | ~2 min |
| `freeipa-env up` (network, container, systemd wait, sshd, config) | ~40 s |
| install (master + KRA, in `run`) | ~5 min |
| `test_xmlrpc` (2636 executed + 13 skipped) | 11 min 11 s |
| uninstall x2 (in `run`) | ~1 min |
| `freeipa-env down` (journal + Azure-parity daemon tarball, stop, rm, net rm) | <5 s |

Result: **16 failed, 2607 passed, 13 skipped, 0 errors in 671.10s**
(deterministic across two full runs). All 16 were analysed against the
source tree at `8f33c1304`: **none are environment bugs**.

* 10× `test_permission_bindtype` — stale write-baseline expectations left
  by test commit `585084e6e` (the re-baselined `read`+anonymous steps still
  expect `ipapermright=[u'write']` / `allow (write) ...` ACIs and dropped
  the 13032 no-attrs warning the server still emits with right='read').
* 4× `test_selfservice` — test commit `998126e08` updated the show/find ACI
  expectations to the compound bind rule but missed the closing paren in the
  ACL Syntax *error-message* expectations.
* 2× `test_range::test_range` (idrange_add with
  `ipanttrusteddomainsid`) — the known samba environment gap: SID
  validation needs the `samba` python module (`python3-samba`), which the
  image cannot get while trust-ad/samba 4.24.5 are out of the rolling F44
  repo; the test itself only needs `MockLDAP`'s fake domain, so the fix is
  to pin the bindings via `PIN_SPECS` (deferred).

The environment itself — provisioning, JUnit artifact (`nosetests.xml`),
Azure-parity log/journal collection, teardown — completed cleanly end to
end. See `ci/TODO.md` for the artifact list and the per-failure detail.

An earlier build (`44-962ac6d0e`) scored 2106 passed / 124 failed /
405 errors; every one of those extra failures was a product bug in that
dev snapshot (Principal `replace` `InternalError` on the
managed-permissions path, ~100 admin `Insufficient access` ACI changes,
cascades) and is fixed in the `8f33c1304` window.

Implementation notes that came out of the validation:

* **chronyd must be active** in the base image (unmasked): the installer
  without `--no-ntp` — as the Azure base jobs run — restarts it; in a
  container it just tracks the host clock.
* **xunit path**: `ipa-run-tests` derives `IPATEST_XUNIT_PATH` from `$PWD`
  *before* chdir-ing into the ipatests package dir; `run-base-tests.sh`
  uses `mkdir -p "$IPA_TESTS_LOGSDIR"` so the JUnit report lands at
  `/root/ipa-env/logs/nosetests.xml` (Azure-parity), and the CLI fetches it
  from there first (fallbacks: `/root/nosetests.xml`, package dir).
* **firewalld masking confirmed in the installer path**: the install log
  shows the installer detecting the masked firewalld and skipping its
  `--add-service` rules cleanly.

## 9. Risks and open questions

* **SELinux enforcing**: the current Azure containers run permissive only;
  PRCI's `nightly_*_selinux.yaml` need enforcing. Two options: (a) a
  `provider: external` VM lane for the enforcing preset — enforcing SELinux
  + systemd-in-container is exactly the part that does not survive
  containerization, and the attach design (§3.2) makes this a scheduling
  concern, not a new mechanism — or (b) investigate podman on a host with
  enforcing policy + unconfined container labels — the IPA processes inside
  the container would still be confined by the *host* policy, which may be
  sufficient for most of the `selinux` test classes. Decision in Phase 2.
* **FIPS**: userspace FIPS (`fips.py`) already works in containers;
  kernel-level FIPS needs a FIPS-validated runner class — same shape as the
  `windows` pool, added only if the suite grows tests that need it.
* **Windows for AD**: podman-on-WSL2 for Windows containers is workable but
  fragile; fallback is the 2–4 VM `windows` pool (much smaller than PRCI's
  AD farm, since Samba covers most of the suite).
* **`pytest_multihost` upstream**: (optionally) a podman-native host driver
  would be upstreamed; until then the `mh` fixture shim in `ipatests`
  absorbs it.
* **Install time floor**: `ipa-server install` (2–4 min) remains the
  per-env cost. Optional later optimization: a *pre-enrolled* master image
  variant (CA baked at image build, hostname rewritten at boot) for
  client-heavy classes — only safe for classes that never touch CA
  lifecycle; catalog marks eligibility. Expected to save ~50 % of nightly
  wall time; not on the critical path.

## Reuse summary (what survives)

| Existing piece | Fate |
| --- | --- |
| `pytest_ipa/integration` framework, `env_config`, `tasks.py`, `base.py` | **kept unchanged** |
| `ipa-run-tests`, `ipa-test-config`, log collection | kept (entrypoint + config print) |
| `Dockerfile.build.fedora` / `seccomp.json` / `wait-for-systemd.sh` | absorbed into `ci/images` + `freeipa-env` |
| `ipa-test-config-template.yaml` (Jinja multihost config) | generalized into `freeipa-env` output |
| Azure matrix YAML / `generate-matrix.py` | **replaced** by catalog + dynamic packing |
| PRCI definitions + `prci_checker.py` | **replaced** by catalog (same validation role, 1/20 the lines) |
| Beaker/PRCI infra | **retired** after Phase 3 |
