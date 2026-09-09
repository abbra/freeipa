# freeipa-env — CI environment provisioner

`freeipa-env` spawns (or attaches to) FreeIPA test environments from a single
declarative file and drives the install → test → uninstall workflow. See
`doc/designs/ci_modernization.md` for the design.

```
freeipa-env up   ENV.YAML    create (or attach) the environment
freeipa-env run  ENV.YAML    run the test workflow (install, tests, uninstall)
freeipa-env down ENV.YAML    collect journal/logs, then tear down
freeipa-env show ENV.YAML    print environment state
freeipa-env logs ENV.YAML    categorize and retrieve collected logs
freeipa-env migrate PRCI.YAML  generate presets from a PRCI definition
freeipa-env queue run QUEUE.YAML --runner USER@HOST [...]   # run a queue
freeipa-env queue generate PRCI.YAML -o QUEUE.YAML          # PRCI-order queue
```

Common options: `--workdir DIR` (state/logs dir, default `./<env-name>.env`),
`--tool podman`, `--seccomp FILE` (podman), `--strict` (external: fail on
unreachable ports), `--ssh-key FILE` (external: root SSH key).

## Env file

```yaml
name: base-xmlrpc
provider: podman            # or: external (pre-created systems)
domain: ipa.test
dist: 44
image: freeipa-current      # build channel; the provider resolves the
                            # concrete image (per-host image: overrides)
hosts:
  - {role: master, name: master1}
  - {role: client, name: client1}
resources:                  # defaults mirror Azure variables-fedora.yml
  master: {memory: 1800m, memory-swap: 2500m}
  client: {memory: 512m, memory-swap: 1024m}
run:
  mode: base                # or: integration
  setup_dns: true
  setup_kra: true
  forwarder: 8.8.8.8        # explicit; else --auto-forwarders
  tests: [test_xmlrpc]
  ignore: [test_xmlrpc/test_dns_plugin.py]
```

External (pre-created) systems: set `provider: external` (or just give a
host an `address:`). Hosts then need `name`/`role`/`address` (plus optional
`user`, `port`, `image`, `os`). `up` only validates reachability/SSH/
hostname/distribution/IPA state and never mutates; `run` is unchanged; `down`
collects logs without destroying anything. Authenticate with `--ssh-key`
(default `~/.ssh/id_rsa`).

## Artifacts

`run` writes:

- `<workdir>/nosetests.xml` — JUnit XML from `ipa-run-tests --with-xunit`
- `<workdir>/logs/` — per-host journal + `/var/log/ipa*` tarballs, install
  and test run logs
- `IPA_TESTS_LOGSDIR` (in-container) — per-test logs from the framework

## Log analysis (`logs`)

`freeipa-env logs` turns the collected artifacts into a triage view for
resolving CI issues. With no `--category` it prints a per-category summary
(source count + interesting-line count per category);
`--category NAME` (repeatable, or `all`) prints the matching lines plus a
tail per source file:

```
freeipa-env logs ENV.YAML                        # category summary
freeipa-env logs ENV.YAML --category tests       # failed tests, grouped by module
freeipa-env logs ENV.YAML --category ds --category httpd --category kra  # several at once
freeipa-env logs ENV.YAML --category tests --json  # machine-readable summary
freeipa-env logs --workdir DIR --category system --pattern 'OOM|segfault'
```

Categories (each with a sensible default line filter, overridable via
`--pattern REX`):

| category    | source                                   |
|-------------|------------------------------------------|
| `tests`     | `nosetests.xml` (JUnit): totals + failed/errored tests with messages and traceback tails, grouped by module |
| `run`       | `logs/run.log` — the streamed install/test/uninstall console (FAILED/ERROR/summary lines) |
| `install`   | `ipaserver-install.log` (ERROR/WARNING) |
| `uninstall` | `ipaserver-uninstall.log` (ERROR/WARNING) |
| `ds`        | 389-ds `errors` log (`- ERR -`/`- CRIT -` lines) |
| `httpd`     | `error_log` — IPA framework errors + Python tracebacks (debug noise excluded) |
| `kra` / `ca`| pki instance logs (`pki-tomcat/{kra,ca}` + spawn logs) |
| `kdc`       | `krb5kdc.log` (error/crit/fatal) |
| `samba`     | `/var/log/samba` (AD trust) |
| `dns`       | BIND runtime logs (`named.run`) |
| `ipa`       | per-operation logs under `/var/log/ipa/` (ERROR/CRITICAL) |
| `system`    | boot journal: failed units, OOM, segfaults, watchdogs |

Useful flags: `--pattern REX` (override a category's line filter),
`--lines N` (matched lines per file, default 30), `--tail N` (0 disables),
`--all` (print whole files unfiltered), `--host NAME`, `--json` (summary
for scripting), `--refresh` (re-collect logs from a still-running
environment before analyzing; a failed collection never clobbers existing
artifacts). Daemon tarballs are extracted selectively into
`<workdir>/logs/extracted/<host>/` and cached by mtime+size, so repeated
calls are instant.

## Presets

- `presets/base-xmlrpc.yaml` — the Azure **xmlrpc** job (1 master,
  DNS+KRA, `test_xmlrpc` minus `test_dns_plugin.py`).
- `presets/external-smoke.yaml` — external-provider smoke template.
- `presets/azure/` — one preset per Azure CI job (the full recreation of
  `ipatests/azure/azure_definitions/{base,gating}-fedora.yml`):

| preset (`presets/azure/`) | Azure job | hosts | suite |
|---|---|---|---|
| `base.yaml` | base | master | unit tests + `test_xmlrpc/test_dns_plugin.py` (`-k 'not test_dns_soa'`) |
| `kerberos-flags.yaml` | kerberos_flags | master, client | `test_kerberos_flags.py` |
| `forced-client-reenrollment.yaml` | forced_client_reenrollment | master, replica, client | `test_forced_client_reenrollment.py` |
| `external-ca-install.yaml` | external_ca_ExternalCAInstall | master | `test_external_ca.py::TestExternalCAInstall` |
| `simple-replication.yaml` | simple_replication | master, replica | `test_simple_replication.py` |
| `service-permissions.yaml` | service_permissions | master | `test_service_permissions.py` |
| `sudo.yaml` | sudo | master, client | `test_sudo.py` (deselects `TestSudo_Functional`) |
| `external-ca.yaml` | external_ca_ExternalCA | master, replica, client | `test_external_ca.py::TestExternalCA` |
| `topologies-testconfig.yaml` | topologies_and_testconfig | master | `test_topologies.py`, `test_testconfig.py` (no installs) |
| `external-ca-constraints.yaml` | external_ca_ExternalCAConstraints | master, client | `test_external_ca.py::TestExternalCAConstraints` |
| `membermanager.yaml` | membermanager | master | `test_membermanager.py` |
| `netgroup.yaml` | netgroup | master | `test_netgroup.py` |
| `external-ca-profile-scenarios.yaml` | external_ca_ExternalCAProfileScenarios | master | `test_external_ca.py::TestExternalCAProfileScenarios` |
| `caless-to-ca-full.yaml` | ServerReplicaCALessToCAFull | master, replica | `test_caless.py::TestServerReplicaCALessToCAFull` |
| `external-ca-self-external-self.yaml` | external_ca_SelfExternalSelf | master | `test_external_ca.py::TestSelfExternalSelf` |

The `xmlrpc` job is `presets/base-xmlrpc.yaml`. Base-pipeline jobs run in
`mode: base` (run-base-tests.sh: install → test → uninstall); gating jobs
run in `mode: integration`, where the framework performs the per-class
install/uninstall from the multihost config. Per-host memory limits mirror
the Azure definitions.

## Migrated PRCI definitions (`migrate`)

`freeipa-env migrate ipatests/prci_definitions/<def>.yaml` converts a PRCI
definition into freeipa-env presets (one per job) under
`presets/prci/<def>/`, with a `MIGRATED.md` report. Regenerate after PRCI
definition changes; options: `-o DIR`, `--jobs NAME` (substring filter).

`presets/prci/` currently contains all 11 PRCI definitions
(1301 presets):

dir | PRCI file | presets
---|---|---
`gating/` | `gating.yaml` | 31
`nightly-latest/` | `nightly_latest.yaml` | 185
`nightly-latest-389ds/` | `nightly_latest_389ds.yaml` | 48
`nightly-latest-pki/` | `nightly_latest_pki.yaml` | 91
`nightly-latest-selinux/` | `nightly_latest_selinux.yaml` | 185
`nightly-latest-sssd/` | `nightly_latest_sssd.yaml` | 20
`nightly-latest-testing/` | `nightly_latest_testing.yaml` | 185
`nightly-latest-testing-selinux/` | `nightly_latest_testing_selinux.yaml` | 185
`nightly-previous/` | `nightly_previous.yaml` | 185
`nightly-rawhide/` | `nightly_rawhide.yaml` | 185
`temp-commit/` | `temp_commit.yaml` | 1

Mapping rules:

- **topology → hosts**: `ipaserver` → 1 master (base mode);
  `master[_Nrepl]_Mclient` → master/replica/client hosts (integration
  mode when >1 IPA host); AD tokens `ad` / `adroot_adchild_adtree` add
  external AD hosts with roles `ad`, `ad_subdomain`, `ad_treedomain`.
- **topology memory → per-role limits**, split evenly (rounded to 100 MiB,
  floor 512 MiB) — PRCI numbers are per-topology totals.
- **test_suite → `run.tests`** (space-separated list preserved).
- **class Build** → skipped (the `freeipa-ci` image pipeline replaces it);
  **ipa_ipa_trust** topologies → skipped (two IPA domains; the preset
  model supports one IPA domain plus AD domains).
- **RunWebuiTests** → `mode: base` with a NOTE: PRCI provisions a browser
  + selenium; `freeipa-ci/full` does not include them, so those presets
  will not pass as-is.

**AD hosts are external.** PRCI provisions the AD DCs itself; here each AD
host is an `address` placeholder (RFC 5737) plus a placeholder FQDN — edit
both before `freeipa-env up` (the preset footer lists every EDIT ME). The
IPA containers resolve the AD FQDNs via `/etc/hosts` entries written at
`up`; trust setup itself (AD admin credentials, DNS) is done by the tests
via `ad_admin_name`/`ad_admin_password` (defaults `Administrator`/
`Secret123`). A Samba AD DC (or Windows) reachable over SSH for log
collection works; Windows-only DCs need `user` adjusted.

## Run queues and the supervisor (`queue`)

Queues run ordered preset lists on a pool of **pre-allocated runners**
(hosts with ssh + podman + systemd, e.g. the lab VMs) — the replacement
for PRCI's per-PR job scheduling. Queue files live in `ci/queues/`:

* `azure.yaml` — the 16 Azure CI jobs (Azure ran them in parallel; the
  queue order is conventional);
* one per PRCI definition, named like the preset dirs
  (`gating.yaml`, `nightly-latest.yaml`, …) — each in the PRCI
  definition's job order, generated with `freeipa-env queue generate`
  (regenerate after PRCI definition changes).

Queue format: an ordered `jobs:` list of preset paths (relative to
`ci/env/`), a directory entry (trailing `/`) expanding to all presets in
it sorted, or per-job dicts (`preset`/`dir` + `note`).

**Image references are build channels, never builds.** A preset pins
no build — it names a *channel*: `image: freeipa-current` (the current
release's newest build), `freeipa-next` (the next release, PRCI
`fedora-rawhide`) or `freeipa-previous` (the previous release). This
mirrors PRCI, where each definition file references one build generation
and every job in it uses that one build. `ci/images/build.sh --channel
NAME` tags each build with the channel tag (`freeipa-ci/full:<channel>`)
alongside the immutable provenance tag (`freeipa-ci/full:<dist>-<sha>`).

Resolving a channel to a concrete image on a given host is a **provider
task**: the podman provider maps the channel to its podman tag and
resolves it against the local image store at `up` time (and
`freeipa-env resolve ENV.YAML` does just that one thing, printing
`<ref> <concrete> <image_id>`); the external provider ignores it —
external hosts run their own IPA. A preset may also name an explicit
image reference (passed through unchanged) if you need to pin a build.

```
freeipa-env queue run ci/queues/gating.yaml \
    --runner root@192.168.122.215 --runner root@192.168.122.216 \
    [--jobs NAME ...] [--limit N] [--dry-run] [--keep-on-failure] \
    [--job-timeout SECS] [--outdir DIR] [--no-bootstrap] [--ssh-key FILE]
```

The supervisor, per run:

1. validates every preset (parse + existence),
2. checks each runner (ssh + podman) and rsyncs the local `ci/` tree to
   `--remote-ci` (default `/root/freeipa-ci/ci`),
3. asks each runner's provider to resolve every distinct preset's image
   references (remote `freeipa-env resolve`; fail fast on a missing
   image, before any job starts; resolutions are recorded per runner in
   `summary.md`),
4. schedules: each runner pulls the next job from the front of the list,
   one job at a time — `up` → `run` → `down`, under a per-job remote
   `timeout` (default 4 h), workdir `/root/jobs/<job-key>` per job.
5. writes `summary.tsv` / `summary.md` + per-job transcripts to `--outdir`
   (default `./<queue>.queue`); exit code 0 only when every job passed.

Ordering semantics: with one runner the jobs run exactly in queue order;
with N runners each runner's subsequence preserves queue order (FIFO
dequeue) — the same shape as a PRCI run queue spread over a pool of VMs.
`--keep-on-failure` skips `down` on a failed job so the environment stays
on the runner for `freeipa-env logs --refresh`-style triage (remember to
`down` manually before reusing the runner's capacity).

## Notes

- The podman provider pins one network per env (10.89.0.0/24 +
  2001:db8:1::/64); one env per host in v1.
- `run` in base mode copies `scripts/run-base-tests.sh` into the master
  container and runs it there; the JUnit report is fetched back afterwards.
- Uninstall is part of the workflow (install → test → uninstall); the
  container is destroyed only by `down`, after uninstall completes.
