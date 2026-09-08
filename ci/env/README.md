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
image: freeipa-ci/full:44
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

## Notes

- The podman provider pins one network per env (10.89.0.0/24 +
  2001:db8:1::/64); one env per host in v1.
- `run` in base mode copies `scripts/run-base-tests.sh` into the master
  container and runs it there; the JUnit report is fetched back afterwards.
- Uninstall is part of the workflow (install → test → uninstall); the
  container is destroyed only by `down`, after uninstall completes.
