# Akamu ACME server integration

## Overview

FreeIPA already ships an ACME (RFC 8555) responder built into the Dogtag CA
subsystem (`pki-acme`, enabled automatically when the CA role is installed,
managed via `ipa-acme-manage`). Akamu (source: `acme-server`, upstream
`codeberg.org/freeipa/akamu`) is a separate, independently-developed ACME
server written in Rust with a much broader RFC 8555/8555-adjacent feature
set (ACME profiles, ARI, device-attestation-style token authorities, Merkle
Tree Certificate transparency, multi-CA support). It already ships
deliberate FreeIPA co-deployment support upstream (`contrib/demo/ipa/`,
`docs/src/user/deployment-ipa.md`): gssproxy/SPNEGO integration, an LDAP
profile source for Dogtag-format certificate profiles, and — most
importantly for this integration — a "Dogtag RA mode" where Akamu validates
ACME challenges itself but delegates actual certificate signing to an
existing Dogtag CA via its REST enrollment API.

This design integrates Akamu into FreeIPA the same way another external
service (Ahdapa, an OAuth2/OIDC IdP) was recently integrated: a FreeIPA-side
installer class deploys and configures the already-packaged Akamu server,
wires it into `ipa-server-install`/`ipa-replica-install`/`ipa-server-upgrade`,
and provisions the LDAP/Kerberos state Akamu needs to operate against this
IPA deployment.

Unlike Ahdapa, Akamu is **CA-adjacent**: it authenticates to Dogtag's CA REST
API with an agent-privileged TLS client certificate and can cause
certificates to be issued from IPA's CA. This changes several defaults
relative to the Ahdapa integration (see [Design](#design)).

## Use Cases

**UC1 — Fresh server install with CA.** An administrator runs
`ipa-server-install --setup-ca`. Akamu is installed and configured
automatically alongside the existing `pki-acme` responder, exposed at
`https://<fqdn>/akamu/directory`. Existing ACME clients pointed at
`https://<fqdn>/acme/directory` (Dogtag's responder) are unaffected.

**UC2 — Server install without CA, or with `--no-akamu`.** Akamu is not
installed. No Akamu-specific systemd unit, config, or LDAP state is created.

**UC3 — Replica install with `--setup-ca`.** Same as UC1, scoped to the
replica. A replica installed without `--setup-ca` never runs Akamu,
regardless of the `--no-akamu` flag.

**UC4 — Kerberos-authenticated host/service cert enrollment.** A host or
service with a Kerberos keytab requests a certificate from Akamu using only
its Kerberos identity (`GET /akamu/eab` via SPNEGO, then a normal ACME
`newAccount`/`finalize` with no http-01/dns-01 challenge), receiving a
certificate whose SAN is stamped with its own Kerberos principal. This is
the ACME-protocol analogue of what `certmonger`/`ipa-getcert` do today
against Dogtag directly.

**UC5 — Upgrade of an existing CA-enabled server.** `ipa-server-upgrade`
deploys Akamu onto a server that already has the CA role but predates this
feature, the same way `AhdapaInstance.upgrade_instance()` brings Ahdapa onto
pre-existing servers.

## How to Use

No new user-facing FreeIPA CLI/UI surface is added by this integration for
day-to-day ACME operations — Akamu is administered via its own `akamuctl`
tool (Kerberos-authenticated: `akamuctl login --gssapi`), the same way
Ahdapa is administered via `ahdapactl`. FreeIPA's role is limited to
install/config/upgrade/uninstall and to provisioning the LDAP/Kerberos
prerequisites Akamu needs.

- Install: `ipa-server-install --setup-ca` (Akamu deployed automatically
  unless `--no-akamu` is also given).
- Skip: `ipa-server-install --setup-ca --no-akamu`.
- Directory URL for ACME clients: `https://<fqdn>/akamu/directory`.
- Kerberos-bridged enrollment: `akamu-cli` (or any ACME client supporting
  EAB) against the same directory URL, using credentials obtained from
  `GET https://<fqdn>/akamu/eab` under a valid Kerberos ticket.

## Design

### Non-goals for this pass

- No FreeIPA Web UI changes. ACME is protocol/agent-driven; there is no
  interactive login flow analogous to Ahdapa's OIDC work to build.
- No wiring of Akamu's `[profiles.providers.ipa]` LDAP profile source.
  Akamu issues certificates through Dogtag's existing `acmeIPAServerCert`
  profile (the same profile `pki-acme` already uses), not a
  freshly-defined one.
- No cross-host CA discovery. Akamu is only installed where Dogtag is
  installed locally; it never proxies certificate requests to a CA on a
  different host.
- No SELinux policy authored here: Akamu ships its own (`contrib/selinux/
  akamu.te`/`.if`/`.fc`, likewise Ahdapa's `contrib/selinux/ahdapa.*`),
  installed by their respective RPMs, not by FreeIPA. It already covers
  the RA agent cert/key at `/var/lib/akamu/` via the dedicated
  `akamu_ra_cert_t` type and `akamu_manage_ra_cert(certmonger_t)` interface,
  so certmonger-driven renewal works under enforcing SELinux without any
  FreeIPA-side policy work. One real gap found and fixed upstream: neither
  `akamu.te` nor `ahdapa.te` granted the `map` permission on their own
  `*_var_lib_t` file type -- `manage_files_pattern()` predates that
  permission class -- which broke SQLite's mmap-based WAL/shared-memory
  access and crashed both services outright on a fresh enforcing-SELinux
  install, not just renewal.

### Topology

```
ACME client ─▶ IPA Apache (TLS, /akamu/*) ─▶ mod_proxy ─▶ Unix socket ─▶ akamu
                                                                           │
                                                        validates ACME challenges
                                                        itself (http-01/dns-01/
                                                        tls-alpn-01/EAB)
                                                                           │
                                                     mTLS (dedicated RA agent cert)
                                                                           ▼
                                                     Dogtag CA REST API (localhost:8443)
                                                     POST /ca/rest/certrequests
                                                     (signs with the existing IPA CA key)

Kerberos client ─▶ GET /akamu/eab (SPNEGO via gssproxy) ─▶ HKDF-derived EAB
                                                          ─▶ newAccount/finalize
                                                            ─▶ cert bound to caller's
                                                              own Kerberos principal
```

Akamu never becomes a second root of trust: it validates and orchestrates
ACME issuance, but Dogtag signs the certificate. This coexists with, rather
than replaces, the existing `pki-acme` responder — the two are reached at
different URL paths (`/acme` vs `/akamu`) since Apache already routes
`/acme` to Dogtag's Tomcat-hosted ACME webapp
(`install/share/ipa-pki-proxy.conf.template`).

### Install gating

Ahdapa is installed by default on every server (`--no-idp` to opt out)
because it has no CA-adjacent privileges. Akamu is different: it holds a
TLS client certificate that Dogtag recognizes as CA-agent-privileged. Per
discussion, Akamu still follows the **opt-out** pattern (installed by
default, `--no-akamu` to skip) for consistency with Ahdapa, but — unlike
Ahdapa — it is only ever installed on hosts that already have the CA role,
mirroring `cainstance.py`'s existing `minimum_acme_support()`/`setup_acme()`
gating for `pki-acme`. Concretely, `AkamuInstance.create_instance()` is
invoked as a step from `CAInstance` itself (alongside `setup_acme`), guarded
by `not options.no_akamu`, rather than unconditionally from
`server/install.py` the way `AhdapaInstance` is invoked today.

### RA agent identity and credential provisioning

Akamu's Dogtag signer authenticates to `/ca/rest/certrequests` with a TLS
client certificate. Dogtag's stock `AgentCertAuth` mechanism only recognizes
two **hardcoded** LDAP groups for this — `Certificate Manager Agents` and
`Registration Manager Agents` — the same groups the existing internal `ipara`
RA agent belongs to. There is no way to scope a cert-authenticated agent to
a bespoke lower-privilege group without customizing Dogtag's `CS.cfg`, which
is out of scope here.

Akamu therefore gets its own **dedicated identity** (separate from `ipara`,
independently revocable/auditable) that must still join those same two
groups:

1. Create LDAP user `uid=akamu-ra,ou=People,<basedn>`, `usertype=agentType`,
   member of `Certificate Manager Agents` and `Registration Manager Agents`
   (not `Security Domain Administrators` — `ipara` needs that for
   domain-level operations Akamu never performs).
2. Generate a keypair + CSR (`CN=Akamu RA`), submit it the same way
   `cainstance.py`'s `__request_ra_certificate()` does for `ipara`: a
   throwaway NSS DB, the `pki` Python client library, profile
   `caSubsystemCert` (`ipalib.constants.RA_AGENT_PROFILE`). Write the result
   to new dedicated PEM paths (`AKAMU_RA_AGENT_PEM`/`_KEY`, plain PEM,
   `0440`, `ipaapi` group — same permission model as `RA_AGENT_PEM`/`_KEY`).
3. Track renewal via `certmonger.start_tracking(..., storage='FILE')` with
   new pre/post renewal scripts modeled on
   `install/restart_scripts/renew_ra_cert{,_pre}.in`, resyncing the LDAP
   `userCertificate` attribute post-renewal the same way
   `cainstance.update_people_entry()` does for `ipara`.
4. Akamu's `[[ca]]`/`[ca.signer]` config points at these two PEM files,
   `url = https://<fqdn>:8443`, `dogtag_profile_id = "acmeIPAServerCert"`.

Open question for the implementation plan: `uid=akamu-ra` is a single
shared LDAP identity, but each CA-enabled replica needs its own local copy
of the RA agent PEM files (Akamu never reads them over the network). How
`ipara`'s `ra-agent.pem`/`.key` end up present on every CA replica today
(fresh per-replica issuance under the same shared uid vs. copying an
existing pair) needs to be traced during planning and the same mechanism
reused for `akamu-ra`, rather than assumed here.

### New files

| File | Purpose |
|---|---|
| `ipaserver/install/akamuinstance.py` | `AkamuInstance(SimpleServiceInstance)` — container/config/gssproxy/proxy steps, RA-agent provisioning, `_configure_grants()` (analogous to Ahdapa's `_configure_hbac()`) |
| `install/share/akamu.toml.template` | Unix-socket listener, `base_url=https://$FQDN/akamu`, `[[ca]] [ca.signer] type="dogtag"` pointing at localhost:8443 + the RA PEM paths, `dogtag_profile_id="acmeIPAServerCert"`, `[server.gssapi]`/`[admin.gssapi] gssproxy=true`, auto-generated `eab_master_secret` |
| `install/share/akamu-gssproxy.conf.template` | `[service/akamu]`, same shape as `ahdapa-gssproxy.conf.template`, `euid=akamu` |
| `install/share/ipa-akamu-proxy.conf.template` | Apache reverse proxy, `/akamu/` → Unix socket, same security-header pattern as `ipa-idp-proxy.conf.template` |
| `install/updates/79-akamu.update` | `cn=akamu` container + `Akamu IPA CA Read` privilege (`System: Read Certificate Profiles`) / `Akamu Services` role, same LDIF pattern as `78-ahdapa.update` |

New path constants in `ipaplatform/base/paths.py`: `AKAMU_CONF_DIR`,
`AKAMU_CONF`, `AKAMU_SOCKET`, `AKAMU_STATE_DIR`, `AKAMU_GSSPROXY_CONF`,
`AKAMUCTL`, `HTTPD_IPA_AKAMU_PROXY_CONF`, `AKAMU_RA_AGENT_PEM`/`_KEY`.

New service registration in `ipaserver/masters.py`:
`service_definition('akamu', 55, 'AKAMU')` — placed after CA (50), reflecting
the dependency.

## Implementation

### Dependencies

`freeipa.spec.in` already declares `pki-acme` as a conditional dependency
that only applies when `pki-ca` is present:
`Requires: (pki-acme >= %{pki_version} if pki-ca >= 10.10.0)`. Akamu follows
the identical pattern: `Requires: (akamu >= <ver> if pki-ca >= <ver>)`, so a
plain `ipa-server` install without the CA package never pulls in Akamu.
The same conditional also covers `akamu-client` (the `akamu-cli` ACME
protocol client used for UC4's Kerberos-authenticated enrollment) and
`akamu-webui` (the static assets `[server.webui].static_dir` points at,
served by akamu itself at `/akamu/ui/`) -- without these, the server
installs and runs, but there is no ACME client available and the
management web UI silently fails to come up.

### Backup and Restore

Two unrelated mechanisms both need to know about Akamu's files, and each
already does:

- **Uninstall-time restore** (`fstore`/sysrestore): `AkamuInstance.uninstall()`
  backs up `akamu.toml`, `akamu-gssproxy.conf`, and `ipa-akamu-proxy.conf`
  via `self.fstore` before removing Akamu, and restores (or removes, if none
  existed) whatever was there before install -- the same pattern
  `AhdapaInstance.uninstall()` uses. The RA agent PEM/key are *not* covered
  by this; like `ra-agent.pem`/`.key`, they are regenerated rather than
  restored on reinstall.
- **`ipa-backup`/`ipa-restore`** (disaster recovery): `AKAMU_STATE_DIR`
  (`/var/lib/akamu`) is backed up as a whole directory in `ipa_backup.py`'s
  `dirs`, covering the ACME account/order/cert CRDT database, the persisted
  `eab_master_secret`, and the RA agent PEM/key together -- these must stay
  consistent with each other and with the LDAP `uid=akamu-ra` entry restored
  in the same snapshot, so a directory-level backup takes them as one unit
  rather than special-casing the RA agent cert like `ra-agent.pem`/`.key`
  (which piggyback on `VAR_LIB_IPA` already being backed up whole).
  `akamu.toml`, `20-akamu.conf`, and `ipa-akamu-proxy.conf` are listed
  individually in `files`, matching every other single-purpose config file
  in that list. `ipa_restore.py` needs no Akamu-specific code: it extracts
  the archive generically and already restarts gssproxy and `ipactl`-managed
  services (which include `akamu`, registered in `ipaserver/masters.py`)
  after restore.

### CLI flag

`--no-akamu` (not `--no-acme*`, to avoid clashing with existing
`ipa-acme-manage`/`pki-acme` terminology), `enroll_only`, added to
`ServerInstallInterface` next to `--no-idp`.

### Wiring into install/replica/upgrade

- `server/install.py`: no unconditional call (unlike Ahdapa); instead
  `CAInstance`'s own install flow gains an `AkamuInstance` step next to
  `setup_acme`, gated on `not options.no_akamu`.
- `replicainstall.py`: same guard, additionally conditioned on the replica
  actually installing the CA role.
- `upgrade.py`: calls `AkamuInstance.upgrade_instance()` unconditionally;
  it self-guards via sysupgrade state plus a local CA-presence check, the
  same idiom as `AhdapaInstance.upgrade_instance()`.

## Feature Management

### UI

None. See [Non-goals](#non-goals-for-this-pass).

### CLI

| Command | Options |
| --- | --- |
| `ipa-server-install` / `ipa-replica-install` | `--no-akamu` (skip Akamu even when `--setup-ca` is given) |
| `akamuctl` | Akamu's own admin CLI (Kerberos or mTLS); not a new FreeIPA command |

### Configuration

No new `ipa config-mod` options. Akamu's own `/etc/akamu/config.toml` is
entirely installer-rendered, the same way `/etc/ahdapa/ahdapa.toml` is.

## Upgrade

`ipa-server-upgrade` brings Akamu onto any server that already has the CA
role but predates this feature (UC5), mirroring
`AhdapaInstance.upgrade_instance()`.

## Test plan

No live install/upgrade is possible in the development environment this
design was authored in; verification is static only:

- `py_compile` on the new installer module.
- Grep-verify the `System: Read Certificate Profiles` permission name
  referenced by the new LDIF still exists verbatim in `ipaserver/plugins/*.py`
  before relying on it (the Ahdapa integration caught exactly this kind of
  drift against a permission name Ahdapa's own docs got wrong).
- LDIF stanza sanity check on `79-akamu.update` (matching `default:`/`add:`
  pairs, no malformed action tokens).
- Diff the new templates against Akamu's own `contrib/demo/ipa/*` reference
  files to confirm no drift from the upstream-documented configuration.

Actual integration test scenarios (deferred to CI, not authored here):
fresh install with `--setup-ca` exposes `/akamu/directory`; install with
`--no-akamu` does not; install without `--setup-ca` does not; Kerberos EAB
enrollment issues a cert with the correct principal SAN; upgrade path
deploys Akamu onto a pre-existing CA-enabled server; uninstall cleanly
removes config and RA agent state.

## Troubleshooting and debugging

- Config: `/etc/akamu/config.toml` (rendered, not hand-edited).
- Logs: `journalctl -u akamu` (dedicated `journald@akamu` namespace,
  structured `AKAMU_EVENT_TYPE`/`AKAMU_OUTCOME` fields per Akamu's own
  conventions).
- LDAP state: `cn=akamu,cn=ipa,cn=etc,$SUFFIX` container,
  `uid=akamu-ra,ou=People,$SUFFIX` RA agent entry, `Akamu Services` role.
- RA agent cert renewal: tracked by `certmonger`, same
  `getcert list -f /var/lib/ipa/akamu-ra.pem`-style inspection as the
  existing `ra-agent.pem`.
- If `/akamu/directory` 404s: check `HTTPD_IPA_AKAMU_PROXY_CONF` is present
  and the `akamu` systemd unit/socket are active (same "proxy conf presence
  as availability probe" idiom Ahdapa's `login_oidc._serve_config` uses).
