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
installed by FreeIPA: no `/etc/akamu/config.toml`, no gssproxy or httpd
proxy drop-in, no `cn=akamu` LDAP container, and no installer-managed
`akamu` service. Without the CA role the `akamu` RPMs are not even pulled
in; with `--no-akamu` they still are (the package dependency is conditional
on `pki-ca`, not on the flag) — only the FreeIPA-side deployment is
skipped.

**UC3 — Replica install with `--setup-ca`.** Same as UC1, scoped to the
replica. A replica installed without `--setup-ca` never runs Akamu,
regardless of the `--no-akamu` flag. The replica does not issue its own RA
agent certificate: it imports the shared `akamu-ra` PEM pair from the CA
renewal master over Custodia (see
[RA agent identity and credential provisioning](#ra-agent-identity-and-credential-provisioning)).

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
- No SELinux policy authored here: FreeIPA's own policy sources
  (`selinux/ipa.te`/`.if`/`.fc`) gained no Akamu rules, and none were
  needed. Akamu ships its policy in its own upstream repository
  (`contrib/selinux/akamu.te`/`.if`/`.fc`, likewise Ahdapa's
  `contrib/selinux/ahdapa.*`), installed by their respective RPMs. It already covers
  the RA agent cert/key at `/var/lib/akamu/` via the dedicated
  `akamu_ra_cert_t` type and `akamu_manage_ra_cert(certmonger_t)` interface,
  so certmonger-driven renewal works under enforcing SELinux without any
  FreeIPA-side policy work. One real gap was found and fixed upstream during
  planning: neither
  `akamu.te` nor `ahdapa.te` granted the `map` permission on their own
  `*_var_lib_t` file type -- `manage_files_pattern()` predates that
  permission class -- which broke SQLite's mmap-based WAL/shared-memory
  access and crashed both services outright on a fresh enforcing-SELinux
  install, not just renewal. (Upstream-side claim; not checkable from this
  repository.)

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
                                                     Dogtag CA REST API (<fqdn>:8443)
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
Ahdapa — it is only ever deployed on hosts that install the CA role. The
gate is not `cainstance.py`'s `minimum_acme_support()`/`setup_acme()`
version check for `pki-acme`; it is simply the CA-role condition at each
call site.

The work is split in two halves, because they have different prerequisites:

- The **RA agent identity and certificate** are provisioned from inside
  `CAInstance.configure_instance()`. The CA installer — `ca.install_step_0()`,
  reached directly from `server/install.py:968` and through `ca.install()`
  from `replicainstall.py:1442` — passes
  `setup_akamu=not options.no_akamu` (`ipaserver/install/ca.py:644`), and
  `cainstance.py:530-536` then schedules either "requesting Akamu RA
  certificate from CA" (`__request_akamu_ra_certificate`, non-clone) or
  "Importing Akamu RA key" (`__import_akamu_ra_key`, clone + promote),
  right after the `ipara` steps and before "configure certificate renewals".
  Both are skipped when `paths.AKAMU_RA_AGENT_PEM` already exists.
- The **Akamu service itself** (`AkamuInstance.configure_instance()`, which
  ends by calling the inherited `create_instance(gensvc_name='AKAMU')`) is
  invoked from `server/install.py` and `server/replicainstall.py`, *not*
  from `CAInstance`: it needs `HTTP_KEYTAB`, httpd and gssproxy, none of
  which exist yet while the CA is being configured. In `install.py:1022` it
  runs after `ds.apply_updates()` under `if setup_ca and not
  options.no_akamu`; in `replicainstall.py:1444` under `if ca_enabled and
  options.setup_ca and not options.no_akamu`, deliberately *after*
  `ca.install()` so the RA PEM pair is already materialized.

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
   domain-level operations Akamu never performs) — `akamuinstance._create_akamu_ra_agent()`,
   mirroring `cainstance.CAInstance.__create_ca_agent()` for `ipara`
   (`cainstance.py:1030-1068`), including the `description` marker
   `2;<serial>;<CA subject>;<agent subject>` that the renewal helper matches
   on.
2. Generate a keypair + CSR (`CN=Akamu RA` under the CA's subject base, key
   type/strength from `api.env.key_type_size`) in a throwaway NSS DB and
   submit it with the `pki` Python client library, profile
   `caSubsystemCert` (`ipalib.constants.RA_AGENT_PROFILE`), i.e. through the
   same `certs.CertDB.pki_issue_ra_certificate()` helper
   `cainstance.py`'s `__request_ra_certificate()` uses for `ipara` — except
   that the enrollment is authenticated with the **existing `ipara` RA agent
   pair** (`client_certfile=paths.RA_AGENT_PEM`,
   `client_keyfile=paths.RA_AGENT_KEY`, `akamuinstance.py:115-118`) instead
   of unsealing Dogtag's admin `ca-agent.p12` with the DM password.
   `AgentCertAuth` authorizes the `Certificate Manager Agents` group, which
   both `ipara` and `akamu-ra` belong to, so the ipara agent may enroll the
   profile; this also drops the DM-password dependency, which is not
   available on the upgrade path (`certs.py:825-844`). The private key is
   exported through a transient PKCS #12 protected by a freshly generated
   random password and written out with `certs.install_key_from_p12()`.
3. Write the pair to the dedicated paths `AKAMU_RA_AGENT_PEM` =
   `/var/lib/akamu/akamu-ra-agent.pem` and `AKAMU_RA_AGENT_KEY` =
   `/var/lib/akamu/akamu-ra-agent.key`, owned `akamu:akamu`, mode `0400`
   (`_set_akamu_ra_cert_perms()`). This deliberately differs from
   `RA_AGENT_PEM`/`_KEY` (`0440`, group `ipaapi`): the Akamu pair is read
   only by the `akamu` daemon itself, never by IPA's Python code.
4. Track renewal via `certmonger.start_tracking(..., storage='FILE')`
   (`akamuinstance.configure_agent_renewal()`, CA
   `ipalib.constants.RENEWAL_CA_NAME`, profile `caSubsystemCert`) with the
   pre/post scripts `install/restart_scripts/renew_akamu_ra_cert{,_pre}.in`,
   modelled on `renew_ra_cert{,_pre}.in`: the post script re-loads the
   renewed certificate into the LDAP entry through
   `cainstance.update_people_entry()`, guarded by `ca.is_renewal_master()`
   exactly as the `ipara` script does.
5. Akamu's `[[ca]]`/`[ca.signer]` config points at these two files as
   `ra_cert_file`/`ra_key_file`, with `url = "https://<fqdn>:8443"`,
   `ca_cert_file = $IPA_CA_CRT` and `profile_id = "acmeIPAServerCert"`.

Per-replica distribution (the draft's open question, now resolved):
`uid=akamu-ra` is a single shared LDAP identity, and the PEM pair is shared
too — only the first (non-clone) CA server ever issues it
(`akamuinstance.request_ra_certificate()` runs from the non-clone branch of
the CA step). Every other CA-enabled host obtains a byte-identical copy of
the same cert+key over Custodia — from the CA renewal master on the upgrade
path, and from the CA peer it was cloned from (`CustodiaModes.CA_PEER`,
`replicainstall.py:1428-1432`) on the replica-install path — which is the
mechanism `ipara`'s `ra-agent.pem`/`.key` already use on promoted replicas
(`cainstance.import_ra_key()` → `custodia.import_ra_key()`):

- `ipaserver/secrets/store.py:180-184` registers an `akamu-ra` PEM handler
  running `install/custodia/ipa-custodia-akamu-ra-agent`, whose
  `akamu_ra_agent_parser()` (`ipaserver/secrets/handlers/pemfile.py:129-136`)
  points at `AKAMU_RA_AGENT_PEM`/`_KEY` on the serving host.
- `CustodiaInstance.import_akamu_ra_key()` (`custodiainstance.py:201-203`)
  fetches the key `akamu-ra/akamu` from that peer;
  `akamuinstance.import_ra_key()` wraps it with state-dir creation, the
  `akamu:akamu` `0400` permission reset and `configure_agent_renewal()`, so
  the receiving host tracks its own local copy.
- Call sites: `CAInstance.__import_akamu_ra_key` (replica install with
  `--setup-ca`, which reaches `ca.install()` with `promote=True`) and
  `AkamuInstance.upgrade_instance()` (upgrade of a CA host with no local
  pair), which builds a `CustodiaInstance` against
  `cainstance.get_ca_renewal_master_fqdn()` when this host is not the
  renewal master itself. If no peer can be resolved the deployment is
  deferred with a warning to the next upgrade run rather than issuing a
  second, conflicting certificate.

### New files

| File | Purpose |
|---|---|
| `ipaserver/install/akamuinstance.py` | module-level RA-agent provisioning (`request_ra_certificate()`, `_create_akamu_ra_agent()`, `_set_akamu_ra_cert_perms()`, `configure_agent_renewal()`, `import_ra_key()`) plus `AkamuInstance(SimpleServiceInstance)`: the steps "creating akamu container", "granting akamu service role membership", "configuring akamu", "configuring gssproxy for akamu", "configuring httpd proxy for akamu", "granting httpd access to the akamu socket" (`_configure_socket_group()`, `usermod -a -G akamu httpd`), then start/enable and an httpd reload once `AKAMU_SOCKET` is listening. `_configure_grants()` adds this host's `HTTP/<fqdn>@<realm>` principal to the `Akamu Services` role — the FreeIPA-side counterpart of Ahdapa's `_configure_hbac()`, which instead drives `ahdapactl` |
| `install/share/akamu.toml.template` | `listen_addr = "unix:$AKAMU_SOCKET"`, `base_url = "https://$FQDN/akamu"`, `[database] url = "sqlite://$AKAMU_STATE_DIR/akamu.db"`, `[[ca]] id = "ipa"` with `cert_file`/`crl_url`/`ocsp_url`, `[ca.signer] type = "dogtag"` pointing at `https://$FQDN:8443` with `ra_cert_file`/`ra_key_file`/`ca_cert_file`/`profile_id = "acmeIPAServerCert"`, `[server] validate_dnssec` + `eab_master_secret`, `[server.gssapi]`/`[admin.gssapi] gssproxy = true`, `[server.webui] static_dir = "$AKAMU_WEBUI_DIR"`, `[admin] bootstrap_operator_gssapi_principal = "admin@$REALM"` |
| `install/share/akamu-gssproxy.conf.template` | `[service/akamu]` with `mechs = krb5`, `cred_store = keytab:$HTTP_KEYTAB`, `cred_usage = accept`, `euid = $AKAMU_USER` (rendered as the numeric uid). Deliberately **not** the `ahdapa-gssproxy.conf.template` shape: `client_keytab`, `allow_protocol_transition` and `allow_constrained_delegation` are only needed for Akamu's `[profiles.providers.ipa]` LDAP profile source (S4U2Self/S4U2Proxy to bind to `o=ipaca`), which this integration does not enable — SPNEGO acceptance for `/akamu/eab` and admin GSSAPI is all that is required |
| `install/share/ipa-akamu-proxy.conf.template` | Apache reverse proxy, `/akamu/` → `unix:$AKAMU_SOCKET\|http://akamu-local/`, same security-header and in-`<Location>` cookie-rewrite pattern as `ipa-idp-proxy.conf.template` (the two confs both rewrite from `/`, so the directives must stay scoped) |
| `install/updates/79-akamu.update` | `cn=akamu,cn=ipa,cn=etc,$SUFFIX` container, `Akamu Services` role, `Akamu IPA CA Read` privilege, and the grant of the existing `System: Read Certificate Profiles` permission to it; role membership is granted from Python, not LDIF. Same LDIF pattern as `78-ahdapa.update` |
| `install/restart_scripts/renew_akamu_ra_cert{,_pre}.in` | certmonger pre/post renewal hooks for the Akamu RA pair (renewal lock, then `update_people_entry()` on the CA renewal master) |
| `install/custodia/ipa-custodia-akamu-ra-agent.in` | Custodia PEM handler serving `AKAMU_RA_AGENT_PEM`/`_KEY` to other CA hosts |

All of these are registered in the corresponding `Makefile.am`
(`install/share/Makefile.am:37-38,104`, `install/updates/Makefile.am:75`,
`install/restart_scripts/Makefile.am:12-13,24-25`,
`install/custodia/Makefile.am:9,17`).

New path constants in `ipaplatform/base/paths.py:443-454`: `AKAMU_CONF_DIR`
(`/etc/akamu`), `AKAMU_CONF` (`/etc/akamu/config.toml`), `AKAMU_STATE_DIR`
(`/var/lib/akamu`), `AKAMU_EAB_MASTER_SECRET`
(`/var/lib/akamu/eab_master_secret`), `AKAMU_RA_AGENT_PEM`/`_KEY`
(`/var/lib/akamu/akamu-ra-agent.pem`/`.key`), `AKAMU_SOCKET_DIR`/`AKAMU_SOCKET`
(`/run/akamu/akamu.sock`), `AKAMU_GSSPROXY_CONF` (`/etc/gssproxy/20-akamu.conf`),
`AKAMU_WEBUI_DIR` (`/usr/share/akamu/webui`), `AKAMUCTL` (`/usr/bin/akamuctl`),
`HTTPD_IPA_AKAMU_PROXY_CONF` (`/etc/httpd/conf.d/ipa-akamu-proxy.conf`).

New service registration in `ipaserver/masters.py:44`:
`service_definition('akamu', 55, 'AKAMU')` — placed after CA (50) and KRA
(51), reflecting the dependency. The `akamu` systemd unit/socket themselves
ship with the Akamu package; FreeIPA only starts, enables and reloads them
through this registration and `SimpleServiceInstance`.

## Implementation

### Dependencies

`freeipa.spec.in` already declares `pki-acme` as a conditional dependency
that only applies when `pki-ca` is present:
`Requires: (pki-acme >= %{pki_version} if pki-ca >= 10.10.0)`. Akamu follows
the same conditional shape, currently with no version constraint of its own
(`freeipa.spec.in:520-522`):
`Requires: (akamu if pki-ca >= 10.10.0)`,
`Requires: (akamu-client if pki-ca >= 10.10.0)`,
`Requires: (akamu-webui if pki-ca >= 10.10.0)`, so a
plain `ipa-server` install without the CA package never pulls in Akamu.
The same conditional also covers `akamu-client` (the `akamu-cli` ACME
protocol client used for UC4's Kerberos-authenticated enrollment) and
`akamu-webui` (the static assets `[server.webui].static_dir` points at,
served by akamu itself at `/akamu/ui/`) -- without these, the server
installs and runs, but there is no ACME client available and the
management web UI silently fails to come up.

This is a package-level dependency, not the installer gate: `--no-akamu`
suppresses the FreeIPA-side configuration only, the `akamu` RPMs are still
installed whenever `pki-ca` is present.

### Backup and Restore

Two unrelated mechanisms both need to know about Akamu's files, and each
already does:

- **Uninstall-time restore** (`fstore`/sysrestore): `AkamuInstance.uninstall()`
  backs up `paths.AKAMU_CONF` (`/etc/akamu/config.toml`),
  `paths.AKAMU_GSSPROXY_CONF` (`/etc/gssproxy/20-akamu.conf`) and
  `paths.HTTPD_IPA_AKAMU_PROXY_CONF` in `self.fstore` as each is written,
  then restores (or removes, if none existed) whatever was there before
  install -- the same pattern `AhdapaInstance.uninstall()` uses. It also
  stops certmonger tracking of and then deletes `AKAMU_RA_AGENT_PEM`/`_KEY`
  outright: like `ra-agent.pem`/`.key` they are never fstore-backed, and
  are regenerated rather than restored on reinstall. Finally it clears the
  `sysupgrade` `akamu/installed` state. `server/install.py:1300` calls it
  next to `AhdapaInstance.uninstall()`.
- **`ipa-backup`/`ipa-restore`** (disaster recovery): `AKAMU_STATE_DIR`
  (`/var/lib/akamu`) is backed up as a whole directory in `ipa_backup.py:123`'s
  `dirs`, covering the Akamu SQLite database (`akamu.db`), the persisted
  `eab_master_secret`, and the RA agent PEM/key together -- these must stay
  consistent with each other and with the LDAP `uid=akamu-ra` entry restored
  in the same snapshot, so a directory-level backup takes them as one unit
  rather than special-casing the RA agent cert like `ra-agent.pem`/`.key`
  (which piggyback on `VAR_LIB_IPA` already being backed up whole).
  `AKAMU_CONF`, `AKAMU_GSSPROXY_CONF` and `HTTPD_IPA_AKAMU_PROXY_CONF` are
  listed individually in `files` (`ipa_backup.py:204-206`), matching every
  other single-purpose config file
  in that list. `ipa_restore.py` needs no Akamu-specific code: it extracts
  the archive generically and already restarts gssproxy and `ipactl`-managed
  services (which include `akamu`, registered in `ipaserver/masters.py`)
  after restore.

### CLI flag

`--no-akamu` (not `--no-acme*`, to avoid clashing with existing
`ipa-acme-manage`/`pki-acme` terminology), `enroll_only`, added to
`ServerInstallInterface` next to `--no-idp` (`ipaserver/install/server/__init__.py:384-388`,
description "Do not configure the integrated ACME RA (akamu)"). It is read
at three points: `ca.py:644` (whether the CA configures the Akamu RA agent),
`server/install.py:1022` and `server/replicainstall.py:1444` (whether the
Akamu service itself is deployed). `ipa-server-upgrade` has no equivalent
flag: it follows whatever the host already has, and skips Akamu entirely on
a host without a locally configured CA.

### Wiring into install/replica/upgrade

- `server/install.py`: no unconditional call (unlike Ahdapa). The RA agent
  half runs inside the CA's own step list; the service half is a plain
  `if setup_ca and not options.no_akamu:` block after `ds.apply_updates()`
  and the KDC restart, calling `AkamuInstance(fstore).configure_instance()`
  (`install.py:1022-1026`).
- `replicainstall.py`: `if ca_enabled and options.setup_ca and not
  options.no_akamu:` (`replicainstall.py:1444`), placed deliberately *after*
  `ca.install()` because the RA PEM pair is only materialized there —
  requested by the CA step on a non-clone, or imported from the CA peer over
  Custodia on a clone with `promote=True` (`CustodiaModes.CA_PEER`,
  `replicainstall.py:1428-1432`).
- `upgrade.py`: `akamu.upgrade_instance(ca=ca, custodia=akamu_custodia)` is
  called from inside the existing `if ca.is_configured():` block, right after
  `ca.setup_acme()` (`upgrade.py:1963-1978`). When this host is not the CA
  renewal master, upgrade first builds a `CustodiaInstance` against
  `cainstance.get_ca_renewal_master_fqdn()`, and re-populates
  `ca.subject_base`/`ca.ca_subject` (the upgrade path only ever ran
  `CAInstance.__init__`, so the enrollment helpers would otherwise read
  unset attributes). `AkamuInstance.upgrade_instance()` then self-guards:
  it returns immediately when `ca` is `None` or `not ca.is_configured()`,
  uses the `sysupgrade` `akamu/installed` state to decide between a full
  `configure_instance()` and a re-render of the three config files plus a
  restart, forces reinstallation when `AKAMU_CONF` is missing, and defers to
  the next upgrade run when neither a local RA PEM, nor the renewal master
  role, nor a Custodia peer is available. The sysupgrade-state/config-missing
  idiom is the same one `AhdapaInstance.upgrade_instance()` uses; the
  CA-presence guard and the Custodia fallback are Akamu-specific.

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
entirely installer-rendered, the same way `/etc/ahdapa/ahdapa.toml` is, as
are `/etc/gssproxy/20-akamu.conf` and `/etc/httpd/conf.d/ipa-akamu-proxy.conf`.
The one value that is *not* in the rendered config is the EAB master secret:
`_get_eab_master_secret()` keeps it in `/var/lib/akamu/eab_master_secret`
(`paths.AKAMU_EAB_MASTER_SECRET`, mode `0600`, `akamu:akamu`) and only
substitutes it into `config.toml`, generating a fresh `secrets.token_hex(32)`
on first use and never rotating an existing one — every already-registered
ACME account's Kerberos-derived EAB credential depends on it staying stable
across reconfigure/upgrade runs.

## Upgrade

`ipa-server-upgrade` brings Akamu onto any server that already has the CA
role but predates this feature (UC5): the CA block of `upgrade()` calls
`AkamuInstance.upgrade_instance()`, which issues the RA certificate locally
when this host is the CA renewal master and otherwise imports the shared pair
from that master over Custodia (see [Install gating](#install-gating)). On a
host where Akamu is already deployed it re-renders the three config files and
restarts the service; on a host without the CA role it does nothing.

## Test plan

The checks below were the static verification performed when this design was
authored; they are recorded here as history, and their outcomes are noted
against the code as it now stands.

- `py_compile` on the new installer module.
- Grep-verify the `System: Read Certificate Profiles` permission name
  referenced by the new LDIF still exists verbatim in `ipaserver/plugins/*.py`
  before relying on it (the Ahdapa integration caught exactly this kind of
  drift against a permission name Ahdapa's own docs got wrong). It does:
  `ipaserver/plugins/certprofile.py:150`, and `79-akamu.update` grants to
  exactly that name.
- LDIF stanza sanity check on `79-akamu.update` (matching `default:`/`add:`
  pairs, no malformed action tokens).
- Diff the new templates against Akamu's own `contrib/demo/ipa/*` reference
  files to confirm no drift from the upstream-documented configuration. The
  deliberate deviations are recorded in [New files](#new-files): the `/acme`
  → `/akamu` path rewrite in the proxy conf, and the trimmed gssproxy
  service entry.

Integration test scenarios (still deferred to CI: `ipatests/` contains no
Akamu test at HEAD): fresh install with `--setup-ca` exposes
`/akamu/directory`; install with `--no-akamu` does not; install without
`--setup-ca` does not; Kerberos EAB enrollment issues a cert with the
correct principal SAN; replica install and upgrade obtain the RA pair from
the CA renewal master via Custodia; uninstall cleanly removes config and RA
agent state.

## Troubleshooting and debugging

- Config: `/etc/akamu/config.toml` (rendered, not hand-edited).
- EAB master secret: `/var/lib/akamu/eab_master_secret` (must not be
  regenerated by hand; changing it invalidates every existing EAB credential).
- GSSAPI plumbing: `/etc/gssproxy/20-akamu.conf`, and the `akamu` group
  membership for the httpd user that lets mod_proxy reach
  `/run/akamu/akamu.sock`.
- Logs: `journalctl -u akamu` (dedicated `journald@akamu` namespace,
  structured `AKAMU_EVENT_TYPE`/`AKAMU_OUTCOME` fields per Akamu's own
  conventions).
- LDAP state: `cn=akamu,cn=ipa,cn=etc,$SUFFIX` container,
  `uid=akamu-ra,ou=People,$SUFFIX` RA agent entry, `Akamu Services` role.
- RA agent cert renewal: tracked by `certmonger`, same
  `getcert list -f /var/lib/akamu/akamu-ra-agent.pem`-style inspection as the
  existing `ra-agent.pem`. Every CA host tracks its own local copy
  (`configure_agent_renewal()` runs on both the request and the import path);
  the post-renewal LDAP resync in `renew_akamu_ra_cert` only performs the
  `update_people_entry()` work on the CA renewal master, exactly as
  `renew_ra_cert` does for `ipara`.
- If `/akamu/directory` 404s: check `HTTPD_IPA_AKAMU_PROXY_CONF` is present
  and the `akamu` systemd unit/socket are active (same "proxy conf presence
  as availability probe" idiom Ahdapa's `login_oidc._serve_config` uses,
  `ipaserver/rpcserver.py:1258`). Note the installer itself waits on the
  socket (`ipautil.wait_for_open_socket(paths.AKAMU_SOCKET)`) before
  reloading httpd, so a 404 usually means the daemon is not running rather
  than that the proxy conf is missing.
