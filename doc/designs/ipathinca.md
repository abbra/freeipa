# IPAthinCA: Python-native Certificate Authority

## Overview

FreeIPA's CA subsystem has historically been provided by
[Dogtag PKI](https://www.dogtagpki.org/) (`pki-tomcat`), a Java-based certificate
management system. While Dogtag is feature-rich, it introduces significant operational
complexity: a separate Java process (`pki-tomcat`), an embedded Tomcat servlet
container, an independent LDAP suffix (`o=ipaca`), and a dedicated NSSDB for key
storage. This complexity makes IPA installations heavier, increases startup time, and
creates additional failure modes that are difficult to diagnose.

IPAthinCA is a Python-native CA backend for FreeIPA that replaces `pki-tomcat` while
maintaining full compatibility with the existing IPA RA layer, the Dogtag LDAP schema,
and all IPA certificate management commands. It implements the same REST API surface
that IPA's `ipaserver/plugins/dogtag.py` expects, so no IPA plugin changes are needed.

Key design goals:

- **Python-native:** runs as a standard gunicorn WSGI service under the existing `ipaca`
  system user, with no Java or Tomcat dependency.
- **Dogtag-compatible LDAP schema:** uses the existing `o=ipaca` suffix and Dogtag
  `certificateRecord` / `request` objectClasses, allowing in-place migration and
  replica interoperability during transition.
- **Algorithm-agnostic:** supports RSA, ECDSA, and post-quantum ML-DSA (FIPS 204)
  signing algorithms from the same code path.
- **HSM-ready:** PKCS#11 hardware security modules are supported natively via
  OpenSSL's pkcs11-provider and the `synta` cryptography library.
- **Full feature parity:** sub-CAs (lightweight CAs), OCSP (RFC 6960), ACME
  (RFC 8555), KRA key archival, CRL generation, and certmonger renewal are all
  preserved.

### Background and references

- [Dogtag PKI documentation](https://www.dogtagpki.org/)
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) — OCSP
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) — ACME
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA (post-quantum signatures)
- [PKCS#11 v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html) — base HSM interface
- [PKCS#11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.2/pkcs11-base-v3.2.html) — required for ML-DSA (post-quantum) key operations
- [Dogtag LDAP schema](https://github.com/dogtagpki/pki/tree/main/base/server/database/ds)

---

## Use Cases

### Standard IPA CA installation

An administrator installs a new FreeIPA server with IPAthinCA as the CA backend:

```
ipa-server-install --setup-ca --use-ipathinca
```

The installation generates RSA-3072 CA signing, subsystem, OCSP signing, audit
signing, and server TLS certificates. The `ipathinca` service starts automatically.
All `ipa cert-*` and `ipa ca-*` commands work unchanged.

### Post-quantum CA deployment

An administrator installs a new FreeIPA server with an ML-DSA-65 CA signing key
(a NIST FIPS 204 post-quantum signature scheme). This is chosen at installation
time and cannot be changed on an existing deployment:

```
ipa-server-install --setup-ca --use-ipathinca \
    --ca-key-type=mldsa:65
```

All certificates issued by this CA carry ML-DSA-65 signatures. OCSP responses
and CRLs are also signed with ML-DSA-65.

### HSM-backed CA signing key

An administrator installs IPA with the CA signing key stored on a PKCS#11 HSM
(for example, a network-accessible PKCS#11 hardware token):

```
ipa-server-install --setup-ca --use-ipathinca \
    --token-name=IPA-CA \
    --token-library-path=/usr/lib64/pkcs11/vendor-pkcs11.so \
    --token-password-file=/etc/ipa/hsm_pin
```

The relevant options are:

| Option | Description |
|--------|-------------|
| `--token-name` | PKCS#11 token name where keys are stored |
| `--token-library-path` | Path to the PKCS#11 shared library for the HSM |
| `--token-password` | Token password (interactive prompt if omitted) |
| `--token-password-file` | File containing the token password |

The CA signing private key is generated on the HSM and never leaves it. All signing
operations are delegated to the HSM via the PKCS#11 URI mechanism.

A network-accessible hardware HSM (such as a Thales Luna or Entrust nShield) is
required for multi-replica deployments, because all replicas must share access to
the same signing key. Software PKCS#11 tokens (SoftHSM2, Kryoptic) do not support
this and are only suitable for single-host testing.

### Enabling ACME for certificate automation

After IPAthinCA is running, an administrator enables the ACME service for certificate
automation (e.g. for web servers using certbot):

```
ipa-acme-manage enable
```

ACME clients can then obtain certificates via the standard
`https://<ipa-server>/acme/directory` endpoint.

### KRA key archival for vault

When the IPA Vault feature is used, the KRA subsystem archives symmetric keys and
secrets. IPAthinCA provides a built-in KRA that is automatically configured during
installation when `--setup-kra` is specified.

### Replica promotion

An existing FreeIPA replica that runs Dogtag can be converted to use IPAthinCA. The
installer connects to an existing IPAthinCA master, clones the CA certificate chain
and signing key material, and starts the local `ipathinca` service. The Dogtag LDAP
suffix (`o=ipaca`) is shared between all replicas via standard LDAP replication.

---

## How to Use

### Installation

Install IPAthinCA during a new FreeIPA server installation by passing
`--use-ipathinca`:

```bash
ipa-server-install --setup-ca --use-ipathinca \
    [--ca-key-type=TYPE] [--ca-signing-algorithm=ALG] \
    [--key-type-size ALG:SIZE]
```

**CA key type (`--ca-key-type`)** — selects the CA signing key type:

| Value | Key type | Notes |
|-------|---------|-------|
| `rsa` | RSA-3072 | Default |
| `mldsa` | ML-DSA-65 | Post-quantum (FIPS 204), defaults to level 3 |
| `mldsa:44` | ML-DSA-44 | Post-quantum level 2 |
| `mldsa:65` | ML-DSA-65 | Post-quantum level 3 |
| `mldsa:87` | ML-DSA-87 | Post-quantum level 5 |

**CA signing algorithm (`--ca-signing-algorithm`)** — selects the signing hash
algorithm. For RSA keys this determines the hash; for ML-DSA keys this must match
the key type (ML-DSA is pure — no pre-hash):

| Value | Notes |
|-------|-------|
| `SHA256withRSA` | Default for RSA keys |
| `SHA384withRSA` | |
| `SHA512withRSA` | |
| `ML-DSA-44` | Use with `--ca-key-type=mldsa:44` |
| `ML-DSA-65` | Use with `--ca-key-type=mldsa:65` |
| `ML-DSA-87` | Use with `--ca-key-type=mldsa:87` |

**Issued certificate defaults (`--key-type-size`)** — sets the default key type
and size for end-entity certificates issued by this CA. Format is `ALG:SIZE`
(e.g. `RSA:3072` or `EC:256`). May be specified multiple times for multiple
algorithm families.

### Service management

The `ipathinca` service is managed by IPA together with all other IPA services.
Use `ipactl` to start, stop, or restart the full IPA service stack:

```bash
ipactl start
ipactl stop
ipactl restart
ipactl status
```

Do not start or stop `ipathinca.service` directly with `systemctl` — IPA
manages service ordering and dependencies.

### Certificate operations

IPAthinCA exposes the same `ipa cert-*` interface as the Dogtag backend:

```bash
ipa cert-request --principal=HTTP/host.ipa.example /tmp/server.csr
ipa cert-show <serial>
ipa cert-revoke <serial>
ipa cert-status <request_id>
```

### Sub-CA (lightweight CA) management

```bash
ipa ca-add --name=subca --subject="CN=Sub CA,O=EXAMPLE.COM"
ipa ca-show subca
ipa ca-disable subca
ipa ca-enable subca
ipa ca-del subca
```

### ACME management

```bash
ipa-acme-manage enable     # Enable ACME service
ipa-acme-manage disable    # Disable ACME service
ipa-acme-manage status     # Show ACME status
```

ACME clients configure `https://<ipa-server>/acme/directory` as the directory URL.

### CRL management

```bash
ipa-crlgen-manage enable   # Enable CRL generation on this replica
ipa-crlgen-manage disable
ipa-crlgen-manage status
```

### Configuration

The main configuration file is `/etc/ipa/ipathinca.conf`:

```ini
[global]
realm = EXAMPLE.COM
host = ipa.example.com
basedn = dc=example,dc=com
domain = example.com

[server]
bind_host = 0.0.0.0
https_port = 8443
workers = 1
threads = 4
ssl_cert = /var/lib/ipathinca/certs/server_cert.pem
ssl_key = /var/lib/ipathinca/private/server_key.pem
user = ipaca
group = ipaca

[ldap]
pool_min_connections = 2
pool_max_connections = 10

[ca]
random_serial_numbers = true
serial_number_bits = 128
default_signing_algorithm = SHA256withRSA
crl_update_interval = 240
max_search_returns = 1000

[logging]
level = INFO
log_file = /var/log/ipathinca/ipathinca.log
access_log = /var/log/ipathinca/access.log
```

---

## Design

### Architecture

IPAthinCA is a Flask WSGI application served by Gunicorn. It is organised as a
package of Flask Blueprints, one per subsystem:

```
┌─────────────────────────────────────────────────────────────┐
│  IPA RA (ipaserver/plugins/dogtag.py)                       │
│  uses Dogtag REST API, port 8443, HTTPS + client cert auth  │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS (PKI REST API v1/v2)
┌──────────────────────▼──────────────────────────────────────┐
│  Apache httpd (mod_proxy)  →  127.0.0.1:8443                │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Gunicorn (gthread worker class)                            │
│  Entry point: ipathinca.wsgi:application                    │
│  User: ipaca   Config: /etc/ipa/ipathinca.conf             │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Flask application  (ipathinca/rest_api/)                   │
│  Blueprints:                                                │
│    ca_core · certs · profiles · crl_ocsp · authorities      │
│    ranges · kra · acme · hsm                                │
└──────────────────┬─────────────────────┬────────────────────┘
                   │                     │
      ┌────────────▼───────┐  ┌──────────▼───────────┐
      │  synta / OpenSSL   │  │  LDAP (o=ipaca)      │
      │  (crypto + PKCS11) │  │  389-ds via LDAPI    │
      └────────────────────┘  └──────────────────────┘
```

### REST API surface

IPAthinCA implements the PKI REST API v1 (`/ca/rest/`) and v2 (`/ca/v2/`)
endpoints expected by `ipaserver/plugins/dogtag.py`, plus the KRA endpoints
(`/kra/rest/`), the ACME directory (`/acme/`), and an HSM management interface
(`/ca/rest/hsm/`):

| Blueprint | URL prefix | Subsystem |
|-----------|-----------|-----------|
| `ca_core` | `/pki/`, `/ca/rest/info`, `/ca/rest/account` | CA info, auth |
| `certs` | `/ca/rest/certs`, `/ca/rest/certrequests` | Certificates |
| `profiles` | `/ca/rest/profiles` | Certificate profiles |
| `crl_ocsp` | `/ca/rest/crl`, `/ca/rest/pruning`, `/ca/ocsp` | CRL, OCSP, pruning |
| `authorities` | `/ca/rest/authorities` | Sub-CAs |
| `ranges` | `/ca/rest/ranges` | Serial number ranges |
| `kra` | `/kra/rest/` | Key Recovery Authority |
| `acme` | `/acme/` | ACME (RFC 8555) |
| `hsm` | `/ca/rest/hsm/` | HSM configuration |

All endpoints accept TLS client certificates from `ipara` (the IPA RA agent),
validated by Apache before the request reaches IPAthinCA.

### Authentication and access control

Authentication follows Dogtag's model:

- **Agent endpoints** (`/agent/`) require a valid client certificate issued to
  the IPA RA subsystem. Apache validates the certificate before proxying.
- **End-entity endpoints** (`/ee/`) and informational endpoints are accessible
  without client certificates.
- **Admin endpoints** verify membership in the `cn=admins` LDAP group.
- Internally, IPAthinCA connects to 389-ds via LDAPI autobind as the `ipaca`
  system user (mapped to `uid=ipacasrv,cn=sysaccounts,cn=etc,<basedn>`).

### Cryptography

All cryptographic operations use the `synta` library, which wraps OpenSSL via
a Rust extension. Key types supported:

| Algorithm | Key size / parameters | Notes |
|-----------|----------------------|-------|
| RSA | 2048–8192 bits | Default 3072 (NIST SP 800-131A) |
| ECDSA | P-256, P-384, P-521 | |
| ML-DSA-44 | FIPS 204, level 2 | No pre-hash |
| ML-DSA-65 | FIPS 204, level 3 | No pre-hash |
| ML-DSA-87 | FIPS 204, level 5 | No pre-hash |

Private keys are stored as PEM files under `/var/lib/ipathinca/` with mode 0600,
owned by `ipaca`. When an HSM is configured, only a PKCS#11 URI is stored; the
key material never leaves the HSM.

### LDAP storage

IPAthinCA uses the Dogtag `o=ipaca` LDAP suffix with the standard Dogtag PKI
schema (`/usr/share/pki/server/database/ds/schema.ldif`). No new objectClasses
or attributes are added to the IPA schema at `dc=<domain>`.

The only new LDAP artifact is the service account used for LDAPI autobind:

```ldif
dn: uid=ipacasrv,cn=sysaccounts,cn=etc,<basedn>
objectClass: account
objectClass: simplesecurityobject
uid: ipacasrv
```

And the autobind mapping:

```ldif
dn: cn=ipa-ca,cn=auto_bind,cn=config
objectClass: nsLDAPIFixedAuthMap
cn: ipa-ca
nsslapd-uidNumber: <ipaca UID>
nsslapd-gidNumber: <ipaca GID>
nsslapd-ldapiDNMappingBase: uid=ipacasrv,cn=sysaccounts,cn=etc,<basedn>
```

Certificate entries follow the Dogtag `certificateRecord` schema:

```ldif
dn: cn=<serial>,ou=certs,o=ipaca
objectClass: certificateRecord
cn: <serial>
serialno: <length-prefixed hex>
subjectName: CN=...,O=...
certStatus: VALID|REVOKED|EXPIRED
userCertificate;binary: <DER>
```

### Serial number management

IPAthinCA supports both sequential and random serial numbers (RSNv3):

- **Sequential:** serial numbers are allocated by atomically incrementing an
  LDAP counter with optimistic locking. Multi-master replication conflicts are
  retried automatically.
- **Random (default):** 128-bit random serial numbers are generated with the
  MSB set to ensure consistent length. Collision detection queries LDAP before
  committing.

Multi-master replication uses per-replica serial number ranges stored in LDAP
under `ou=ranges,o=ipaca`, compatible with Dogtag's range management protocol.

### CRL generation

CRLs are generated by IPAthinCA on a configurable schedule (default: every 240
minutes). The CRL is signed with the `crl_signing_algorithm` key and published
to `/var/lib/ipa/pki-ca/publish/MasterCRL.bin`. Apache exposes this file
at the standard Dogtag CRL URL.

### OCSP responder

A built-in OCSP responder (RFC 6960) is served at `/ca/ocsp`. Each replica
maintains a per-CA OCSP responder with a dedicated signing certificate. Response
caching reduces LDAP load. Nonce extension support prevents replay attacks.

### Sub-CAs (lightweight CAs)

Sub-CAs (also called Lightweight CAs or authorities) are stored in LDAP under
`cn=cas,cn=ca,o=ipaca`. Each sub-CA has its own signing key stored under
`/var/lib/ipathinca/ca/subcas/<ca_id>/`. Sub-CA certificates are signed by the
root CA or by another sub-CA, forming a chain of any depth (subject to
`pathLenConstraint`).

### KRA (Key Recovery Authority)

When `--setup-kra` is specified, IPAthinCA sets up a built-in KRA subsystem:

- An RSA-4096 transport key pair is generated and signed as a certificate.
- Client secrets are wrapped with the transport public key on upload, then
  stored in LDAP under `ou=keys,o=ipaca`.
- Recovery wraps the stored secret with the agent's public key and returns it.
- The transport private key is stored in the NSS database at
  `transportCert cert-pki-kra`.

### HSM integration

When an HSM is configured:

1. The CA signing key is generated on the HSM during `ipa-server-install`.
2. IPAthinCA stores a PKCS#11 URI (e.g.
   `pkcs11:token=IPA-CA;object=ipa-ca-signing;type=private`) instead of a PEM
   file.
3. Signing is performed via `synta.PrivateKey.from_pkcs11_uri()`, which uses
   OpenSSL's pkcs11-provider to delegate to the PKCS#11 token.
4. The pkcs11-provider must be configured in `/etc/pki/pkcs11/pkcs11.conf` or
   via `OPENSSL_CONF`.

Hardware HSMs that expose a PKCS#11 3.0 interface can be used for RSA and
ECDSA keys. ML-DSA (post-quantum) key operations require a token that implements
PKCS#11 3.2 or later, as ML-DSA key types were introduced in that version.
Software PKCS#11 tokens (SoftHSM2, Kryoptic) may be used for single-host
testing only; they cannot provide the shared key access required for
multi-replica deployments.

### Audit logging

A structured audit log is written to `/var/log/ipathinca/audit.log`. Each entry
is signed with the `audit_signing_algorithm` key so tampering is detectable.
Audit events cover certificate issuance, revocation, profile changes, and
configuration modifications.

---

## Implementation

### Dependencies

New dependencies introduced by IPAthinCA:

| Package | Reason |
|---------|--------|
| `python3-flask` | REST API framework |
| `python3-gunicorn` | WSGI process manager |
| `synta` | Cryptography (RSA, ECDSA, ML-DSA, PKCS#11) |
| `pkcs11-provider` | OpenSSL PKCS#11 provider (for HSM support) |

Existing dependencies that are no longer needed when Dogtag is replaced:

| Package | Reason removed |
|---------|----------------|
| `pki-ca` | Dogtag CA server |
| `pki-kra` | Dogtag KRA server |
| `tomcatjss` | JSS/Tomcat bridge |
| `java-headless` | JVM runtime |

### File system layout

```
/etc/ipa/ipathinca.conf          Main configuration
/var/lib/ipathinca/
    ca/
        ca_signing.key           CA signing private key (or PKCS#11 URI)
        ca_signing.crt           CA signing certificate
        subcas/<ca_id>/          Sub-CA keys and certificates
    audit/
        audit_signing.key        Audit signing key
    certs/
        server_cert.pem          TLS server certificate
    private/
        server_key.pem           TLS server private key (mode 0600)
    kra/
        transport.key            KRA transport private key
        transport.crt            KRA transport certificate
/var/log/ipathinca/
    ipathinca.log                Application log
    audit.log                    Signed audit log
    access.log                   HTTP access log
/run/ipathinca/
    ipathinca.pid                PID file
/var/lib/ipa/pki-ca/publish/
    MasterCRL.bin                Published CRL (Apache-accessible)
```

### Backup and restore

All state that must be backed up:

- `/etc/ipa/ipathinca.conf` — configuration
- `/var/lib/ipathinca/` — all keys and certificates
- The `o=ipaca` LDAP suffix (covered by `ipa-backup` as part of the LDAP
  database backup)

The `ipa-backup` and `ipa-restore` tools handle the LDAP suffix automatically.
The `/var/lib/ipathinca/` directory must be added to the backup set. The existing
`Backup and Restore` implementation covers `/var/lib/ipa/` and must be extended
to include `/var/lib/ipathinca/`.

When HSM is in use, key material on the HSM is not covered by `ipa-backup` and
must be backed up separately according to the HSM vendor's procedures.

### Certmonger integration

Certmonger is used to renew the service certificates (server TLS, RA agent,
subsystem, OCSP signing, audit signing). Renewal scripts are installed under
`/usr/lib/ipa/certmonger/` and follow the same pattern as the existing Dogtag
certmonger helpers.

---

## Feature Management

### UI

IPAthinCA does not add new Web UI pages. The existing IPA Web UI pages for
certificates, CAs, profiles, and ACME work unchanged, because the IPA server
uses the same `ipa cert-*` / `ipa ca-*` XMLRPC interface regardless of the
CA backend.

### CLI

No new `ipa` subcommands are added. The existing certificate and CA management
commands work unchanged:

| Command | Options | Notes |
|---------|---------|-------|
| `ipa cert-request` | `--principal`, `--ca`, `--profile-id` | Works unchanged |
| `ipa cert-show` | `<serial>` | Works unchanged |
| `ipa cert-revoke` | `<serial>`, `--revocation-reason` | Works unchanged |
| `ipa ca-add` | `--name`, `--subject` | Sub-CA management |
| `ipa ca-show` | `<name>` | |
| `ipa ca-disable` / `ipa ca-enable` | `<name>` | |
| `ipa certprofile-import` | `--file` | Profile management |
| `ipa-acme-manage` | `enable` / `disable` / `status` | ACME control |
| `ipa-crlgen-manage` | `enable` / `disable` / `status` | CRL generation |

New management tool:

| Command | Options | Description |
|---------|---------|-------------|
| `/usr/sbin/ipathinca` | `[CONFIG]` `[--foreground]` | Start IPAthinCA directly (normally managed by systemd) |

### Configuration

Key configuration options in `/etc/ipa/ipathinca.conf`:

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[server]` | `bind_host` | `0.0.0.0` | Listen address |
| `[server]` | `https_port` | `8443` | HTTPS port |
| `[server]` | `workers` | `1` | Gunicorn worker processes |
| `[server]` | `threads` | `4` | Threads per worker |
| `[ldap]` | `pool_min_connections` | `2` | Minimum LDAP pool size |
| `[ldap]` | `pool_max_connections` | `10` | Maximum LDAP pool size |
| `[ca]` | `random_serial_numbers` | `true` | Use RSNv3 random serials |
| `[ca]` | `serial_number_bits` | `128` | Random serial entropy |
| `[ca]` | `default_signing_algorithm` | `SHA256withRSA` | CA signing algorithm |
| `[ca]` | `crl_update_interval` | `240` | CRL update interval (minutes) |
| `[ca]` | `max_search_returns` | `1000` | Max cert search results |
| `[logging]` | `level` | `INFO` | Log level |

---

## Upgrade

### Migration from Dogtag to IPAthinCA

Migration of an existing Dogtag-based IPA deployment to IPAthinCA is a planned
future feature. The migration path will:

1. Export the CA signing key from the Dogtag NSSDB.
2. Convert the key to the IPAthinCA PEM format under `/var/lib/ipathinca/ca/`.
3. Stop `pki-tomcatd@pki-tomcat`.
4. Install and start `ipathinca.service`.
5. Verify that IPA certificate operations continue to work.

The `o=ipaca` LDAP suffix, all certificates, and all certificate records are
shared between Dogtag and IPAthinCA (Dogtag-compatible LDAP schema), so no
data migration is required.

### Replica-by-replica transition

Because IPAthinCA and Dogtag share the same `o=ipaca` LDAP suffix via standard
replication, it is possible to run a mixed environment during transition:
some replicas run Dogtag, others run IPAthinCA. Both service the same certificate
database. This allows zero-downtime migration.

### Schema upgrades

IPAthinCA does not modify the `o=ipaca` LDAP schema. The existing Dogtag schema
is used as-is. The only IPA-tree change is the addition of the `ipacasrv`
sysaccount and the LDAPI autobind mapping, both of which are added by
`ipa-server-upgrade` and are backward-compatible.

---

## Test plan

- **Unit tests** (`ipathinca/tests/`):
  - CA engine: issuance, revocation, serial allocation (`test_ca.py`)
  - Certificate lifecycle: renewal, expiry, status transitions (`test_certificate_lifecycle.py`)
  - OCSP: request parsing, response generation, nonce handling (`test_ocsp.py`)
  - Profile management: CRUD, constraint evaluation (`test_profiles.py`)
  - KRA: key archival, retrieval, transport cert (`test_kra.py` — if present)
  - Audit: signature verification, tamper detection (`test_audit.py`)
  - Thread safety: concurrent issuance under gthread workers (`test_threading.py`)
  - REST API: HTTP endpoint contract tests (`test_rest_api.py`)

- **Integration tests** (IPA CI, `ipatests/test_integration/`):
  - Full `ipa-server-install --setup-ca --use-ipathinca`
  - `ipa cert-request`, `ipa cert-revoke`, `ipa cert-show` round-trip
  - Sub-CA creation and certificate issuance through a sub-CA
  - ACME: certbot client obtains a certificate via `acme/directory`
  - CRL: verify CRL is published and contains revoked serials
  - OCSP: verify OCSP response for good and revoked certificates
  - Replica promotion: install replica with IPAthinCA, verify replication
  - Certmonger renewal: verify service certs are renewed automatically
  - HSM: install with a software PKCS#11 token (SoftHSM2 or Kryoptic) for testing, verify signing works
  - ML-DSA: install with `--ca-key-type=mldsa:65`, verify issued cert

- **Upgrade/migration tests:**
  - In-place `ipa-server-upgrade` on an existing IPAthinCA deployment
  - Mixed-replica environment (one Dogtag replica, one IPAthinCA replica)

---

## Troubleshooting and debugging

### Log files

| File | Contents |
|------|----------|
| `/var/log/ipathinca/ipathinca.log` | Application log (errors, warnings, debug) |
| `/var/log/ipathinca/access.log` | HTTP request log (gunicorn access log) |
| `/var/log/ipathinca/audit.log` | Signed audit events |
| `journalctl -u ipathinca` | Systemd journal (startup, crashes) |

Increase log verbosity by setting `level = DEBUG` in `/etc/ipa/ipathinca.conf`
under `[logging]`, then restarting with `ipactl restart`.

### Service status

```bash
ipactl status                        # All IPA services including ipathinca
journalctl -u ipathinca              # Systemd journal for ipathinca
curl -sk https://ipa.example.com:8443/ca/rest/info  # CA info endpoint (no auth)
```

### LDAP entries

IPAthinCA state is stored under `o=ipaca`:

```bash
ldapsearch -H ldap:/// -Y EXTERNAL -b "o=ipaca" "(objectClass=certificateRecord)" \
    cn certStatus  # List all certificates and their status

ldapsearch -H ldap:/// -Y EXTERNAL -b "ou=certs,o=ipaca" \
    "(certStatus=REVOKED)" cn  # List revoked certificates

ldapsearch -H ldap:/// -Y EXTERNAL -b "cn=ipaca,cn=ldbm database,cn=plugins,cn=config" \
    # Verify the ipaca database backend is configured
```

The service account:

```bash
ldapsearch -H ldap:/// -Y EXTERNAL \
    -b "uid=ipacasrv,cn=sysaccounts,cn=etc,<basedn>" objectClass
```

### REST API diagnostics

The `/ca/rest/info` endpoint returns CA status without authentication:

```bash
curl -sk https://ipa.example.com:8443/ca/rest/info | python3 -m json.tool
```

The `/ca/admin/ca/getStatus` endpoint returns a plain-text status:

```bash
curl -sk https://ipa.example.com:8443/ca/admin/ca/getStatus
# Expected: status=running
```

### HSM diagnostics

```bash
# List PKCS#11 tokens (replace library path with the one from --token-library-path)
pkcs11-tool --list-slots --module /path/to/pkcs11-library.so

# List keys on the IPA-CA token
pkcs11-tool --list-keys --token-label IPA-CA \
    --module /path/to/pkcs11-library.so

# Test signing via OpenSSL pkcs11-provider
openssl dgst -sign 'pkcs11:token=IPA-CA;object=ipa-ca-signing;type=private' \
    -sha256 /etc/ipa/ca.crt
```

### Certmonger tracking

```bash
getcert list -d /var/lib/ipathinca/certs   # List tracked certificates
getcert list -r                             # Show renewal status
```

### Common failure modes

| Symptom | Likely cause | Diagnostic step |
|---------|-------------|-----------------|
| `ipathinca` fails to start | LDAP not reachable | `ldapsearch -H ldapi:/// -Y EXTERNAL -b "" -s base` |
| 503 on all CA requests | `ca_backend` not initialized | Check `ipathinca.log` for init errors |
| CRL not updating | CRL signing key unreadable | Check permissions on `/var/lib/ipathinca/ca/` |
| OCSP returns `internalError` | LDAP search failure | Check LDAP pool / `ldap_utils` errors in log |
| HSM signing fails | pkcs11-provider not configured | Check `OPENSSL_CONF`, `/etc/pki/pkcs11/pkcs11.conf` |
| KRA 503 | KRA init failed | Check `kra_init_error` in log; verify transport key exists |
