# Post-quantum enrollment of IPA clients through kuipa

This document proposes how an IPA host gets its Kerberos keys without those keys crossing the
network in a form a later adversary can read back. The mechanism is provided by
[kuipa](https://github.com/abbra/kuipa), a separate project; what is designed here is the FreeIPA
side. Command and option names are proposals; the behaviours they name are the design.

## Overview

`ipa-client-install` enrolls a host in two steps: authenticate to the realm, then run
`ipa-join`, which creates the host's principal name and forks `ipa-getkeytab` for its keys. With
the usual one-time password (`ipa host-add --random`), the password travels in an LDAP bind and
the keytab travels in an LDAP extended operation — both protected by the transport, not by the
protocol: a set of long-lived secrets handed over in the clear once, from which every later
authentication is built.

kuipa changes the shape of that exchange: the keytab travels under a key derived from
contributions of both sides, and the server's claims about the realm — its identity, the other
servers it knows, the CA chain, the Kerberos configuration a new host needs — are signed rather
than asserted. The directory keeps making the keys: the KDC, `krbPrincipalKey`, and the join and
keytab extended operations are unchanged.

What changes is who carries the secrets, and how a host with no CA and no ticket yet decides that
the server it is talking to is the right one — which is why this is not only a client change.
kuipa's answer is a per-server signing key, an *anchor*, which the realm's servers vouch for each
other, plus a short **enrollment string** an administrator carries to the host:

```
ipa-ku1:EXAMPLE.TEST:dgt-VqrSdFC64H8R98ehg3kLJ8FzijPp84MmUJHHKMk:1793575335
```

Realm, the issuing server's anchor fingerprint, and an expiry after which the host refuses it. A
fifth field may carry the credential itself: a one-time password, or a server-generated secret for
hosts not named in advance. Producing that string, authorizing the host it describes, and answering
"which anchors does this realm currently trust?" are FreeIPA features, and they are the bulk of
this design.

## Assumptions

- The IPA servers run a version of FreeIPA that configures the enrollment daemon; that
  part is already in the installer.
- The daemon is reachable through the IPA HTTP server on the path already set up for it.
  Enrollment callers have no Kerberos credential, so that path is not authenticated by
  Apache; each request carries its own proof.
- A host record exists before the host enrolls, created by `ipa host-add` or by a host
  group or automation, and the administrator has a way to deliver the string to the host:
  console, kickstart, cloud user-data, a configuration-management variable.
- Realm-to-realm trust is out of scope; so are PKINIT-based enrollment, host certificates
  as the enrollment credential, and post-quantum signatures in certificates.

## Use Cases

### UC1: A host known in advance

The host record is created and authorized in one command, and everything the host
needs comes back on stdout, in the shape `--random` already produces:

```console
$ ipa host-add client12.ipa.test --random --pq-days 14
----------------------------
Added host "client12.ipa.test"
----------------------------
  Host name: client12.ipa.test
  Random password: 1Fzop138ftt6TCcfpMs56Ql
  Enrollment string: ipa-ku1:EXAMPLE.TEST:dgt-VqrSdFC64H8R98ehg3kLJ8FzijPp84MmUJHHKMk:1793575335
```

The provisioning system puts that string on the host with the password appended as a
fifth field, and the host installs itself:

```console
# ipa-client-install --domain ipa.test --server replica1.ipa.test --pq-enroll
```

The host ends with a normal `/etc/krb5.keytab` for
`host/client12.ipa.test@EXAMPLE.TEST`, and with the realm's CA, anchors and Kerberos
configuration in the files the client normally writes.

### UC2: A fleet that cannot be named host by host

A template host record authorizes many hosts when the credential is a secret the
server generates, because the string then carries the credential itself:

```console
$ ipa host-add template.ipa.example --random --pq-stage --pq-days 30
  Enrollment string: ipa-ku1:EXAMPLE.TEST:dgt-VqrSdFC64H8R98ehg3kLJ8FzijPp84MmUJHHKMk:1793575335:YBn2vK4pR8sT1uW6xYzB3cDqa7fHgJsLdNpQeStUvWx
```

The string is complete on its own and is the only thing the image needs — and it is a
credential, so it must travel on a channel nobody else can read. A string left in an image after
the anchor it names was rotated must be refused, not silently trusted.

`host-add` requires a resolvable fully qualified name and accepts no wildcards, so the template
record names *a* host; the hosts that use the string become principals when they enroll,
exactly as they do today with a shared password.

### UC3: A host that will not reach the network

The host's keys can be generated before the host ever contacts the realm. The host
makes its own key pair, the administrator supplies the public half to the server,
and the server puts the sealed keytab into a signed bundle that the host opens
locally, with no server to talk to:

```console
# kuipa prepare                       # on the host, offline
$ scp /var/lib/ipa-client/ku/recipient.pub.jwk admin@master1.ipa.test:/tmp/
$ ipa host-mod offline17.ipa.test --pq-stage \
      --pq-recipient=/tmp/recipient.pub.jwk --pq-bundle=staged-bundle.json
# … the bundle is copied to the host …
# kuipa enroll --bundle staged-bundle.json      # opens the keytab, no network
```

`--random` is not part of this flow: the host authenticates with its own key pair. The host stays
incomplete — its realm configuration and anchor pins arrive on the first contact, days later.

### UC4: Enrollment authorized by a user's credential

A host with a human or a service account vouching for it needs no password at all: the caller
authenticates with its own Kerberos credential and the realm issues keys on that authority. Nothing
is added to the directory and no credential is carried to the host, which is what makes it usable
from a build pipeline.

### UC5: Retiring recovery registrations, and disabling a host

A recovery registration — the server-side half of a sealed keytab, so a host can recover it
without re-enrolling — outlives the keytab it was made for. Decommissioning a host should be able
to drop those registrations without touching the key itself:

```console
$ ipa host-mod decommissioned.ipa.test --clear-pq-escrow
$ ipa service-mod HTTP/web1.ipa.test --clear-pq-escrow
```

And a disabled host should be unable to open what it was registered for. Today `ipa host-disable`
removes the key and revokes the certificates, but a host whose keys were sealed keeps them: the
seal is opened by a local helper against the realm, which never asks whether the host is still
enabled.

## How to Use

### What works today, and the fallback this design must keep

What exists today is the daemon's own command line, on the server and on the host. This is the
path exercised against a real FreeIPA deployment, and it stays working:

```console
$ ipa host-add client1.ipa.test --random
$ kuipad enrollment-string --days 1                     # on the server
$ cat /tmp/kuipa.string
ipa-ku1:EXAMPLE.TEST:dgt-VqrSdFC64H8R98ehg3kLJ8FzijPp84MmUJHHKMk:1793575335
$ printf ':%s' "$OTP" >> /tmp/kuipa.string             # on the host
# kuipa enroll --server master1.ipa.test --enrollment-file /tmp/kuipa.string \
               --hostname client1.ipa.test --ldap-otp
```

`--ldap-otp` is there for a reason this design has to be honest about: a `--random` host has no
Kerberos key, only an LDAP password, and the KDC cannot authenticate a principal that has no key,
so the password is spent as an LDAP bind credential and the keytab operation creates the keys — the
same two steps `ipa-join` performs. Until that gap is closed the LDAP path is the one that works.

Everything else below is planned and exists in no release yet; the commands are listed in the CLI
section under Feature Management.

### Minting a string and enrolling with it (UC1, UC2)

1. Prepare the host and get the credential in one call:
   `ipa host-add client12.ipa.test --random --pq-days 14`, or add `--pq-stage` to a template
   record for a fleet.
2. Put the printed string on the host — kickstart, cloud user-data, a configuration-management
   variable — appending the password as a fifth field when the string did not carry a secret.
3. Install: `ipa-client-install --domain ipa.test --server replica1.ipa.test --pq-enroll`.
4. Check from the server: `ipa host-show client12.ipa.test --all --raw` has a key and no
   `userPassword`; `ipa pq-anchor-show` lists the anchors hosts are pinning.

### Enrolling a host that never reaches the network (UC3)

1. On the host, offline: `kuipa prepare`, which creates its key pair.
2. Copy `/var/lib/ipa-client/ku/recipient.pub.jwk` to a server.
3. `ipa host-mod offline17.ipa.test --pq-stage --pq-recipient=/tmp/recipient.pub.jwk --pq-bundle=staged-bundle.json`.
4. Copy the bundle to the host and `kuipa enroll --bundle staged-bundle.json`. The keytab appears
   with no contact; realm configuration and anchor pins arrive on the host's first contact.

### Enrolling on a caller's own credential (UC4)

Run the enrollment with the authorizing principal's Kerberos credential rather than a password: no
`--random`, nothing printed to carry, and the directory records that principal as the entity that
enrolled the host. The administrator's part is only the authorization, described under the Design
section's `Directory authorization`.

### Retiring registrations, locking and unlocking (UC5)

1. `ipa host-mod decommissioned.ipa.test --clear-pq-escrow` — or `service-mod`, `user-mod` — drops
   the recovery registrations and nothing else.
2. `ipa host-disable`, then confirm with `ipa host-show --all`: `nsAccountLock` present, and the
   host's sealed keytabs refuse to open.
3. `ipa host-enable` removes the lock and they open again; a second `host-enable` reports the host
   was not locked.

## Design

### What changes in the client install, and what does not

`ipa-client-install` obtains a credential for the host principal — the one-time password, a
keytab, or PKINIT — runs `ipa-join`, and only then installs the CA certificate and configures
the host. Those first two steps are the whole of enrollment and are what the post-quantum path
replaces; everything after them is untouched, including the CA certificate, `/etc/krb5.conf`,
SSSD, automount, SSH, NTP and the resumable staging of the installation itself.

| | today | with the option |
|---|---|---|
| authentication | password or PKINIT credential for the host principal | the enrollment string, which carries the credential |
| server verification | the CA certificate fetched later, or a fingerprint checked then | the anchor named in the string, checked before any key material is accepted |
| key exchange | `ipa-join`, then `ipa-getkeytab` | the encapsulation exchange; the same join and keytab extended operations run on the server |
| a realm without the daemon | as today | refused with a clear message; `ipa-join` remains available |

`ipa-join` and `ipa-getkeytab` are not removed: re-enrollment of an already-known host,
`ipa-getkeytab` rekeying and every installation without the option keep using them. An explicit
opt-out (`--no-pq`) is proposed so a scripted install can state which path it wants rather than
relying on the absence of another option.

### Trust: how a host with no realm configuration verifies a server

Two properties of the anchor model are FreeIPA's to provide, and both shape the commands below:

* **An anchor belongs to a server.** Each server creates its own at install and its private key
  never leaves it, so a realm has as many anchors as it has servers. A string minted on a
  replica pins that replica until the anchor log says otherwise, so the view of anchors is
  per-server by construction and needs a command that shows it.
* **The string is a credential with a deadline.** Where it carries the secret itself, whoever
  holds it can claim a host identity until that host first contacts the realm or the string
  expires. Expiry is bounded by the issuing server's delegation lifetime, not by the caller's
  preference.

Accepted anchors are kept in `/etc/ipa/ku-anchors`; the daemon rotates its own anchor and
publishes the replacement in the anchor log. Rotation needs no FreeIPA command; being unable to
answer "is this anchor still current?" does. `ipa server-show` therefore gains this server's anchor
thumbprint and validity and the anchors it vouches for, and `ipa pq-anchor-show` is the realm-wide
listing assembled from the same read: the daemon's signed advertisement naming the peer anchors it
delegates for, and its anchor log recording successors. Nothing is stored for these
commands and no attribute is added to the master entry; an answer is verifiable as stale because it
is signed by the server that produced it, and a stale answer is itself the diagnosis. They read the
daemon over its local socket and have no primary key, attributes or permissions of their own.

### Directory authorization

Three things authorize a host, all already expressible in the directory:

* **The host's one-time password.** `ipa host-add --random` already creates it. The post-quantum
  path spends it as a Kerberos credential, which needs the KDC change listed in the server-side
  behaviour table.
* **A user's or service account's credential.** An authenticated caller asks the realm to issue
  keys for a host — no new directory object, no secret carried to the host.
* **A voucher.** A short-lived signed authorization for a host with neither password nor credential
  yet, consumed on use; the record of a spent voucher is what makes replay detectable.

Whichever path is used, the directory records *who* authorized the enrollment, in the existing
`enrolledBy`: a host enrolled today records itself, a host staged by an administrator records the
administrator.

### The key is installed by the join, not by `host-add`

It is tempting to have `host-add --random` also set the host's Kerberos key, so the string would
be bounded by a real key expiry. FreeIPA refuses that in three independent places, and the design
follows the refusal: `host-add --random` strips the Kerberos object classes and writes
`userPassword` alone, so the host is not a Kerberos principal yet; the password extended operation
refuses to derive Kerberos keys for host principals at all; and password metadata is withheld from
hosts for the same reason — `krbPasswordExpiration` on a host entry makes a keytab look expired,
and `krbPrincipalExpiration` belongs to the principal class the entry does not have.

The key arrives later, on the connection the host makes when it spends the string, in two ordered
steps FreeIPA already performs: the join extended operation adds the principal names and the
object class, then the keytab extended operation generates the keys, sets `krbLastPwdChange`,
deletes `userPassword` and records `enrolledBy`. The password is the *bind credential* of that
second step, never its key material.

So a string bounds the *string*, not the host, and a host that has joined owns ordinary keys and
must not carry that expiry — the server-side change listed below. `host-mod --random` stays a
password reset on a host without keys, refused on an enrolled one; re-keying an enrolled host
stays `ipa-getkeytab`.

### One command, two halves: where the work happens

Minting a string and staging a host need a key-encapsulation key pair or a bundle secret in the
server's own key ring, and this server's anchor — both in `/var/lib/ipa/ku/`, root-owned. The API
worker has no business opening either. Three placements were considered:

| option | verdict |
|---|---|
| the plugin computes it in Python over LDAP | rejected: the private key would be created outside the daemon's key ring and outside its rotation rules |
| the plugin calls the daemon over HTTP as the caller | rejected for the API path: correct for a *host*, which proves itself with a Kerberos authenticator, but the API worker has no Kerberos credential to spend |
| an oddjob helper, as `trust-add` reaches Samba and `server-conncheck` reaches its helper | chosen: the mechanism, its D-Bus authorization for the API user and its packaging already exist; the helper runs as root, so it may read the key ring, and it adds no privilege the server does not already have |

The helper is a thin wrapper beside the four the tree already registers
(`org.freeipa.server`: `conncheck`, `trust_enable_agent`, `config_enable_sid`;
`com.redhat.idm.trust`: `fetch_domains`), with two modes that differ in whether they
touch the directory. **Minting** needs none: the daemon prints the string from this server's anchor
and generates the recipient key pair or bundle secret in its key ring, and the command writes
`userPassword` itself as it does today. **Staging** is a directory transaction and reuses the
daemon's own staging path — authenticate the caller, run the join extended operation to set the
principal names, generate the keys, record the stage with `krbPrincipalExpiration` — carrying the
administrator's identity through instead of the host's. Staging requires the entry to exist, hence
the order in the diagram: mint in `pre_callback`, stage in `post_callback`. `host-add --pq-stage`
stages the host it creates and `host-mod --pq-stage` re-stages an existing one; the result is
indistinguishable in the directory from a stage a host asked the daemon for. There is one staged
state, not two.

.. uml::

  participant "ipa host-add --random --pq-stage" as CLI
  participant "host_add plugin\n(API worker)" as P
  participant "oddjob helper\n(root)" as H
  participant "kuipad\n(key ring, anchor)" as K
  participant "directory" as D

  CLI -> P : RPC with the administrator's credential
  P -> H : pre_callback: mint string,\ngenerate recipient or bundle secret
  H -> K : ask for a string from this anchor
  K --> H : enrollment string, recipient or bundle secret
  P -> D : create the entry with userPassword only
  P -> H : post_callback: stage this host
  H -> K : stage this host as the administrator
  K -> D : join extop, keytab extop:\nprincipal names, keys, stage, expiry
  P --> CLI : random password + enrollment string\n(+ bundle file)

The host later spends the string over the HTTP path the installer already configures for the
daemon; nothing else in this flow is new.

### Staging a host: the options and the record they write

The options sit where `--random` already sits; the only ones new in kind name a file to read
and a file to write. Reading a public key follows the certificate commands that accept a file
argument; writing the returned bundle follows `--certificate-out`, with the writability check
deciding the failure before anything is sent.

| option | effect on the host entry | who holds the secret |
|---|---|---|
| `--random` | `userPassword` as today, no key and no expiry; the string carries the password as its fifth field | the holder of the string |
| `--pq-stage` | the server generates the bundle secret, the daemon creates the host's keys and records the stage with an expiry; the string carries the secret | the holder of the string |
| `--pq-stage --pq-recipient=FILE` | the same, with the stage naming the supplied public key; `--pq-bundle=FILE` writes the signed bundle the response returns | the host, from its own key pair |

A fourth mode — a bundle protected only by its signature, with nothing to open it — is
reachable from the host's own enrollment command and deliberately gets no framework option: it
protects nothing in transit.

A host has at most one active stage; re-staging replaces it, and `--pq-days` bounds a staged
key exactly as it bounds a string. `host-show` reports the stage — recipient thumbprint, valid
until — and never repeats the password, the bundle secret or the recipient key. An
out-of-range `--pq-days` is a validation error. On a server whose daemon has no anchor role
`--random` prints nothing extra, as today, and `--pq-stage` reports the daemon's reason rather
than a traceback: the anchor role decides where a host can be enrolled from, not the client.

### Server-side behaviour this design needs

Four changes outside the command layer, all in code the installer already configures:

| need | why | today |
|---|---|---|
| the KDC answers an authentication request for a host that has only `userPassword`, deriving a key from it, bounded by `krbPrincipalExpiration` | the post-quantum join authenticates the host with the password it was given, so the realm's Kerberos keys vouch for the server as well as the anchor | the KDC reads keys from `krbPrincipalKey` only. Until this exists an OTP enrollment binds over LDAP — which works, and is the demonstrated path |
| `krbPrincipalExpiration` is cleared whenever a host's keys are created, and `ipaKUStaged` consumed | a string's expiry bounds the string; a joined host must not carry an expiry that makes ordinary keys look dead | the daemon clears both only when a *staged* host rekeys. A host that joined with a plain password keeps an expiry; a staged host that joins over the password path is never un-staged. One condition in the first-contact path closes both |
| a sealed keytab is refused for a principal the directory has disabled | otherwise `ipa host-disable` does not stop a host recovering what it was registered for | the unseal check consults the registered binding only |
| the authorizer is recorded | "who enrolled this host" has a different answer on the password, credential and staged paths | `enrolledBy` records the identity that ran the keytab operation; the staged path must carry the administrator's, not the daemon's. The write is `LDAP_MOD_ADD` and only when the attribute is absent, so a re-enrollment keeps the first authorizer; and `userPassword` is deleted only when the entry has no `krbLastPwdChange`, i.e. on the first enrollment |

Nothing here is a protocol change; each is about which credentials the server accepts and which
records it leaves behind.

### Directory state: what is already there and what must be added

The installers already create the `cn=kuipa,cn=etc` containers (seals, trusts, recovery,
vouchers, seal limits, signing policy), the `ipaKU*` attribute and object-class arcs, and the
`cn=kuipa servers` group of `ipa-ku/<server>` principals, and the attributes named here — the
stage record, the escrow bindings, the spent-voucher record, the lease — exist, as does
`krbPrincipalExpiration`. No schema change is needed.

What is missing is authorization: the installed access control grants read and write over the
stage, spent-voucher and lease attributes to the servers' group only, so nothing in the tree lets
an ordinary API caller write a stage. A principal's own escrow bindings are the exception: the
installed tree already lets a principal write those two attributes itself, under "principals
register their own escrow bindings". New permissions are needed for the stage, and for an
administrator clearing a binding that is not their principal's, following the pattern the host
object already declares:

* New permissions created for writing the enrollment state: `System: Manage host
  post-quantum state`, `System: Manage service post-quantum state`, `System: Manage user
  post-quantum state`. Granted to the privileges *Host Administrators*, *Service
  Administrators* and *User Administrators*.
* Self-service rights so a host administrator may stage or un-stage a host they administer,
  following how *System: Manage Host Keytab* grants the key to the *Host Enrollment* privilege
  (*System: Enroll a Host* itself grants only `objectclass`, `enrolledby`, `nshardwareplatform`
  and `nsosversion`).
* By default only members of the admins group may stage a host or clear its registrations.

`enrolledBy` needs no new permission — enrolling already writes it — and the servers' own access
control stays untouched. A framework permission is the point: one an administrator can revoke and
see through `ipa permission-show`, rather than a daemon-side refusal.

### Disabling a host, and what a disabled host can no longer do

`ipa host-disable` walks a host's services, revokes its certificates and removes its key;
`ipa service-disable` does the same for one principal. Neither marks the principal inactive.
Writing `nsAccountLock` at the point where the key is removed — through the same backend
helper `user-disable` uses — makes the lock part of the same operation, and `ipa host-enable`
/ `ipa service-enable` are the counterparts. Three consequences, accepted deliberately:

* `AlreadyInactive` today means "there was nothing to do". With the lock, a host that has
  neither key nor certificate but is unlocked *has* something left to do, so the command
  succeeds. Hosts disabled before this change are not retroactively locked; re-running
  `host-disable` brings them in line.
* A server is never locked by this command, as it is refused today — and that matters,
  because `ipa-ku/<server>` is that host's principal and its keytab is requested at install.
  Locking a server would lock its own daemon out of the directory.
* `nsAccountLock` is enforced by the directory server, so other consumers see it — a tool binding
  as a lesser identity now sees a lock it did not see before, which is the point of the change and
  why it is paired with an enable. No schema change: the attribute is in no object class, which is
  why the backend reads and writes it directly.

### Compatibility with older servers, and domain level

No new domain level, and no requirement that both sides run the same version: nothing new is
stored, and the stage record and the escrow bindings replicate as ordinary attributes. New
behaviour lives in each server's own command layer, so an older replica simply does not offer
`--pq-stage` or `pq-anchor-show`, and the option-less change works against any master. A stage is
bound to the anchor of the server that minted it, so hosts enrolled from a replica's string pin
that replica; a replica installing itself is untouched, because a server's own identity never goes
through this enrollment path.

## Implementation

### Dependencies

No new dependencies: the server package already requires the enrollment daemon package, oddjob
and its dependency are present, and the schema and access control these commands read are already
installed. `ipa-client-install --pq-enroll` is the design's only new package relationship — the
client package gains a dependency on the host-side kuipa package, without which the client has no
enrollment command and keeps using `ipa-join`. No post-quantum algorithm is implemented in
Python, so no Python cryptography library gains a version floor.

| change | where |
|---|---|
| the staging options and the enrollment string in the output | the host plugin's parameters, `pre_callback` and `post_callback`, beside the existing random-password pair; the bundle is written by the client after the call returns |
| `host-show` reporting the staged state | the host plugin's attribute list, secrets excluded |
| the oddjob helper | one helper program beside the four already registered, one method registration, one file-list entry |
| `pq-anchor-show`, the anchor section of `server-show` | a new command module reading the advertisement and anchor log over the daemon's local socket; an option on the existing server command, which already composes derived state |
| `--clear-pq-escrow` | the `post_callback` of the host, service and user modify commands, as a value-less delete |
| `nsAccountLock`, new `host-enable` / `service-enable` | the disable commands, plus the backend activate helper the user commands already use |
| the new permissions | the enrollment update file the installer already runs |
| the client-install enrollment step | the join block of the client installer and its option set; `ipa-join` stays in the code path |

### Gaps in the installer glue this design must close

The installers already write the daemon's configuration: containers and schema,
`/etc/ipa/kuipad.json`, its service principal and keytab, its membership of the servers' group,
the delegation it needs to act as the joining principal, and the proxy path the host reaches it
through; the socket-activation drop-in without which the socket has permissions httpd cannot use
is installed by the packaging, not written by the installer. Two omissions are in scope because
this design is what makes them observable, and each is packaging work independent of the client
option:

* **No firewall rule.** Enrollment is served on the HTTP port the installer already opens, so
  nothing is unreachable today; a deployment that restricts that port silently breaks
  enrollment instead of being told to allow it. A service entry makes the requirement explicit.
* **No SELinux rules for the daemon's paths.** FreeIPA's own policy module labels
  `/var/lib/ipa/ku` and `/run/ipa/kuipad.sock` only through the generic
  `ipa_var_lib_t` / `ipa_var_run_t` patterns, and grants `httpd_t` a stream connect to
  `ipa_custodia_stream_connect` — not to `ipa_var_run_t`. What is missing is a type of its own
  for the key directory and an explicit allow for httpd to reach the socket; a new type would
  confine both. An enforcing deployment hits this; a container deployment with labels disabled
  never sees it.

No temporary-file entry is missing: `init/tmpfilesd/ipa.conf.in` already creates `/run/ipa`, the
socket unit creates the socket, and `/var/lib/ipa/ku` is persistent state the installer creates.

### Backup and Restore

Nothing new needs to be backed up and `ipa-backup` / `ipa-restore` need no change for
these commands: the stage record and the escrow bindings are directory data, and the
daemon's configuration and key directory are already archived. A host staged before a
backup restores as a stage; if its validity passed while the server was down it is
simply expired, and `ipa host-mod --pq-stage` mints a new one. A restored server
keeps its anchor, so `pq-anchor-show` after a restore reports the thumbprint hosts
already pinned — no re-pinning, no re-issued strings.

Two consequences a restore makes visible: a host disabled before the backup is still
locked after it, so its sealed keytabs stay shut until `ipa host-enable` runs; and a
string minted before the backup but never spent is still spendable until its expiry — a
backup does not retire a credential.

## Feature Management

### UI

The classic Web UI already carries the one-time-password workflow end to end: the option on the host
add dialog, the panel that prints the password after a successful add, and the Disable action.
Extending it is mechanical — the enrollment string joins that panel, and an Enable action appears
beside Disable when the entry is locked. The classic UI shows no server state, so `pq-anchor-show`
has no classic-UI surface.

The modern Web UI has host settings and a user enable/disable modal but no pages for these objects.
What this design needs there is two views on the host settings page — the registered recovery
bindings and the staged state — plus an Enable/Disable pair following that user modal's shape. A
page listing the realm's anchors is out of scope.

### CLI

These names are proposals for behaviour, to be renamed during implementation. The
first group is what runs today and is the path this design must keep working; the
rest is not implemented.

| Command | Options | Description |
| --- | --- | --- |
| **Today: the daemon's own commands** | | |
| `ipa host-add` | `--random` | This command creates a host and its one-time password and prints the password. It writes no Kerberos key. |
| `kuipad enrollment-string` | `--days N` | Run on a server, this command prints `ipa-ku1:REALM:anchor:expiry` for that server's anchor. The string carries no secret, so the caller appends the password. |
| `kuipa enroll` | `--enrollment-file FILE`, `--hostname HOST`, `--ldap-otp` | Run on the host, this command spends a string and installs the keytab. `--ldap-otp` is required for a password-only host because the KDC cannot authenticate one. |
| `kuipa prepare`, `kuipa enroll --bundle` | | Run on the host, these commands create a key pair and open a staged bundle with no network. |
| `kuipa status`, `kuipa check` | | Host-side diagnosis of enrollment state, anchors and seals; not framework commands and not intended to become one. |
| **Planned on the server** | | |
| `ipa host-add`, `ipa host-mod` | `--random`, `--pq-days N` | This command also mints an enrollment string for this server's anchor and prints it beside the random password, so the authorization and the credential come from one call. |
| `ipa host-add`, `ipa host-mod` | `--pq-stage` | This command stages a host: the server generates the shared secret, the string carries it, and the host's keys are created before its first contact. |
| `ipa host-add`, `ipa host-mod` | `--pq-recipient=FILE`, `--pq-bundle=FILE` | This command stages a host against a public key the host generated, and writes the signed bundle the host will open offline. |
| `ipa host-show` | (output) | This command reports a host's staged state — recipient and expiry — and never prints a secret. |
| `ipa pq-anchor-show` | `[--name THUMBPRINT]` | This command lists the anchors of the server it is run against, the anchors that server vouches for, and their validity. |
| `ipa server-show` | (output) | This command shows this server's own anchor thumbprint and validity. |
| `ipa host-mod`, `ipa service-mod`, `ipa user-mod` | `--clear-pq-escrow` | This command removes an entry's recovery registrations and nothing else. |
| `ipa host-disable`, `ipa service-disable` | (behaviour) | These commands also mark the principal inactive, so a disabled host cannot recover its sealed keytabs. |
| `ipa host-enable`, `ipa service-enable` | | This command removes that mark again. |
| **Planned on the client** | | |
| `ipa-client-install` | `--pq-enroll` | This installation enrolls the host through the post-quantum exchange instead of `ipa-join`, using a string the provisioning system supplied. |
| `ipa-client-install` | `--no-pq` | This installation uses `ipa-join` even where the realm offers the post-quantum path. An opt-out, not a default. |
| `ipa-client-install` | `--pq-bundle=FILE` | This installation opens a staged bundle instead of contacting a server. |

Trust enrollment — an invitation from one realm consumed by another — is a separate
design and is not specified here.

### Configuration

No new configuration file, and none of these commands needs one. A stage's lifetime is a
command option; the daemon's settings stay in `/etc/ipa/kuipad.json`, written by the
installer. Two of those settings decide what the commands can do, and explain a refusal an
administrator would otherwise chase: the anchor role, without which a server cannot mint a
string or stage a host (there `--random` still works exactly as today); and the peer list,
which is what the advertisement publishes and `pq-anchor-show` displays, written by the
installer and the daemon rather than by an administrator.

Nothing turns staging on for a realm: `--pq-stage` is per host, per call. The client
enrollment step is opt-in per installation, so no realm-wide default changes and a client
without the option installs exactly as today. `nsAccountLock` on disable gets no switch: a
lock an administrator could turn off would not be a lock, and the escape hatch is
`host-enable`.

## Upgrade

`ipa-server-upgrade` needs no new upgrade step: it applies every update file and the
external schema directory, then re-writes the daemon's configuration and proxy before
restarting it. The new permissions arrive in the enrollment update file with no separate
code, and the oddjob method is registered by the package's upgrade scriptlet, which
already reloads the helper daemon.

Upgrading changes no existing host: no attribute is written, no key is touched, and hosts
disabled earlier stay unlocked until `host-disable` is run again for them. A realm installed
before the daemon existed gains it by installing the package and re-running the server
configuration; an upgrade alone does not add the daemon.

## Test plan

Unit, in the host and service plugin suites:

* `host-add --random --pq-days 14` returns the password **and** a string whose anchor field
  equals the thumbprint the daemon reports for that server; the entry has `userPassword` and no
  `krbPrincipalKey`. An out-of-range `--pq-days` is a validation error.
* `--pq-stage` adds a full-length random secret as the string's fifth field, and
  `host-show --all --raw` shows the stage with that expiry and no secret or password.
  `--pq-recipient=FILE` records that key's thumbprint and writes the bundle; a malformed key is a
  validation error; re-staging leaves one record.
* On a server whose daemon has no anchor role, `--random` returns the password and no string, and
  `--pq-stage` reports the daemon's reason, not a traceback.
* `host-disable` then `host-show --all` shows `nsAccountLock`; `host-enable` removes it and a
  second `host-enable` reports it was not locked — the pair behaves like `user-disable` /
  `user-enable`. A master is still refused; a host with no key and no certificate now succeeds.
* `--clear-pq-escrow` is a no-op without bindings, removes them otherwise while leaving the key
  and stage untouched, and is refused without the new permission.
* `pq-anchor-show` returns the anchors of the server that answered; `--name` with an unknown
  thumbprint is an empty result.

Integration: the forced client re-enrollment suite gains the counterpart of its disabled-host test
— disable, re-enrol fails; enable, re-enrol succeeds — and the CA-less suite's host-disable test
must still pass. The backup-and-restore suite disables a host with recovery registrations,
restores, and asserts it stays locked until `host-enable` runs.

End-to-end, in the kuipa deployment: hosts prepared by `host-add --random --pq-days 14` and by
`--pq-stage` enroll against a real server, and after the join `host-show --all --raw` shows no
`userPassword` and no `krbPrincipalExpiration` for either. Such a host fails to open its
sealed keytab after `host-disable` and opens it after `host-enable`.

## Troubleshooting and debugging

No new daemons and no new files, so the diagnosis path is the existing one with one extra hop.

* **Files relied on**: `/etc/ipa/kuipad.json` and `/var/lib/ipa/ku/`, both root-only and read only
  by the helper, the daemon's own keytab, and the target host's entry. A staging failure is almost
  always one of those being absent on that server.
* **Where a failure surfaces**: the helper's output is returned as command messages, as the
  connection-check command already does, so a staging failure appears in `ipa` output rather than
  only in a log; the daemon logs each stage it writes and consumes to the journal.
* **Which step failed**: run the daemon's own command on the server. "This server has no anchor
  role" is a configuration answer, not a framework bug; a thumbprint from the daemon that differs
  from `pq-anchor-show` means the command reached a different server. The daemon's local socket
  answers a staging request from a shell when the helper path is suspect.
* **Sealed keytabs that stop opening**: the unseal check consults the host's lock, the registered
  binding and the key's expiry, so `host-show --all` and the journal refusals separate the new
  cause from the old ones.
* **Debug logging**: there is no `ipa server-mod` debug setting; use the per-command debug flag or
  the IPA debug setting, and run the helper by hand as root — it prints exactly what the plugin saw.
  A `--clear-pq-escrow` refusal naming access control means the caller lacks the new privilege,
  which `ipa permission-show` confirms.

