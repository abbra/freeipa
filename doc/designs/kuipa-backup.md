# Sealed and signed backups with kuipa

## Overview

`ipa-backup` makes the one file an administrator reaches for when
everything else has failed. It holds the CA and KRA keys, the Directory
Manager password hash, the Kerberos master key and, on a server with
kuipa, kuipad's key directory (`/var/lib/ipa/ku`, which sits under
`/var/lib/ipa` and so is already part of every full backup). Anyone who
can read it owns the realm, and anyone who can make one that
`ipa-restore` accepts owns the realm too.

Today the only protection is the `--gpg` option, and it has two gaps
that matter in exactly the case backups exist for, the loss of every
server:

- **The key is on the server that died.** `encrypt_file()` runs
  `gpg --batch --default-recipient-self --encrypt`, so the decryption key
  lives in the `GNUPGHOME` of the host that made the backup. Unless the
  administrator exported it by hand, the backups die with the server.
- **Nothing is signed.** GnuPG is asked only to encrypt. `ipa-restore`
  cannot tell a backup a master made from one that someone dropped into
  the backup repository.

This document adds a second choice, `ipa-backup --kuipa`, which fixes
both. The backup is **sealed** to a recovery key that exists only as
printed papers, so no server can open it, and **signed** by the realm, so
`ipa-restore` refuses anything the realm did not make. The mechanism (the
file format, the commands, the cryptography, the threat analysis) is in
kuipa's `docs/DESIGN-backup.md`. This document covers only what FreeIPA
does with it. `--gpg` stays as it is; the two options exclude each other.

The kuipa commands are implemented. The FreeIPA changes described here
are implemented and unit tested; restoring a real server from a sealed
backup has not yet been run end to end.

## Use cases

**UC1: the nightly backup.** Cron runs `ipa-backup --kuipa` on a master.
The result is a sealed file and its signatures. Nothing on the server,
including root, can open the backup.

**UC2: everything is gone.** All servers are lost. On a new host with the
same name as the backup's host and the same IPA release installed (but
nothing configured: `ipa-restore` restores from nothing in that case), the
administrator fetches the backup from the repository, collects two of the
three papers, the recovery passphrase and the realm card, and runs
`ipa-restore`. The restored server has the old anchors and keys, so
enrolled clients carry on working.

**UC3: a planted file.** Someone puts a backup of their own making into
the repository. `ipa-restore` stops at the signature check, before it asks
for the papers and before anything is decrypted.

## How to use

### One time: make the recovery key

On any machine with the `kuipa` package (it does not need to be a server,
a ticket, or a network):

```console
# kuipa backup key create --realm EXAMPLE.TEST --threshold 2 --shares 3 \
        --out /root/backup-recipient.json
```

This asks for a recovery passphrase (at least 16 characters) and prints
three pages of words. Any two pages and the passphrase rebuild the key.
Print the pages and keep them in different places, and keep the passphrase
apart from all of them. Then check that two pages really work:

```console
# kuipa backup key check --recipient /root/backup-recipient.json < two-pages.txt
```

`backup-recipient.json` contains only the public key. It is not secret.

### On the first master: back up

```console
# ipa-backup --kuipa --kuipa-recipient /root/backup-recipient.json
# kuipa backup card > card.txt
```

`ipa-backup` copies the recipient file to `/etc/ipa/kuipa-backup.json`,
and that file is itself part of the backup, so a restored server keeps
sealing to the same key. Later runs, on this or any other master that has
the file, need only `ipa-backup --kuipa`. The card lists the realm, the
recovery key id and the realm's anchor thumbprints. Print it and keep it
with the papers. It is what lets a brand-new host decide whether a backup
is genuine.

The backup directory then holds:

```text
ipa-full-2026-11-09-03-00-00/
    ipa-full.tar.kuipa          the sealed backup
    ipa-full.tar.kuipa.kusig    the realm's signature of it
    header                      plain metadata: type, host, time, version
    header.kusig                the realm's signature of the header
```

### After the loss: restore

On the new host, with the papers' words on standard input:

```console
# ipa-restore --kuipa-realm EXAMPLE.TEST \
        --kuipa-anchor dgt-VqrSdFC64H8R98ehg3kLJ8FzijPp84MmUJHHKMk \
        /var/lib/ipa/backup/ipa-full-2026-11-09-03-00-00 < two-pages.txt
```

The realm and anchors come from the card; give `--kuipa-anchor` once per
anchor. You do not say that the backup is a kuipa one: `ipa-restore`
recognises the `.kuipa` file. It then, in this order:

1. verifies the signatures of the backup and of `header` against the
   anchors, and stops if they fail;
2. reads the papers and the passphrase (from the terminal, or from
   `--kuipa-recovery-file`);
3. decrypts into its temporary directory and carries on exactly as for any
   other backup.

Other options: `--kuipa-signer host/ipa1.example.test` insists on a
particular signing host, and `--kuipa-no-verify` opens a backup whose
signature files are lost (and says so in the log). Without
`--kuipa-realm` and `--kuipa-anchor`, `ipa-restore` uses the host's own
kuipa anchors, which a host being rebuilt from nothing does not have.

As with every restore, the host name must match the backup's, the restored
server becomes the data master, and the other servers must be
re-initialised from it.

## Design

### What changes in `ipa-backup`

- `--kuipa` and `--kuipa-recipient FILE` are new, and `--kuipa` cannot be
  combined with `--gpg`. The recipient file defaults to
  `/etc/ipa/kuipa-backup.json` (`paths.KUIPA_BACKUP_CONF`).
- Like the GnuPG option, it checks early. Before any service is stopped,
  `validate_options` has kuipa seal a scratch file to the recipient, so a
  missing or broken recipient file is an error at the start and not after
  an hour of work.
- Sealing replaces the `tar` and `encrypt_file` steps by one pipeline,
  `tar -czf - . | kuipa backup seal`, so no plaintext tarball is written.
  If `tar` fails, the half-written sealed file is deleted: a sealed
  truncated archive would otherwise look like a good backup.
- Signing happens at the very end, after the services have been restarted
  (which the code already waits for before compressing) because a stopped
  kuipad cannot sign. `ipa-backup` gets a ticket from the host keytab,
  as `host/<fqdn>`, in a throw-away credential cache, and runs
  `kuipa sign blob --purpose ipa-backup` over the sealed file and the
  `header`.
- A signing failure is an error: the command exits non-zero, keeps what it
  made, and says how to sign by hand. A kuipa backup without signatures is
  one `ipa-restore` refuses, so pretending it succeeded would be worse.
- `paths.KUIPA_BACKUP_CONF` is added to the backed-up files. Separately,
  a backup that holds kuipad's keys and is neither sealed nor
  GPG-encrypted now logs a warning.

### What changes in `ipa-restore`

- `.kuipa` next to the `header` selects the kuipa path, `.gpg` selects
  GnuPG, as before. The new options are described above and are passed on
  to `kuipa backup open`.
- The signature is checked before the restore has touched any service,
  because `extract_backup()` runs before `ipactl stop`.
- The decrypted tarball goes to the restore's existing 0700 temporary
  directory and is removed after extraction, as with GnuPG. Streaming it
  straight into `tar` is a possible later optimisation.
- Restoring the key directory needs no new code: it is part of the tarball
  like every other file under `/var/lib/ipa`.

### Who may sign a backup

Signing is governed by the realm's signing policy, the JSON in
`ipaKUSignPolicy` on `cn=sign-policy,cn=kuipa,cn=etc`. For new realms
`install/updates/74-kuipa.update` sets a default that lets the host group
`ipaservers` sign the purpose `ipa-backup`:

```json
{"purposes": {"ipa-backup": {"groups": ["ipaservers"]}}}
```

The update uses `default:`, which only applies when the attribute is
absent. A realm that already has a signing policy is left alone, and its
administrator adds the purpose by hand, which is also how to narrow it to
particular hosts.

### The recipient file is trusted by whoever can write it

The recipient file is public, but the host trusts it. An attacker with
root on a master could replace it, and later backups would be sealed to
the attacker's key. Such an attacker already holds every secret in those
backups, so the file is not an additional exposure. To confirm which key
the backups use, compare the key id in `/etc/ipa/kuipa-backup.json` with
the one on the card, or run `kuipa backup key check` against it.

### What stays out

- Removing `--gpg`.
- Backing up kuipa's client-side state on enrolled clients.
- Preventing the restore of an *old* backup. A signature says which master
  made the backup and when, not that it is the newest.
- Restoring into a running realm from papers. This is a total-loss path;
  everything else restores as it always did.

## Implementation

| file | change |
|---|---|
| `ipaplatform/base/paths.py` | `KUIPA_BACKUP_CONF` |
| `ipaserver/install/ipa_backup.py` | options, early check, `kuipa_seal`, `kuipa_sign`, the file list |
| `ipaserver/install/ipa_restore.py` | `.kuipa` detection, `kuipa_open`, the `--kuipa-*` options |
| `install/updates/74-kuipa.update` | the default `ipa-backup` signing policy |
| `install/tools/man/ipa-backup.1`, `ipa-restore.1` | the options |
| `ipatests/test_ipaserver/test_backup_kuipa.py` | unit tests with a stub `kuipa` (what is passed to it, a failed `tar` leaves no file, signing as the host, signature options) |

Still to do: an integration test in `ipatests/test_integration` that backs
up with `--kuipa`, destroys the master, restores a fresh one from the
papers' words, checks that an enrolled client still works, and checks that
a flipped byte and a missing signature are refused; and the same scenario
for the ci-freeipa `kuipa-install` preset, whose steps are written down in
the preset's header but have not been run.

## Dependencies

The kuipa package must provide `kuipa backup key|seal|open|card` and
`kuipa sign verify --realm --anchor` (kuipa `docs/DESIGN-backup.md`).
FreeIPA only calls them.
