# M-of-N approval of certificate issuance with kuipa

## Overview

kuipa seals can require `m` approvals from a named set before a server
releases its share of a file (kuipa `docs/DESIGN-approvals.md`). A
certificate request is not a file release, so IPA turns it into one: the
request is sealed to an approvals seal, and IPA sends it to the CA only
after opening it with an approved release request.

## How to use

1. With kuipa, create a seal that opens with a Kerberos ticket alone (no
   device factor), whose members include every requester (users or a group),
   and whose policy has `approvals` (`m`, the approvers, a window, `uses` 1).
2. Tie a profile to it. The command checks the seal: enabled, `approvals`
   set, a ticket factor, no device or passkey factor, no offline sessions.
   The link is the `ipaKUApprovalSeal` attribute of the profile entry, in the
   auxiliary class `ipaKUApprovalGated`, which any entry whose use needs
   approval may carry (other workflows reuse it);
   `ipa certprofile-del-approval` removes it.

   ```console
   # ipa certprofile-add-approval caIPAserviceCert --seal admin/certs
   ```

3. A requester runs `ipa cert-request` as usual. For such a profile nothing
   is issued; the error carries an approval ID.
4. Approvers list and inspect requests, then decide:

   ```console
   # ipa approval-find --kind=cert-request
   # ipa approval-show ID
   # ipa approval-approve ID      (or approval-deny)
   ```

5. The requester repeats the same `ipa cert-request` with `--approval-id ID`.

## Design

- `cert_request` (ipaserver/plugins/cert.py) runs every existing check
  first (CA ACL, SAN, principal rules), then asks
  `certapproval.approval_seal(profile)`. Without a seal nothing changes.
- First call: `create_approval` hands the canonical request
  `{requester, profile, ca, principal, csr}` to the generic store
  (`approval.create_request`), which seals it to the seal, runs
  `kuipa seal request` and stores an `ipaKUApprovalRequest` entry
  `cn=<id>,cn=approvals,cn=kuipa,cn=etc`. The entry has the common parts as
  attributes (`ipaKUApprovalKind` = `cert-request`, `…Requester`, `…Seal`,
  `…Release`, `…Sealed`) and the workflow's own part as the JSON
  `ipaKUApprovalData`, exactly what was sealed. Other workflows reuse the
  class with their own kind and data. All kuipa calls run with the caller's delegated
  credentials (`seal.kuipa_session`), so kuipad sees the real requester and
  never counts their own approval.
- Repeat call: `redeem_approval` compares the entry's kind, seal, requester
  and data and the opened plaintext with the arguments of this call, and opens the file with
  `kuipa seal open --request`. kuipad enforces approvals, the window, `uses`
  and that the opener is the requester. IPA then issues exactly the opened
  request.
- Anyone may add and read approval entries, so an entry is not trusted: the
  seal comes from the profile's current configuration, and the entry, the
  sealed file and the issuing call must agree.

## Other gated operations

The same store and the same `ipaKUApprovalGated` link serve two more
workflows; `approval.require_approval(kind, seal, document, approval_id,
reason)` is all a command calls.

- **Revoking certificates** (`cert-revoke`, kind `cert-revoke`): the link is
  on the CA entry, `ipa ca-add-revoke-approval CA --seal OWNER/NAME` and
  `ca-del-revoke-approval`. The sealed document is the CA, the serial and the
  reason, so an approval covers that revocation only. `cert-remove-hold` is
  not gated.
- **Retrieving a vault** (`vault-retrieve`, kind `vault-retrieve`): the link
  is on the vault entry, `ipa vault-add-approval NAME [--user|--service|
  --shared] --seal OWNER/NAME` and `vault-del-approval`. The check is in
  `vault_retrieve_internal` after `vault_show`, and the client passes
  `--approval-id` through. A vault's owners can write its attributes (the
  vault ACIs), so an owner can ungate their own vault by LDAP: the gate
  protects an owner from a single account acting alone only when the seal is
  set by someone else, or the owner is trusted not to remove it. Only
  asymmetric and symmetric vaults keep the data secret from the KRA's
  administrators too. Not run against a KRA (the test realm has none).

## Users of trusted (AD) domains

An AD user with an ID override in the default trust view is a user of the
IPA directory, and kuipa treats them as one (kuipa `DESIGN.md` §7.6.12):
they can be named in `approvals.from`, as a seal's manager, member or
depositor, and in the signing policy as `user@AD.REALM`, or reached through
an IPA group that holds the override
(`ipa group-add-member pki-approvers --idoverrideusers user@ad.example`).
They may be requesters and approvers here, and seal administrators through a
group in a role. They own no seal. A trusted realm's user with no override
is refused. `TestKuipaCertApprovalTrustedUser` runs this on a Samba AD DC.

## What stays out

- ACME, direct Dogtag/RA-agent access and `request certificate ignore
  caacl` holders are not gated; do not offer an approval profile to ACME.
- Approvers see the request's fields in `approval-show` (the data is what
  was sealed, checked at issuance), but kuipa approves a release request: an
  entry whose data differs from its sealed file fails at issuance, never issues.
- One issuance is enforced by kuipa's `uses`, which can be exceeded by
  releases on other servers within one replication delay.
- Pending entries are not purged; kuipa's window ends their usefulness.
- No notifications; `ipa approval-find` is the interface.
- Not run against a real realm: kuipa's approvals code has not yet run
  against FreeIPA, and the CLI shapes used here (`seal file|request|open`,
  `--json`) come from its help and source.
