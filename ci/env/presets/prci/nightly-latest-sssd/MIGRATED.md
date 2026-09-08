# PRCI -> freeipa-env migration: nightly_latest_sssd.yaml

Source: `../../ipatests/prci_definitions/nightly_latest_sssd.yaml`

- migrated: 20
- skipped: 2

## Skipped

- `sssd-fedora/build`: class Build: replaced by the freeipa-ci image pipeline
- `sssd-fedora/nfs_automountdiscovery`: class RunPytest / topology ipa_ipa_trust: not mappable

## Migrated

### `test_commands`  (integration, 3 IPA host(s))

- test: `test_integration/test_commands.py::TestIPACommand`

### `test_commands_2`  (integration, 2 IPA host(s))

- test: `test_integration/test_commands.py::TestIPACommandWithoutReplica`
- test: `test_integration/test_commands.py::TestIPAautomount`

### `test_external_idp`  (integration, 4 IPA host(s))

- test: `test_integration/test_idp.py`

### `test_idviews`  (integration, 3 IPA host(s), 1 AD host(s))

- test: `test_integration/test_idviews.py`
- note: 1 external AD host(s) require manual setup (edit placeholders)

### `test_netgroup`  (integration, 2 IPA host(s))

- test: `test_integration/test_netgroup.py`

### `test_nfs_testipaclientautomountfilerestore`  (integration, 4 IPA host(s))

- test: `test_integration/test_nfs.py::TestIpaClientAutomountFileRestore`

### `test_otp`  (integration, 2 IPA host(s))

- test: `test_integration/test_otp.py`

### `test_replica_promotion_testreplicapromotionlevel1`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaPromotionLevel1`

### `test_replica_promotion_testunprivilegeduserpermissions`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestUnprivilegedUserPermissions`

### `test_replica_promotion_testwrongclientdomain`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestWrongClientDomain`

### `test_smb`  (integration, 3 IPA host(s), 1 AD host(s))

- test: `test_integration/test_smb.py`
- note: 1 external AD host(s) require manual setup (edit placeholders)

### `test_sssd`  (integration, 2 IPA host(s), 3 AD host(s))

- test: `test_integration/test_sssd.py`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_subids`  (integration, 3 IPA host(s))

- test: `test_integration/test_subids.py`

### `test_sudo`  (integration, 3 IPA host(s))

- test: `test_integration/test_sudo.py`

### `test_trust`  (integration, 2 IPA host(s), 3 AD host(s))

- test: `test_integration/test_trust.py::TestTrust`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_trust_autoprivate`  (integration, 2 IPA host(s), 3 AD host(s))

- test: `test_integration/test_trust.py::TestNonPosixAutoPrivateGroup`
- test: `test_integration/test_trust.py::TestPosixAutoPrivateGroup`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_user_permissions_testuserpermissions`  (integration, 3 IPA host(s))

- test: `test_integration/test_user_permissions.py::TestUserPermissions`

### `test_trust_functional`  (integration, 3 IPA host(s), 3 AD host(s))

- test: `test_integration/test_trust_functional.py`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_hbac_functional`  (integration, 4 IPA host(s))

- test: `test_integration/test_hbac_functional.py`

### `test_ipa_join`  (integration, 3 IPA host(s))

- test: `test_integration/test_ipa_join.py`

