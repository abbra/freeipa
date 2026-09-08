# PRCI -> freeipa-env migration: gating.yaml

Source: `../../ipatests/prci_definitions/gating.yaml`

- migrated: 31
- skipped: 1

## Skipped

- `fedora-latest/build`: class Build: replaced by the freeipa-ci image pipeline

## Migrated

### `test_installation_testinstallmaster`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallMaster`

### `simple_replication`  (integration, 2 IPA host(s))

- test: `test_integration/test_simple_replication.py`

### `test_caless_testserverreplicacalesstocafull`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestServerReplicaCALessToCAFull`

### `test_external_ca_testexternalca`  (integration, 3 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCA`
- test: `test_integration/test_external_ca.py::TestExternalCAConstraints`

### `test_external_ca_testselfexternalself`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestSelfExternalSelf`
- test: `test_integration/test_external_ca.py::TestExternalCAInstall`

### `external_ca_templates`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCAProfileScenarios`

### `test_topologies`  (integration, 2 IPA host(s))

- test: `test_integration/test_topologies.py`

### `test_sudo`  (integration, 3 IPA host(s))

- test: `test_integration/test_sudo.py`

### `test_commands`  (integration, 3 IPA host(s))

- test: `test_integration/test_commands.py::TestIPACommand`

### `test_commands_2`  (integration, 2 IPA host(s))

- test: `test_integration/test_commands.py::TestIPACommandWithoutReplica`
- test: `test_integration/test_commands.py::TestIPAautomount`

### `test_idm_api`  (integration, 3 IPA host(s))

- test: `test_integration/test_idm_api.py`

### `test_kerberos_flags`  (integration, 3 IPA host(s))

- test: `test_integration/test_kerberos_flags.py`

### `test_forced_client_enrolment`  (integration, 3 IPA host(s))

- test: `test_integration/test_forced_client_reenrollment.py`

### `test_advise`  (integration, 3 IPA host(s))

- test: `test_integration/test_advise.py`

### `test_testconfig`  (integration, 2 IPA host(s))

- test: `test_integration/test_testconfig.py`

### `test_service_permissions`  (integration, 2 IPA host(s))

- test: `test_integration/test_service_permissions.py`

### `test_netgroup`  (integration, 2 IPA host(s))

- test: `test_integration/test_netgroup.py`

### `test_authconfig`  (integration, 3 IPA host(s))

- test: `test_integration/test_authselect.py`

### `test_replica_promotion_testsubcakeyreplication`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestSubCAkeyReplication`

### `test_dnssec_testinstalldnssecfirst`  (integration, 2 IPA host(s))

- test: `test_integration/test_dnssec.py::TestInstallDNSSECFirst`

### `test_membermanager`  (integration, 2 IPA host(s))

- test: `test_integration/test_membermanager.py`

### `test_adtrust_install`  (integration, 2 IPA host(s))

- test: `test_integration/test_adtrust_install.py`

### `test_cert`  (integration, 3 IPA host(s))

- test: `test_integration/test_cert.py`

### `test_upgrade`  (integration, 2 IPA host(s))

- test: `test_integration/test_upgrade.py`

### `test_subids`  (integration, 3 IPA host(s))

- test: `test_integration/test_subids.py`

### `test_ipalib_install`  (integration, 2 IPA host(s))

- test: `test_ipalib_install/test_kinit.py`

### `test_external_idp`  (integration, 4 IPA host(s))

- test: `test_integration/test_idp.py`

### `test_ipahealthcheck_adtrust`  (integration, 2 IPA host(s), 3 AD host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckWithADtrust`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_sysaccounts`  (integration, 2 IPA host(s))

- test: `test_integration/test_sysaccounts.py`

### `test_hbac_functional`  (integration, 4 IPA host(s))

- test: `test_integration/test_hbac_functional.py`

### `test_ipa_join`  (integration, 3 IPA host(s))

- test: `test_integration/test_ipa_join.py`

