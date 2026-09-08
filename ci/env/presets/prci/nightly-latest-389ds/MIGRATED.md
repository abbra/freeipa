# PRCI -> freeipa-env migration: nightly_latest_389ds.yaml

Source: `../../ipatests/prci_definitions/nightly_latest_389ds.yaml`

- migrated: 48
- skipped: 1

## Skipped

- `389ds-fedora/build`: class Build: replaced by the freeipa-ci image pipeline

## Migrated

### `simple_replication`  (integration, 2 IPA host(s))

- test: `test_integration/test_simple_replication.py`

### `test_commands`  (integration, 3 IPA host(s))

- test: `test_integration/test_commands.py::TestIPACommand`

### `test_commands_2`  (integration, 2 IPA host(s))

- test: `test_integration/test_commands.py::TestIPACommandWithoutReplica`
- test: `test_integration/test_commands.py::TestIPAautomount`

### `test_server_del`  (integration, 4 IPA host(s))

- test: `test_integration/test_server_del.py`

### `test_installation_testinstallwithca1`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA1`

### `test_caless_testserverinstall`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestServerInstall`

### `test_caless_testreplicainstall`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestReplicaInstall`

### `test_caless_testclientinstall`  (integration, 3 IPA host(s))

- test: `test_integration/test_caless.py::TestClientInstall`

### `test_caless_testcertinstall`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestCertInstall`

### `test_backup_and_restore_testuserrootfilesownershippermission`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestUserRootFilesOwnershipPermission`

### `test_backup_and_restore_testbackupandrestore`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestore`

### `test_backup_and_restore_testbackupandrestorewithdnssec`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestoreWithDNSSEC`

### `test_backup_and_restore_testbackupreinstallrestorewithdnssec`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupReinstallRestoreWithDNSSEC`

### `test_backup_and_restore_testbackupandrestorewithdns`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestoreWithDNS`

### `test_backup_and_restore_testbackupreinstallrestorewithdns`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupReinstallRestoreWithDNS`

### `test_backup_and_restore_testbackupandrestorewithkra`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestoreWithKRA`

### `test_backup_and_restore_testbackupreinstallrestorewithkra`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupReinstallRestoreWithKRA`

### `test_backup_and_restore_testbackupandrestorewithreplica`  (integration, 4 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestoreWithReplica`

### `test_backup_and_restore_testbackupandrestoredmpassword`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestoreDMPassword`

### `test_backup_and_restore_testreplicainstallafterrestore`  (integration, 4 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestReplicaInstallAfterRestore`

### `test_dnssec`  (integration, 4 IPA host(s))

- test: `test_integration/test_dnssec.py`

### `test_replica_promotion_testreplicapromotionlevel1`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaPromotionLevel1`

### `test_replica_promotion_testprohibitreplicauninstallation`  (integration, 4 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestProhibitReplicaUninstallation`

### `test_replica_promotion_testhiddenreplicapromotion`  (integration, 4 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestHiddenReplicaPromotion`

### `test_upgrade`  (integration, 2 IPA host(s))

- test: `test_integration/test_upgrade.py`

### `test_topology_testcaspecificruvs`  (integration, 5 IPA host(s))

- test: `test_integration/test_topology.py::TestCASpecificRUVs`

### `test_topology_testtopologyoptions`  (integration, 5 IPA host(s))

- test: `test_integration/test_topology.py::TestTopologyOptions`

### `test_replication_layouts_testlinetopologywithoutca`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestLineTopologyWithoutCA`

### `test_replication_layouts_testlinetopologywithca`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestLineTopologyWithCA`

### `test_replication_layouts_testlinetopologywithcakra`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestLineTopologyWithCAKRA`

### `test_replication_layouts.py_teststartopologywithoutca`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestStarTopologyWithoutCA`

### `test_replication_layouts_teststartopologywithca`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestStarTopologyWithCA`

### `test_replication_layouts_teststartopologywithcakra`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestStarTopologyWithCAKRA`

### `test_replication_layouts_testcompletetopologywithoutca`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestCompleteTopologyWithoutCA`

### `test_replication_layouts_testcompletetopologywithca`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestCompleteTopologyWithCA`

### `test_replication_layouts_testcompletetopologywithcakra`  (integration, 5 IPA host(s))

- test: `test_integration/test_replication_layouts.py::TestCompleteTopologyWithCAKRA`

### `test_client_uninstallation`  (integration, 3 IPA host(s))

- test: `test_integration/test_uninstallation.py`

### `customized_ds_config_install`  (integration, 2 IPA host(s))

- test: `test_integration/test_customized_ds_config_install.py`

### `dns_locations`  (integration, 4 IPA host(s))

- test: `test_integration/test_dns_locations.py`

### `external_ca_testexternalcadirsrvstop`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCAdirsrvStop`

### `mask`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestMaskInstall`

### `test_ipahealthcheck`  (integration, 3 IPA host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheck`

### `automember`  (integration, 2 IPA host(s))

- test: `test_integration/test_automember.py`

### `test_fips`  (integration, 3 IPA host(s))

- test: `test_integration/test_fips.py`

### `test_pwpolicy`  (integration, 2 IPA host(s))

- test: `test_integration/test_pwpolicy.py`

### `test_external_idp`  (integration, 4 IPA host(s))

- test: `test_integration/test_idp.py`

### `test_sysaccounts`  (integration, 2 IPA host(s))

- test: `test_integration/test_sysaccounts.py`

### `test_ds_migration`  (integration, 3 IPA host(s))

- test: `test_integration/test_ds_migration.py`

