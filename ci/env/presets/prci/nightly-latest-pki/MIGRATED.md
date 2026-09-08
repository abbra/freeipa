# PRCI -> freeipa-env migration: nightly_latest_pki.yaml

Source: `../../ipatests/prci_definitions/nightly_latest_pki.yaml`

- migrated: 91
- skipped: 1

## Skipped

- `pki-fedora/build`: class Build: replaced by the freeipa-ci image pipeline

## Migrated

### `simple_replication`  (integration, 2 IPA host(s))

- test: `test_integration/test_simple_replication.py`

### `test_external_ca_testexternalca`  (integration, 3 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCA`

### `test_external_ca_testselfexternalself`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestSelfExternalSelf`
- test: `test_integration/test_external_ca.py::TestExternalCAInstall`

### `external_ca_templates`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCAProfileScenarios`

### `test_vault`  (integration, 2 IPA host(s))

- test: `test_integration/test_vault.py`

### `test_forced_client_enrolment`  (integration, 3 IPA host(s))

- test: `test_integration/test_forced_client_reenrollment.py`

### `test_installation_testinstallwithca1`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA1`

### `test_installation_testinstallwithca2`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA2`

### `test_installation_testinstallca`  (integration, 4 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallCA`

### `test_installation_testinstallwithca_kra1`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA_KRA1`

### `test_installation_testinstallwithca_kra2`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA_KRA2`

### `test_installation_testinstallwithca_dns1`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA_DNS1`

### `test_installation_testinstallwithca_dns2`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA_DNS2`

### `test_installation_testinstallwithca_dns3`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA_DNS3`

### `test_installation_testinstallwithca_dns4`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA_DNS4`

### `test_installation_testinstallwithca_kra_dns1`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA_KRA_DNS1`

### `test_installation_testinstallwithca_kra_dns2`  (integration, 5 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithCA_KRA_DNS2`

### `test_installation_testinstallmaster`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallMaster`

### `test_installation_testinstallmasterkra`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallMasterKRA`

### `test_installation_testinstallmasterdns`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallMasterDNS`

### `test_installation_testinstallmasterdnsrepeatedly`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallMasterDNSRepeatedly`

### `test_installation_testinstallmasterreservedipasforwarder`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallMasterReservedIPasForwarder`

### `test_installation_testinstallwithsha384withrsa`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallwithSHA384withRSA`

### `test_caless_testserverinstall`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestServerInstall`

### `test_caless_testreplicainstall`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestReplicaInstall`

### `test_caless_testclientinstall`  (integration, 3 IPA host(s))

- test: `test_integration/test_caless.py::TestClientInstall`

### `test_caless_testipacommands`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestIPACommands`

### `test_caless_testcertinstall`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestCertInstall`

### `test_caless_testpkinit`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestPKINIT`

### `test_caless_testserverreplicacalesstocafull`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestServerReplicaCALessToCAFull`

### `test_caless_testreplicacalesstocafull`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestReplicaCALessToCAFull`

### `test_caless_testservercalesstoexternalca`  (integration, 2 IPA host(s))

- test: `test_integration/test_caless.py::TestServerCALessToExternalCA`

### `test_backup_and_restore_testbackupandrestorewithkra`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestoreWithKRA`

### `test_backup_and_restore_testbackupreinstallrestorewithkra`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupReinstallRestoreWithKRA`

### `test_backup_and_restore_testbackupandrestorewithreplica`  (integration, 4 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestoreWithReplica`

### `test_backup_and_restore_testreplicainstallafterrestore`  (integration, 4 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestReplicaInstallAfterRestore`

### `test_replica_promotion_testreplicapromotionlevel1`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaPromotionLevel1`

### `test_replica_promotion_testrenewalmaster`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestRenewalMaster`

### `test_replica_promotion_testsubcakeyreplication`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestSubCAkeyReplication`

### `test_replica_promotion_testreplicainstallcustodia`  (integration, 4 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaInstallCustodia`

### `test_upgrade`  (integration, 2 IPA host(s))

- test: `test_integration/test_upgrade.py`

### `test_topology_testcaspecificruvs`  (integration, 5 IPA host(s))

- test: `test_integration/test_topology.py::TestCASpecificRUVs`

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

### `test_webui_cert`  (base, 1 IPA host(s))

- test: `test_webui/test_cert.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_identity`  (base, 1 IPA host(s))

- test: `test_webui/test_automember.py`
- test: `test_webui/test_idviews.py`
- note: RunWebuiTests: browser/selenium not in image

### `dns_locations`  (integration, 4 IPA host(s))

- test: `test_integration/test_dns_locations.py`

### `external_ca_testexternalcadirsrvstop`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCAdirsrvStop`

### `external_ca_testexternalcainvalidcert`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCAInvalidCert`

### `external_ca_testmultipleexternalca`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestMultipleExternalCA`

### `test_ipahealthcheck`  (integration, 3 IPA host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheck`

### `test_ipahealthcheck_nodns_extca_file`  (integration, 2 IPA host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckWithoutDNS`
- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckWithExternalCA`
- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckFileCheck`

### `test_pkinit_install`  (integration, 3 IPA host(s))

- test: `test_integration/test_pkinit_install.py`

### `test_pkinit_manage`  (integration, 2 IPA host(s))

- test: `test_integration/test_pkinit_manage.py`

### `test_crlgen_manage`  (integration, 2 IPA host(s))

- test: `test_integration/test_crlgen_manage.py`

### `test_ca_custom_sdn`  (integration, 2 IPA host(s))

- test: `test_integration/test_ca_custom_sdn.py`

### `test_fips`  (integration, 3 IPA host(s))

- test: `test_integration/test_fips.py`

### `test_acme`  (integration, 3 IPA host(s))

- test: `test_integration/test_acme.py::TestACME`
- test: `test_integration/test_acme.py::TestACMECALess`
- test: `test_integration/test_acme.py::TestACMEwithExternalCA`
- test: `test_integration/test_acme.py::TestACMERenew`

### `test_acme_prune`  (integration, 3 IPA host(s))

- test: `test_integration/test_acme.py::TestACMEPrune`

### `test_cert_fix`  (integration, 2 IPA host(s))

- test: `test_integration/test_ipa_cert_fix.py`

### `test_external_idp`  (integration, 4 IPA host(s))

- test: `test_integration/test_idp.py`

### `test_random_serial_numbers_testinstallwithca_dns1_rsn`  (integration, 5 IPA host(s))

- test: `test_integration/test_random_serial_numbers.py::TestInstallWithCA_DNS1_RSN`

### `test_random_serial_numbers_testinstallwithca_kra1_rsn`  (integration, 5 IPA host(s))

- test: `test_integration/test_random_serial_numbers.py::TestInstallWithCA_KRA1_RSN`

### `test_random_serial_numbers_test_commands_rsn`  (integration, 3 IPA host(s))

- test: `test_integration/test_random_serial_numbers.py::TestIPACommand_RSN`

### `test_caless_testservercalesstoexternalca_rsn`  (integration, 2 IPA host(s))

- test: `test_integration/test_random_serial_numbers.py::TestServerCALessToExternalCA_RSN`
- test: `test_integration/test_random_serial_numbers.py::TestInstall_RSN_MDB`

### `test_random_serial_numbers_testrsnpkiconfig`  (integration, 5 IPA host(s))

- test: `test_integration/test_random_serial_numbers.py::TestRSNPKIConfig`

### `test_random_serial_numbers_testrsnvault`  (integration, 2 IPA host(s))

- test: `test_integration/test_random_serial_numbers.py::TestRSNVault`

### `test_hsm_testhsminstall`  (integration, 5 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMInstall`

### `test_hsm_testhsminstallpasswordfile`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMInstallPasswordFile`

### `test_hsm_testhsminstalladtrustbase`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMInstallADTrustBase`

### `test_hsm_testadtrustinstallwithdns_kra_adtrust`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestADTrustInstallWithDNS_KRA_ADTrust`

### `test_hsm_testhsmcertrenewal`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMcertRenewal`

### `test_hsm_testhsmcalesstoexternaltoselfsignedca`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMCALessToExternalToSelfSignedCA`

### `test_hsm_testhsmexternaltoselfsignedca`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMExternalToSelfSignedCA`

### `test_hsm_testhsmcertfix`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMcertFix`

### `test_hsm_testhsmcertfixkra`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMcertFixKRA`

### `test_hsm_testhsmcertfixreplica`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMcertFixReplica`

### `test_hsm_testhsmnegative`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMNegative`

### `test_hsm_testhsmacme`  (integration, 3 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMACME`

### `test_hsm_testhsmbackuprestore`  (integration, 2 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMBackupRestore`

### `test_hsm_testhsmacmeprune`  (integration, 3 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMACMEPrune`

### `test_hsm_testhsmvault`  (integration, 3 IPA host(s))

- test: `test_integration/test_hsm.py::TestHSMVault`

### `test_installation_testinstallkeysizes`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallKeySizes`

