# PRCI -> freeipa-env migration: nightly_latest_selinux.yaml

Source: `../../ipatests/prci_definitions/nightly_latest_selinux.yaml`

- migrated: 185
- skipped: 2

## Skipped

- `fedora-latest/build`: class Build: replaced by the freeipa-ci image pipeline
- `fedora-latest/nfs_automountdiscovery`: class RunPytest / topology ipa_ipa_trust: not mappable

## Migrated

### `simple_replication`  (integration, 2 IPA host(s))

- test: `test_integration/test_simple_replication.py`

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

### `test_kerberos_flags`  (integration, 3 IPA host(s))

- test: `test_integration/test_kerberos_flags.py`

### `test_http_kdc_proxy`  (integration, 3 IPA host(s), 1 AD host(s))

- test: `test_integration/test_http_kdc_proxy.py`
- note: 1 external AD host(s) require manual setup (edit placeholders)

### `test_fips`  (integration, 3 IPA host(s))

- test: `test_integration/test_fips.py`

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

### `test_vault`  (integration, 2 IPA host(s))

- test: `test_integration/test_vault.py`

### `test_authconfig`  (integration, 3 IPA host(s))

- test: `test_integration/test_authselect.py`

### `test_smb`  (integration, 3 IPA host(s), 1 AD host(s))

- test: `test_integration/test_smb.py`
- note: 1 external AD host(s) require manual setup (edit placeholders)

### `test_server_del`  (integration, 4 IPA host(s))

- test: `test_integration/test_server_del.py`

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

### `test_installation_testinstallmasterreplica`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallMasterReplica`

### `test_installation_testinstallreplicaagainstspecificserver`  (integration, 4 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallReplicaAgainstSpecificServer`

### `test_installation_testadtrustinstall`  (integration, 4 IPA host(s))

- test: `test_integration/test_installation.py::TestADTrustInstall`

### `test_installation_testadtrustinstallwithdns_kra_adtrust`  (integration, 4 IPA host(s))

- test: `test_integration/test_installation.py::TestADTrustInstallWithDNS_KRA_ADTrust`

### `test_installation_testkrainstallaftercertrenew`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestKRAinstallAfterCertRenew`

### `test_installation_testinstallwithoutsudo`  (integration, 3 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithoutSudo`

### `test_installation_testinstallwithoutnamed`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallWithoutNamed`

### `test_installation_testinstallwithsha384withrsa`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallwithSHA384withRSA`

### `test_idviews`  (integration, 3 IPA host(s), 1 AD host(s))

- test: `test_integration/test_idviews.py`
- note: 1 external AD host(s) require manual setup (edit placeholders)

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

### `test_backup_and_restore_testbackuproles`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupRoles`

### `test_dnssec`  (integration, 4 IPA host(s))

- test: `test_integration/test_dnssec.py`

### `test_replica_promotion_testreplicapromotionlevel1`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaPromotionLevel1`

### `test_replica_promotion_testunprivilegeduserpermissions`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestUnprivilegedUserPermissions`

### `test_replica_promotion_testprohibitreplicauninstallation`  (integration, 4 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestProhibitReplicaUninstallation`

### `test_replica_promotion_testwrongclientdomain`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestWrongClientDomain`

### `test_replica_promotion_testrenewalmaster`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestRenewalMaster`

### `test_replica_promotion_testreplicainstallwithexistingentry`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaInstallWithExistingEntry`

### `test_replica_promotion_testsubcakeyreplication`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestSubCAkeyReplication`

### `test_replica_promotion_testreplicainstallcustodia`  (integration, 4 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaInstallCustodia`

### `test_replica_promotion_testreplicainforwardzone`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaInForwardZone`

### `test_replica_promotion_testhiddenreplicapromotion`  (integration, 4 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestHiddenReplicaPromotion`

### `test_replica_promotion_testhiddenreplicakra`  (integration, 4 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestHiddenReplicaKRA`

### `test_replica_promotion_testreplicaconn`  (integration, 3 IPA host(s), 1 AD host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaConn`
- note: 1 external AD host(s) require manual setup (edit placeholders)

### `test_replica_promotion_testreplicapromotionrandompassword`  (integration, 2 IPA host(s))

- test: `test_integration/test_replica_promotion.py::TestReplicaPromotionRandomPassword`

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

### `test_installation_client`  (integration, 4 IPA host(s))

- test: `test_integration/test_installation_client.py`

### `test_user_permissions`  (integration, 3 IPA host(s))

- test: `test_integration/test_user_permissions.py`

### `test_webui_cert`  (base, 1 IPA host(s))

- test: `test_webui/test_cert.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_general`  (base, 1 IPA host(s))

- test: `test_webui/test_loginscreen.py`
- test: `test_webui/test_misc_cases.py`
- test: `test_webui/test_navigation.py`
- test: `test_webui/test_translation.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_host`  (base, 1 IPA host(s))

- test: `test_webui/test_host.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_host_net_groups`  (base, 1 IPA host(s))

- test: `test_webui/test_hostgroup.py`
- test: `test_webui/test_netgroup.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_identity`  (base, 1 IPA host(s))

- test: `test_webui/test_automember.py`
- test: `test_webui/test_idviews.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_network`  (base, 1 IPA host(s))

- test: `test_webui/test_automount.py`
- test: `test_webui/test_dns.py`
- test: `test_webui/test_vault.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_policy`  (base, 1 IPA host(s))

- test: `test_webui/test_hbac.py`
- test: `test_webui/test_krbtpolicy.py`
- test: `test_webui/test_pwpolicy.py`
- test: `test_webui/test_selinuxusermap.py`
- ... and 1 more
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_rbac`  (base, 1 IPA host(s))

- test: `test_webui/test_delegation.py`
- test: `test_webui/test_rbac.py`
- test: `test_webui/test_selfservice.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_server`  (base, 1 IPA host(s))

- test: `test_webui/test_config.py`
- test: `test_webui/test_range.py`
- test: `test_webui/test_realmdomains.py`
- test: `test_webui/test_topology.py`
- ... and 1 more
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_service`  (base, 1 IPA host(s))

- test: `test_webui/test_service.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_users`  (base, 1 IPA host(s))

- test: `test_webui/test_group.py`
- test: `test_webui/test_user.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_webui_subid`  (base, 1 IPA host(s))

- test: `test_webui/test_subid.py`
- note: RunWebuiTests: browser/selenium not in image

### `customized_ds_config_install`  (integration, 2 IPA host(s))

- test: `test_integration/test_customized_ds_config_install.py`

### `dns_locations`  (integration, 4 IPA host(s))

- test: `test_integration/test_dns_locations.py`

### `external_ca_testexternalcadirsrvstop`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCAdirsrvStop`

### `external_ca_testexternalcainvalidcert`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestExternalCAInvalidCert`
- test: `test_integration/test_external_ca.py::TestExternalCAInvalidIntermediate`

### `external_ca_testmultipleexternalca`  (integration, 2 IPA host(s))

- test: `test_integration/test_external_ca.py::TestMultipleExternalCA`

### `test_ipahealthcheck`  (integration, 3 IPA host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheck`

### `test_ipahealthcheck_caless`  (integration, 2 IPA host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIPAHealthcheckWithCALess`

### `test_ipahealthcheck_nodns_extca_file`  (integration, 2 IPA host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckWithoutDNS`
- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckWithExternalCA`
- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckFileCheck`

### `test_ipahealthcheck_cli_fsspace`  (integration, 2 IPA host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCLI`
- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckFilesystemSpace`

### `test_ipahealthcheck_adtrust`  (integration, 2 IPA host(s), 3 AD host(s))

- test: `test_integration/test_ipahealthcheck.py::TestIpaHealthCheckWithADtrust`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_ntp_options`  (integration, 3 IPA host(s))

- test: `test_integration/test_ntp_options.py::TestNTPoptions`

### `test_otp`  (integration, 2 IPA host(s))

- test: `test_integration/test_otp.py`

### `test_pkinit_install`  (integration, 3 IPA host(s))

- test: `test_integration/test_pkinit_install.py`

### `test_pkinit_manage`  (integration, 2 IPA host(s))

- test: `test_integration/test_pkinit_manage.py`

### `test_pki_config_override`  (integration, 2 IPA host(s))

- test: `test_integration/test_pki_config_override.py`

### `nfs_nsswitch_restore`  (integration, 4 IPA host(s))

- test: `test_integration/test_nfs.py::TestIpaClientAutomountFileRestore`

### `mask`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestMaskInstall`

### `hostname_validator`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestHostnameValidator`

### `automember`  (integration, 2 IPA host(s))

- test: `test_integration/test_automember.py`

### `test_crlgen_manage`  (integration, 2 IPA host(s))

- test: `test_integration/test_crlgen_manage.py`

### `test_integration_testipanotconfigured`  (integration, 2 IPA host(s))

- test: `test_integration/test_cli_ipa_not_configured.py::TestIPANotConfigured`

### `test_sssd`  (integration, 2 IPA host(s), 3 AD host(s))

- test: `test_integration/test_sssd.py`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_ca_custom_sdn`  (integration, 2 IPA host(s))

- test: `test_integration/test_ca_custom_sdn.py`

### `test_membermanager`  (integration, 2 IPA host(s))

- test: `test_integration/test_membermanager.py`

### `krbtpolicy`  (integration, 2 IPA host(s))

- test: `test_integration/test_krbtpolicy.py`

### `test_winsyncmigrate`  (base, 1 IPA host(s), 1 AD host(s))

- test: `test_integration/test_winsyncmigrate.py`
- note: 1 external AD host(s) require manual setup (edit placeholders)

### `test_trust`  (integration, 2 IPA host(s), 3 AD host(s))

- test: `test_integration/test_trust.py::TestTrust`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_trust_autoprivate`  (integration, 2 IPA host(s), 3 AD host(s))

- test: `test_integration/test_trust.py::TestNonPosixAutoPrivateGroup`
- test: `test_integration/test_trust.py::TestPosixAutoPrivateGroup`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_backup_and_restore_testbackupandrestoretrust`  (integration, 2 IPA host(s))

- test: `test_integration/test_backup_and_restore.py::TestBackupAndRestoreTrust`

### `test_adtrust_install`  (integration, 2 IPA host(s))

- test: `test_integration/test_adtrust_install.py`

### `test_cert`  (integration, 3 IPA host(s))

- test: `test_integration/test_cert.py`

### `test_epn`  (integration, 4 IPA host(s))

- test: `test_integration/test_epn.py`

### `test_acme`  (integration, 3 IPA host(s))

- test: `test_integration/test_acme.py::TestACME`
- test: `test_integration/test_acme.py::TestACMECALess`
- test: `test_integration/test_acme.py::TestACMEwithExternalCA`
- test: `test_integration/test_acme.py::TestACMERenew`

### `test_acme_prune`  (integration, 3 IPA host(s))

- test: `test_integration/test_acme.py::TestACMEPrune`

### `test_dns`  (integration, 2 IPA host(s))

- test: `test_integration/test_dns.py`

### `test_pwpolicy`  (integration, 2 IPA host(s))

- test: `test_integration/test_pwpolicy.py`

### `test_cert_fix`  (integration, 2 IPA host(s))

- test: `test_integration/test_ipa_cert_fix.py`

### `test_idrange_fix`  (integration, 2 IPA host(s))

- test: `test_integration/test_ipa_idrange_fix.py`

### `test_subids`  (integration, 3 IPA host(s))

- test: `test_integration/test_subids.py`

### `test_custom_plugins`  (integration, 2 IPA host(s))

- test: `test_integration/test_custom_plugins.py`

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

### `test_ipalib_install`  (integration, 2 IPA host(s))

- test: `test_ipalib_install/test_kinit.py`

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

### `test_ipamigrate`  (integration, 3 IPA host(s))

- test: `test_integration/test_ipa_ipa_migration.py::TestIPAMigrateCLIOptions`
- test: `test_integration/test_ipa_ipa_migration.py::TestIPAMigrationStageMode`
- test: `test_integration/test_ipa_ipa_migration.py::TestIPAMigrationProdMode`

### `test_ipamigrate_dns`  (integration, 3 IPA host(s))

- test: `test_integration/test_ipa_ipa_migration.py::TestIPAMigrationDNSRecords`

### `test_ipamigrate_mixedmode`  (integration, 2 IPA host(s))

- test: `test_integration/test_ipa_ipa_migration.py::TestIPAMigrationMixedOnlineOffline`
- test: `test_integration/test_ipa_ipa_migration.py::TestIPAMigrationPluginsMigrated`

### `test_ipamigrateadtrust`  (integration, 3 IPA host(s), 1 AD host(s))

- test: `test_integration/test_ipa_ipa_migration.py::TestIPAMigrationWithADtrust`
- note: 1 external AD host(s) require manual setup (edit placeholders)

### `test_ipamigratebackuprestore`  (integration, 4 IPA host(s))

- test: `test_integration/test_ipa_ipa_migration.py::TestIPAMigratewithBackupRestore`

### `test_cockpit`  (integration, 2 IPA host(s))

- test: `test_integration/test_cockpit.py`

### `test_32bitidranges`  (integration, 3 IPA host(s), 1 AD host(s))

- test: `test_integration/test_32bit_idranges.py`
- note: 1 external AD host(s) require manual setup (edit placeholders)

### `test_edns`  (integration, 4 IPA host(s))

- test: `test_integration/test_edns.py`

### `test_trust_functional`  (integration, 3 IPA host(s), 3 AD host(s))

- test: `test_integration/test_trust_functional.py`
- note: 3 external AD host(s) require manual setup (edit placeholders)

### `test_hbac_functional`  (integration, 4 IPA host(s))

- test: `test_integration/test_hbac_functional.py`

### `test_installation_testinstallkeysizes`  (integration, 2 IPA host(s))

- test: `test_integration/test_installation.py::TestInstallKeySizes`

### `test_sysaccounts`  (integration, 2 IPA host(s))

- test: `test_integration/test_sysaccounts.py`

### `test_webui_sysaccount`  (base, 1 IPA host(s))

- test: `test_webui/test_sysaccount.py`
- note: RunWebuiTests: browser/selenium not in image

### `test_ipa_join`  (integration, 3 IPA host(s))

- test: `test_integration/test_ipa_join.py`

### `test_ds_migration`  (integration, 3 IPA host(s))

- test: `test_integration/test_ds_migration.py`

