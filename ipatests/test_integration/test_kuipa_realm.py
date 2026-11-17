# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

"""kuipa tests that share one realm: a master, a replica and two clients.

Each area is a mixin in its own test_kuipa_*.py module; the realm is
installed once here, so CI needs one deployment instead of one per area.
test_kuipa_trust.py (trust) and test_kuipa_backup.py (it reinstalls the
master) need their own deployments.
"""

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.kuipa_common import KuipaStages
from ipatests.test_integration.test_kuipa_cert_approval import (
    FIRST, SECOND, KuipaCertApprovalTests)
from ipatests.test_integration.test_kuipa_clevis import KuipaClevisTests
from ipatests.test_integration.test_kuipa_enrollment import (
    KuipaEnrollmentTests)
from ipatests.test_integration.test_kuipa_seal_admin import (
    KuipaSealAdminTests)
from ipatests.test_integration.test_kuipa_server_enrollment import (
    KuipaServerEnrollmentTests)


# Run order: server enrollment, cert approval, seal administration,
# enrollment, Clevis. pytest collects the bases in reverse, so they are listed
# reversed.
class TestKuipaRealm(KuipaClevisTests, KuipaEnrollmentTests,
                     KuipaSealAdminTests, KuipaCertApprovalTests,
                     KuipaServerEnrollmentTests, KuipaStages,
                     IntegrationTest):
    topology = 'star'
    num_replicas = 1
    num_clients = 2

    @classmethod
    def install(cls, mh):
        master = cls.master
        tasks.install_master(master, setup_dns=True)
        master.run_command([
            'su', '-s', '/bin/sh', '-c',
            'test -r /etc/ipa/ca.crt && test -r /etc/ipa/ku/realm.json',
            'ipaapi',
        ])
        tasks.install_replica(master, cls.replicas[0], setup_ca=False,
                              promote=False, extra_args=['--no-ntp'])
        # master-side preparation of the cert approval area
        cls.prepare()
        tasks.user_add(master, 'appr2', password=FIRST)
        master.run_command(['ipa', 'group-add-member', 'pki-approvers',
                            '--users', 'appr2'])
        master.run_command(
            ['env', 'KRB5CCNAME=FILE:/tmp/appr2.ccache', 'kinit', 'appr2'],
            stdin_text='{0}\n{1}\n{1}\n'.format(FIRST, SECOND))

    @classmethod
    def uninstall(cls, mh):
        cls.cleanup_clevis()
        for client in cls.clients:
            tasks.uninstall_client(client)
        tasks.uninstall_master(cls.replicas[0])
        tasks.uninstall_master(cls.master)
