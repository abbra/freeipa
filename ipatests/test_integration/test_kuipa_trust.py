# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

"""kuipa tests that need an AD trust, on one deployment.

Trusted-realm enrollment and cert approval by a trusted-realm approver share
one two-way trust. It is separate from test_kuipa_realm.py because the trust
changes the master (adtrust, ID ranges, DNS forwarding).
"""

from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.env_config import get_global_config
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.kuipa_common import KuipaStages
from ipatests.test_integration.test_kuipa_cert_approval import (
    KuipaCertApprovalTrustedTests)
from ipatests.test_integration.test_kuipa_trusted_enrollment import (
    KuipaTrustedEnrollmentTests)

config = get_global_config()


class TestKuipaTrust(KuipaCertApprovalTrustedTests,
                     KuipaTrustedEnrollmentTests,
                     KuipaStages, IntegrationTest):
    """Run order: trusted enrollment, cert approval by a trusted approver."""
    topology = 'line'
    num_clients = 1
    num_ad_domains = 1

    @classmethod
    def install(cls, mh):
        super().install(mh)
        cls.ad = config.ad_domains[0].ads[0]
        master = cls.master
        tasks.install_adtrust(master)
        tasks.sync_time(master, cls.ad)
        tasks.configure_dns_for_trust(master, cls.ad)
        # a two-way trust: the AD DC must find the IPA domain. Samba's
        # DNS has one global forwarder, which becomes the IPA master.
        cls.ad.run_command([
            'sed', '-i', 's/dns forwarder = .*/dns forwarder = {}/'.format(
                master.ip), '/etc/samba/smb.conf'])
        cls.ad.run_command(['systemctl', 'restart', 'samba'])
        tasks.establish_trust_with_ad(
            master, cls.ad.domain.name,
            extra_args=['--range-type', 'ipa-ad-trust',
                        '--two-way=true'])
        cls.aduser = 'testuser@{}'.format(cls.ad.domain.name)
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'idoverrideuser-add',
                            'Default Trust View', cls.aduser])
        # trusted enrollment: the enrollers role
        master.run_command(['ipa', 'group-add', 'enrollers'])
        master.run_command(['ipa', 'group-add-member', 'enrollers',
                            '--idoverrideusers', cls.aduser])
        master.run_command(['ipa', 'role-add', 'AD enrollers'])
        master.run_command(['ipa', 'role-add-privilege', 'AD enrollers',
                            '--privileges', 'Host Enrollment'])
        master.run_command(['ipa', 'role-add-privilege', 'AD enrollers',
                            '--privileges', 'Host Administrators'])
        master.run_command(['ipa', 'role-add-member', 'AD enrollers',
                            '--groups', 'enrollers'])
        # cert approval: the approvers group holds the AD user
        cls.prepare()
        master.run_command(['ipa', 'group-add-member', 'pki-approvers',
                            '--idoverrideusers', cls.aduser])
        master.run_command(
            ['env', 'KRB5CCNAME=FILE:/tmp/aduser.ccache', 'kinit',
             cls.aduser], stdin_text='Secret123\n')

    @classmethod
    def uninstall(cls, mh):
        cls.cleanup_trusted_enrollment()
        tasks.uninstall_client(cls.clients[0])
        super().uninstall(mh)
