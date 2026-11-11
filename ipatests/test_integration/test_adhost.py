#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Unit tests of the AD host classes of the integration test harness.

Active Directory operations of the tests are methods of the AD host, so that
the same test runs against Windows (PowerShell, dnscmd) or Samba AD
(samba-tool, ldb tools); `host_type: samba` in the test configuration
selects Samba. These tests do not need any host.
"""
from unittest.mock import MagicMock, patch

import pytest

from ipatests.pytest_ipa.integration import config
import ipatests.pytest_ipa.integration.host as host_module
from ipatests.pytest_ipa.integration.host import SambaADHost, WinHost


@pytest.fixture(autouse=True)
def no_resolver_setup():
    # creating an IPA host would ssh to it to learn about its resolver
    with patch.object(host_module, 'resolver', MagicMock()):
        yield


def make_config(ad_host_type=None):
    ad_host = dict(name='dc', ip='192.0.2.10', role='ad')
    if ad_host_type:
        ad_host['host_type'] = ad_host_type
    return config.Config.from_dict(dict(
        ssh_username='root',
        domains=[
            dict(name='ipa.test', type='IPA',
                 hosts=[dict(name='master', ip='192.0.2.1')]),
            dict(name='ad.test', type='AD', hosts=[ad_host]),
        ]))


class Recorder:
    """Stand-in for run_command: remember the commands, answer from a map"""

    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        out = next((v for k, v in self.answers.items() if k in argv), '')
        return type('Result', (), {'stdout_text': out, 'returncode': 0})()

    @property
    def argvs(self):
        return [argv for argv, _kwargs in self.calls]


def ad_host(host_type=None):
    return make_config(host_type).domains[1].hosts[0]


def test_ad_host_is_windows_unless_the_configuration_says_samba():
    assert type(ad_host()) is WinHost
    assert type(ad_host('samba')) is SambaADHost
    assert ad_host().ad_flavor == 'windows'
    assert ad_host('samba').ad_flavor == 'samba'


def test_the_ipa_host_is_not_affected_by_host_type():
    master = make_config('samba').domains[0].hosts[0]
    assert not hasattr(master, 'ad_flavor')


def test_windows_forwarder_is_a_dnscmd_zone():
    host = ad_host()
    rec = Recorder()
    with patch.object(WinHost, 'run_command', rec):
        host.dns_forwarder_add('ipa.test', '192.0.2.1')
        host.dns_forwarder_del('ipa.test')
    assert rec.argvs == [
        ['dnscmd', '/zoneadd', 'ipa.test', '/Forwarder', '192.0.2.1'],
        ['dnscmd', '/zonedelete', 'ipa.test', '/f'],
    ]


def test_windows_group_membership_asks_powershell():
    host = ad_host()
    rec = Recorder({'powershell': 'SamAccountName : testuser\n'})
    with patch.object(WinHost, 'run_command', rec):
        assert host.group_has_member('grp', 'testuser')
    argv = rec.argvs[0]
    assert argv[:2] == ['powershell', '-c']
    assert 'Get-ADGroupMember -Identity "grp"' in argv[2]
    assert rec.calls[0][1]['set_env'] is False

    rec = Recorder({'powershell': '  \n'})
    with patch.object(WinHost, 'run_command', rec):
        assert not host.group_has_member('grp', 'testuser')


def test_windows_password_policy_keeps_run_command_options():
    host = ad_host()
    rec = Recorder()
    with patch.object(WinHost, 'run_command', rec):
        host.password_min_age_set(1, raiseonerr=False)
    argv, kwargs = rec.calls[0]
    assert '-MinPasswordAge 1.00:00:00' in argv[2]
    assert kwargs['raiseonerr'] is False


def test_samba_group_membership_is_case_insensitive():
    host = ad_host('samba')
    rec = Recorder({'listmembers': 'Administrator\nTestUser\n'})
    with patch.object(SambaADHost, 'run_command', rec):
        assert host.group_has_member('grp', 'testuser')
        assert not host.group_has_member('grp', 'other')
    assert rec.argvs[0] == ['samba-tool', 'group', 'listmembers', 'grp']


def test_samba_upn_suffix_is_an_ldb_modification():
    host = ad_host('samba')
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs.get('stdin_text')))
        return type('R', (), {'stdout_text': '', 'returncode': 0})()

    with patch.object(SambaADHost, 'run_command', side_effect=run):
        host.upn_suffix_add('sub.ad.test')
        host.upn_suffix_del('sub.ad.test')
    # pylint: disable-next=unbalanced-tuple-unpacking
    (argv, ldif), (_argv2, ldif_del) = calls
    assert argv[:3] == ['ldbmodify', '-H', host.sam_ldb]
    assert ('dn: CN=Partitions,CN=Configuration,DC=ad,DC=test\n'
            in ldif)
    assert 'add: uPNSuffixes\nuPNSuffixes: sub.ad.test' in ldif
    assert 'delete: uPNSuffixes\nuPNSuffixes: sub.ad.test' in ldif_del


def test_samba_user_upn_finds_the_user_dn_first():
    host = ad_host('samba')
    answers = {'ldbsearch': 'dn: CN=Test User,CN=Users,DC=ad,DC=test\n'}
    rec = Recorder(answers)
    with patch.object(SambaADHost, 'run_command', rec):
        host.user_set_upn('testuser', 'testuser@sub.ad.test')
    # pylint: disable-next=unbalanced-tuple-unpacking
    search, modify = rec.calls
    assert '(sAMAccountName=testuser)' in search[0]
    assert 'dn: CN=Test User,CN=Users,DC=ad,DC=test' in modify[1]['stdin_text']
    assert 'userPrincipalName: testuser@sub.ad.test' in modify[1]['stdin_text']


def test_samba_user_upn_of_an_unknown_user_is_an_error():
    host = ad_host('samba')
    with patch.object(SambaADHost, 'run_command', Recorder()):
        with pytest.raises(ValueError, match='no user nobody'):
            host.user_set_upn('nobody', 'nobody@ad.test')


def test_samba_shared_secret_trust_reads_the_remote_from_the_config():
    host = ad_host('samba')
    rec = Recorder({'list': 'Type[Forest] Direction[INCOMING] Name[ipa.test]'})
    with patch.object(SambaADHost, 'run_command', rec):
        host.trust_local_side_create('ipa.test', 's3cret')
    create, kwargs = rec.calls[0]
    assert create[:5] == ['samba-tool', 'domain', 'trust', 'create',
                          'ipa.test']
    assert '--ipaddress=192.0.2.1' in create
    assert 'IPA\\admin%Secret123' in create
    assert '--create-location=local' in create
    # the secret goes in on stdin, not on the command line
    assert kwargs['stdin_text'] == 's3cret\ns3cret\n'
    assert not any('s3cret' in a for a in create)
    # samba-tool exits non-zero while the other side is missing
    assert kwargs['raiseonerr'] is False


def test_samba_trust_that_was_not_created_is_an_error():
    host = ad_host('samba')
    with patch.object(SambaADHost, 'run_command', Recorder({'list': ''})):
        with pytest.raises(AssertionError, match='did not create the trust'):
            host.trust_local_side_create('ipa.test', 's3cret')


def test_samba_forwarder_replaces_the_global_one_and_restores_it():
    host = ad_host('samba')
    rec = Recorder()
    with patch.object(SambaADHost, 'run_command', rec):
        host.dns_forwarder_add('ipa.test', '192.0.2.1')
        host.dns_forwarder_del('ipa.test')
    add, delete = (argv[-1] for argv in rec.argvs)
    assert 'dns forwarder = 192.0.2.1' in add
    assert 'cp -n /etc/samba/smb.conf /etc/samba/smb.conf.ipatests' in add
    assert 'mv -f /etc/samba/smb.conf.ipatests /etc/samba/smb.conf' in delete
