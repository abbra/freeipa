import json

import pytest

from ipaserver.plugins.seal import format_policy, validate_limits


BASE = {
    'max_lifetime': 34560000,
    'max_seals': 16,
    'max_devices': 8,
    'max_reauth': 43200,
    'without_device': True,
    'descriptor_age': 2592000,
}


def validate(value):
    return validate_limits(lambda text: text, json.dumps(value))


def test_valid_group_overrides():
    group = {'group': 'travel', 'priority': 5, 'max_unlocks': None,
             'factors': [{'device': 'any', 'ticket': True}]}
    assert validate({**BASE, 'groups': [group]}) is None


@pytest.mark.parametrize('change', [
    {'max_seals': True},
    {'max_devices': -1},
    {'offline_sessions': 'true'},
    {'factors': [{'device': 'unsupported'}]},
    {'groups': [{'group': 'travel', 'priority': -1}]},
    {'max_lifetim': 2},
])
def test_invalid_limits_are_rejected(change):
    assert validate({**BASE, **change}) is not None


def test_required_limits_cannot_be_omitted():
    assert validate({}) is not None


def test_policy_display_includes_factors_sessions_and_approvals():
    policy = {
        'factors': {'device': 'hardware-bound', 'ticket': True,
                    'passkey': True},
        'ticket_delegation': {'via': ['HTTP/one', 'HTTP/two']},
        'ticket_leased': True, 'not_after': 0, 'max_unlocks': 7,
        'sealing': 'registered',
        'sessions': {'reauth': 300, 'offline': 3600, 'epoch': 60},
        'approvals': {'m': 2, 'from': {'users': ['alice'], 'groups': ['ops']},
                      'window': 120, 'uses': 3},
    }
    entry = {'ipakusealpolicy': [json.dumps(policy)]}
    format_policy(entry)
    assert 'ipakusealpolicy' not in entry
    assert entry['sealpolicyfactors'] == (
        'device (hardware-bound), Kerberos ticket, passkey')
    assert entry['sealpolicydelegation'] == 'via HTTP/one, HTTP/two'
    assert entry['sealpolicyleased'] == 'leased hosts only'
    assert entry['sealpolicyexpires'] == '1970-01-01 00:00:00 UTC'
    assert entry['sealpolicyunlocks'] == '7'
    assert entry['sealpolicysealing'] == 'registered'
    assert entry['sealpolicyreauth'] == '300'
    assert entry['sealpolicyoffline'] == '3600'
    assert entry['sealpolicyepoch'] == '60'
    assert entry['sealpolicyapprovals'] == '2'
    assert entry['sealpolicyapprovers'] == 'users: alice; groups: ops'
    assert entry['sealpolicywindow'] == '120'
    assert entry['sealpolicyuses'] == '3'


def test_raw_and_malformed_policies_remain_available():
    original = '{"factors":{"ticket":true}}'
    entry = {'ipakusealpolicy': [original]}
    format_policy(entry, raw=True)
    assert entry == {'ipakusealpolicy': [original]}
    malformed = {'ipakusealpolicy': ['{invalid']}
    format_policy(malformed)
    assert malformed == {'ipakusealpolicy': ['{invalid']}
    invalid_factor = {'ipakusealpolicy': ['{"factors":{"ticket":"false"}}']}
    format_policy(invalid_factor)
    assert invalid_factor == {'ipakusealpolicy': [
        '{"factors":{"ticket":"false"}}']}
    future = {'ipakusealpolicy': ['{"factors":{"ticket":true},"new_option":1}']}
    format_policy(future)
    assert future['sealpolicyfactors'] == 'Kerberos ticket'
    assert json.loads(future['ipakusealpolicy'][0])['new_option'] == 1
