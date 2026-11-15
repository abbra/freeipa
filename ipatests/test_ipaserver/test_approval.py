import json
from types import SimpleNamespace

import pytest

from ipalib import errors
from ipaserver.plugins import approval as ap


class FakeLdap:
    SCOPE_ONELEVEL = MATCH_ALL = None

    def __init__(self, state='enabled', **policy):
        self.entries = [SimpleNamespace(single_value={
            'ipakusealstate': state,
            'ipakusealpolicy': json.dumps(policy)})]

    def make_filter(self, *args, **kwargs):
        return ''

    def get_entries(self, *args):
        return self.entries


GOOD = {'factors': {'ticket': True}, 'approvals': {'m': 2}}


@pytest.mark.parametrize('state, policy, usable', [
    ('enabled', GOOD, True),
    ('revoked', GOOD, False),
    ('enabled', {'factors': {'ticket': True}}, False),
    ('enabled', {**GOOD, 'factors': {'ticket': False}}, False),
    ('enabled', {**GOOD, 'factors': {'ticket': True, 'device': 'any'}},
     False),
    ('enabled', {**GOOD, 'factors': {'ticket': True, 'passkey': True}},
     False),
    ('enabled', {**GOOD, 'sessions': {'offline': 600}}, False)])
def test_only_a_ticket_approvals_seal_gates_a_profile(
        monkeypatch, state, policy, usable):
    monkeypatch.setattr(ap, 'api', SimpleNamespace(
        env=SimpleNamespace(basedn='dc=ipa,dc=test', realm='IPA.TEST')))
    problem = ap.seal_problem(FakeLdap(state, **policy),
                              'admin@IPA.TEST/certs')
    assert (problem is None) is usable


@pytest.fixture
def gate(monkeypatch):
    """The generic store, recording what a workflow asks of it."""
    calls = []
    monkeypatch.setattr(ap, 'context',
                        SimpleNamespace(principal='alice@EXAMPLE.TEST'))
    monkeypatch.setattr(
        ap, 'create_request',
        lambda *a: calls.append(('create', a)) or 'f' * 32)
    monkeypatch.setattr(
        ap, 'redeem_request', lambda *a: calls.append(('redeem', a)))
    return calls


def test_a_gated_workflow_without_an_approval_makes_a_request(gate):
    with pytest.raises(errors.ExecutionError) as e:
        ap.require_approval('k', 'admin/s', 'doc', None, 'why')
    assert 'f' * 32 in str(e.value)
    assert gate == [('create', (
        'k', 'admin/s', 'alice@EXAMPLE.TEST', 'doc', 'why'))]


def test_a_gated_workflow_with_an_approval_redeems_it(gate):
    ap.require_approval('k', 'admin/s', 'doc', 'id', 'why')
    assert gate == [('redeem', (
        'id', 'k', 'admin/s', 'alice@EXAMPLE.TEST', 'doc'))]
