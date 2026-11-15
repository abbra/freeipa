import base64
from contextlib import contextmanager
import json
from types import SimpleNamespace

import pytest

from ipalib import errors
from ipaserver.plugins import approval as ap
from ipaserver.plugins import certapproval as ca

ARGS = ('alice@EXAMPLE.TEST', 'prof', 'caid', 'HTTP/h@EXAMPLE.TEST', 'CSR')
SEAL = 'admin/certs'


def stored(**change):
    """The approval entry for ARGS, as LDAP gives it."""
    value = {'ipakuapprovalkind': ca.KIND,
             'ipakuapprovalseal': SEAL,
             'ipakuapprovalrequester': ARGS[0],
             'ipakuapprovaldata': ca._document(*ARGS),
             'ipakuapprovalrelease': 'rid',
             'ipakuapprovalsealed': base64.b64encode(b'x').decode()}
    value.update(change)
    return SimpleNamespace(single_value=value)


@pytest.fixture
def kuipa(monkeypatch):
    """A kuipa whose `seal open` yields `state['plain']` or fails."""
    state = {'plain': ca._document(*ARGS), 'ok': True, 'calls': []}

    @contextmanager
    def session():
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            def run(*args):
                state['calls'].append(args)
                if state['ok']:
                    out = args[args.index('--out') + 1]
                    with open(out, 'w') as f:
                        f.write(state['plain'])
                return SimpleNamespace(returncode=0 if state['ok'] else 1,
                                       output='{}', error_log='not approved')
            yield root, run

    monkeypatch.setattr(ap, 'kuipa_session', session)
    return state


def redeem(monkeypatch, entry):
    monkeypatch.setattr(ap, '_load', lambda _id: entry)
    ca.redeem_approval('id', SEAL, *ARGS)


def test_matching_approved_request_is_redeemed(monkeypatch, kuipa):
    redeem(monkeypatch, stored())
    assert '--request' in kuipa['calls'][0]


@pytest.mark.parametrize('change', [
    {'ipakuapprovaldata': ca._document(*ARGS[:4], 'OTHER')},
    {'ipakuapprovalseal': 'x/open'},
    {'ipakuapprovalrequester': 'bob@EXAMPLE.TEST'},
    {'ipakuapprovalkind': 'other-workflow'}])
def test_forged_entry_is_refused_before_opening(monkeypatch, kuipa, change):
    with pytest.raises(errors.ValidationError):
        redeem(monkeypatch, stored(**change))
    assert not kuipa['calls']


def test_sealed_request_that_differs_is_refused(monkeypatch, kuipa):
    kuipa['plain'] = ca._document(*ARGS[:4], 'OTHER')
    with pytest.raises(errors.ValidationError):
        redeem(monkeypatch, stored())


def test_unapproved_request_is_refused(monkeypatch, kuipa):
    kuipa['ok'] = False
    with pytest.raises(errors.ExecutionError):
        redeem(monkeypatch, stored())


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


def test_revocation_is_gated_only_by_a_ca_with_a_seal(monkeypatch, gate):
    monkeypatch.setattr(ca, 'gate_seal', lambda dn: None)
    ca.revocation_gate('cn=ipa', 5, 0, None)
    assert not gate
    monkeypatch.setattr(ca, 'gate_seal', lambda dn: 'admin/s')
    monkeypatch.setattr(ca, 'require_approval', ap.require_approval)
    with pytest.raises(errors.ExecutionError):
        ca.revocation_gate('cn=ipa', 5, 0, None)
    document = json.loads(gate[0][1][3])
    assert gate[0][1][0] == ca.REVOKE_KIND
    assert document == {'ca': 'cn=ipa', 'serial': '5', 'reason': 0}
