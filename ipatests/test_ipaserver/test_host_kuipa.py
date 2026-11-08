import base64
from unittest.mock import Mock

import dbus
import pytest

from ipalib import errors
from ipaserver.plugins import host


REALM = 'EXAMPLE.TEST'
ANCHOR = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
STRING = 'ipa-ku1:{}:{}:2000000000'.format(REALM, ANCHOR)


@pytest.fixture
def helper(monkeypatch):
    monkeypatch.setattr(host.os, 'lstat', lambda path: object())
    monkeypatch.setattr(host.time, 'time', lambda: 1900000000)
    server = Mock()
    server.kuipa_enrollment_string.return_value = (0, STRING + '\n', '')
    bus = Mock()
    monkeypatch.setattr(host.dbus, 'SystemBus', lambda: bus)
    monkeypatch.setattr(host.dbus, 'Interface', lambda obj, interface: server)
    return server


def test_enrollment_string_from_privileged_helper(helper):
    assert host.kuipa_enrollment_string(REALM) == STRING
    helper.kuipa_enrollment_string.assert_called_once_with()


def test_unconfigured_server_preserves_host_add(monkeypatch):
    def missing(path):
        raise FileNotFoundError(path)

    monkeypatch.setattr(host.os, 'lstat', missing)
    monkeypatch.setattr(host.dbus, 'SystemBus',
                        Mock(side_effect=AssertionError))
    assert host.kuipa_enrollment_string(REALM) is None


def test_inaccessible_configuration_is_not_a_downgrade(monkeypatch):
    def denied(path):
        raise PermissionError(path)

    monkeypatch.setattr(host.os, 'lstat', denied)
    with pytest.raises(errors.ExecutionError):
        host.kuipa_enrollment_string(REALM)


@pytest.mark.parametrize('value', [
    '',
    'ipa-ku1:OTHER.TEST:{}:2000000000'.format(ANCHOR),
    'ipa-ku1:{}:invalid:2000000000'.format(REALM),
    'ipa-ku1:{}:{}:1900000000'.format(REALM, ANCHOR),
    STRING + ':unexpected-secret',
    'ipa-ku2:{}:{}:2000000000'.format(REALM, ANCHOR),
])
def test_invalid_helper_output_fails_closed(helper, value):
    helper.kuipa_enrollment_string.return_value = (0, value, '')
    with pytest.raises(errors.ExecutionError):
        host.kuipa_enrollment_string(REALM)


def test_helper_failure_does_not_expose_stderr(helper):
    helper.kuipa_enrollment_string.return_value = (1, '', 'sensitive-value')
    with pytest.raises(errors.ExecutionError) as exc:
        host.kuipa_enrollment_string(REALM)
    assert 'sensitive-value' not in str(exc.value)


def test_dbus_failure_does_not_expose_details(helper):
    helper.kuipa_enrollment_string.side_effect = dbus.DBusException(
        'sensitive-value')
    with pytest.raises(errors.ExecutionError) as exc:
        host.kuipa_enrollment_string(REALM)
    assert 'sensitive-value' not in str(exc.value)


@pytest.mark.parametrize('enrollment', [STRING, None])
def test_host_add_output_contains_password_only_when_configured(
        monkeypatch, enrollment):
    monkeypatch.setattr(host.context, 'randompassword', 'otp', raising=False)
    monkeypatch.setattr(host.context, 'kuipa_enrollment_string', enrollment,
                        raising=False)
    monkeypatch.setattr(host, 'dns_container_exists', lambda ldap: False)
    for name in ('set_certificate_attrs', 'set_kerberos_attrs',
                 'rename_ipaallowedtoperform_from_ldap',
                 'convert_sshpubkey_post'):
        monkeypatch.setattr(host, name, Mock())
    entry = {'has_password': True}
    host.host_add.post_callback(
        Mock(), None, host.DN(('cn', 'test')), entry, 'test', random=True)
    assert entry['randompassword'] == 'otp'
    assert entry.get('enrollmentstring') == (
        STRING + ':otp' if enrollment is not None else None)


def test_enrollment_output_is_sensitive():
    param = next(p for p in host.host.takes_params
                 if p.name == 'enrollmentstring')
    assert param.password
    assert param.safe_value(STRING + ':otp') == '********'
