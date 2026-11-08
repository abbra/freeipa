import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from ipapython.ipautil import realm_to_suffix
from ipaserver.install import kuipadinstance


def test_upgrade_configures_directory_suffix(monkeypatch):
    monkeypatch.setattr(kuipadinstance.sysupgrade, 'get_upgrade_state',
                        lambda *args: True)
    monkeypatch.setattr(kuipadinstance, 'api', SimpleNamespace(
        env=SimpleNamespace(host='server.example.test', realm='EXAMPLE.TEST',
                            domain='example.test')))
    monkeypatch.setattr(kuipadinstance.os.path, 'isfile', lambda path: True)
    instance = kuipadinstance.KuipadInstance()
    seen = []
    monkeypatch.setattr(instance, '_configure_kuipad', lambda: seen.append(instance.suffix))
    monkeypatch.setattr(instance, '_configure_gssproxy', Mock())
    monkeypatch.setattr(instance, 'stop', Mock())
    monkeypatch.setattr(instance, '_configure_httpd_proxy', Mock())
    monkeypatch.setattr(instance, '_enroll_host', Mock())
    monkeypatch.setattr(instance, 'restart', Mock())
    monkeypatch.setattr(kuipadinstance.services.knownservices.httpd,
                        'reload_or_restart', Mock())
    instance.upgrade_instance()
    assert seen == [realm_to_suffix('EXAMPLE.TEST')]


def test_existing_host_enrollment_is_not_rotated(monkeypatch, tmp_path):
    state = tmp_path / 'state.json'
    state.write_text(json.dumps({'realm': 'EXAMPLE.TEST', 'fqdn': 'server.example.test'}))
    instance = kuipadinstance.KuipadInstance()
    monkeypatch.setattr(kuipadinstance, 'paths', SimpleNamespace(KUIPA_CLIENT_STATE=str(state)))
    kinit = Mock()
    monkeypatch.setattr(kuipadinstance, 'kinit_keytab', kinit)
    instance.realm = 'EXAMPLE.TEST'
    instance.fqdn = 'server.example.test'
    instance._enroll_host()
    kinit.assert_not_called()


def test_enrollment_from_another_host_is_refused(monkeypatch, tmp_path):
    state = tmp_path / 'state.json'
    state.write_text(json.dumps({'realm': 'EXAMPLE.TEST', 'fqdn': 'other.example.test'}))
    instance = kuipadinstance.KuipadInstance()
    monkeypatch.setattr(kuipadinstance, 'paths', SimpleNamespace(KUIPA_CLIENT_STATE=str(state)))
    instance.realm = 'EXAMPLE.TEST'
    instance.fqdn = 'server.example.test'
    with pytest.raises(RuntimeError, match='another host or realm'):
        instance._enroll_host()


def test_reconfigure_migrates_legacy_keytab_and_preserves_keys(
        monkeypatch, tmp_path):
    state = tmp_path / 'state'
    state.mkdir()
    legacy = state / 'kuipa.keytab'
    legacy.write_bytes(b'keytab')
    signing = state / 'signing.jwk'
    signing.write_bytes(b'signing key')
    keytab = tmp_path / 'kuipad.keytab'
    config = tmp_path / 'kuipad.json'
    monkeypatch.setattr(kuipadinstance, 'paths', SimpleNamespace(
        KUIPA_STATE_DIR=str(state), KUIPA_KEYTAB=str(keytab),
        KUIPA_CONFIG=str(config), KUIPA_KEYS_SOCKET='/run/ipa/kuipad-keys.sock',
        IPA_CA_CRT='/ca', KDC_CA_BUNDLE_PEM='/anchors',
        IPA_CUSTODIA_HANDLER='/handlers', USR_SHARE_IPA_DIR='/templates'))
    monkeypatch.setattr(kuipadinstance, '_get_kuipa_user',
                        lambda: SimpleNamespace(pw_uid=123, pw_gid=456))
    stat = kuipadinstance.os.stat
    fstat = kuipadinstance.os.fstat

    def as_root(info):
        values = list(info)
        values[4] = 0
        return kuipadinstance.os.stat_result(values)

    def root_stat(path, *args, **kwargs):
        result = stat(path, *args, **kwargs)
        return as_root(result) if kwargs.get('dir_fd') is not None else result

    monkeypatch.setattr(kuipadinstance.os, 'stat', root_stat)
    monkeypatch.setattr(kuipadinstance.os, 'fstat',
                        lambda fd: as_root(fstat(fd)))
    fchown = Mock()
    monkeypatch.setattr(kuipadinstance.os, 'fchown', fchown)
    chown = Mock()
    monkeypatch.setattr(kuipadinstance.os, 'chown', chown)
    monkeypatch.setattr(kuipadinstance.ipautil, 'template_file',
                        lambda path, values: json.dumps(values))
    monkeypatch.setattr(kuipadinstance.tasks, 'restore_context', Mock())
    instance = kuipadinstance.KuipadInstance()
    instance.realm = 'EXAMPLE.TEST'
    instance.domain = 'example.test'
    instance.fqdn = 'server.example.test'
    instance.suffix = realm_to_suffix(instance.realm)
    instance._configure_kuipad()
    assert keytab.read_bytes() == b'keytab'
    assert keytab.stat().st_mode & 0o777 == 0o600
    assert not legacy.exists()
    assert signing.read_bytes() == b'signing key'
    assert state.stat().st_mode & 0o777 == 0o700
    assert config.stat().st_mode & 0o777 == 0o640
    assert any(call.args[1:] == (123, 456) for call in fchown.call_args_list)
    chown.assert_any_call(str(config), 0, 456)



def test_unsafe_legacy_keytab_is_rejected(monkeypatch, tmp_path):
    state = tmp_path / 'state'
    state.mkdir()
    (state / 'kuipa.keytab').symlink_to(tmp_path / 'other')
    monkeypatch.setattr(kuipadinstance, 'paths', SimpleNamespace(
        KUIPA_STATE_DIR=str(state), KUIPA_KEYTAB=str(tmp_path / 'keytab')))
    monkeypatch.setattr(kuipadinstance, '_get_kuipa_user',
                        lambda: SimpleNamespace(pw_uid=123, pw_gid=456))
    with pytest.raises((RuntimeError, OSError)):
        kuipadinstance.KuipadInstance()._configure_kuipad()


def test_reconfigure_does_not_walk_daemon_owned_state(monkeypatch, tmp_path):
    state = tmp_path / 'state'
    state.mkdir()
    (state / 'untrusted').symlink_to(tmp_path)
    monkeypatch.setattr(kuipadinstance, 'paths', SimpleNamespace(
        KUIPA_STATE_DIR=str(state), KUIPA_KEYTAB=str(tmp_path / 'keytab'),
        KUIPA_CONFIG=str(tmp_path / 'config'),
        KUIPA_KEYS_SOCKET='/run/ipa/kuipad-keys.sock',
        IPA_CA_CRT='/ca', KDC_CA_BUNDLE_PEM='/anchors',
        IPA_CUSTODIA_HANDLER='/handlers', USR_SHARE_IPA_DIR='/templates'))
    monkeypatch.setattr(kuipadinstance, '_get_kuipa_user',
                        lambda: SimpleNamespace(pw_uid=123, pw_gid=456))
    fstat = kuipadinstance.os.fstat

    def daemon_owner(fd):
        values = list(fstat(fd))
        values[4] = 123
        return kuipadinstance.os.stat_result(values)

    monkeypatch.setattr(kuipadinstance.os, 'fstat', daemon_owner)
    monkeypatch.setattr(kuipadinstance.os, 'chown', Mock())
    monkeypatch.setattr(kuipadinstance.ipautil, 'template_file',
                        lambda path, values: '{}')
    outside = tmp_path / 'outside'
    outside.write_text('preserved')
    instance = kuipadinstance.KuipadInstance()
    instance.realm = 'EXAMPLE.TEST'
    instance.domain = 'example.test'
    instance.fqdn = 'server.example.test'
    instance.suffix = realm_to_suffix(instance.realm)
    instance._configure_kuipad()
    assert (state / 'untrusted').is_symlink()
    assert outside.read_text() == 'preserved'
