#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
from __future__ import absolute_import

import base64
import json
from unittest import mock

import pytest

from ipaclient.frontend import MethodOverride
from ipalib import errors

from ipaclient.plugins import trust_bootstrap as cb


def _stub_super_forward(*args, **options):
    """Fake MethodOverride.forward() -- echoes back whatever the override
    ends up sending, wrapped like a real command result."""
    return dict(result=dict(options))


@pytest.fixture
def patched_forward():
    with mock.patch.object(
            MethodOverride, 'forward', new=_stub_super_forward,
            create=True):
        yield


def make_command(cls):
    return object.__new__(cls)


class TestKeypairFileRoundTrip:
    def test_write_and_read_keypair(self, tmp_path):
        out = str(tmp_path / "a.key")

        priv_path, pub_path = cb.write_keypair_files(
            out, u'ML-KEM-768', 'cHVibGlj', 'cHJpdmF0ZQ==')

        assert priv_path == out
        assert pub_path == out + '.pub'

        parameter_set, priv_bytes = cb.read_keypair_file(
            'x', priv_path, 'private_key')
        assert parameter_set == u'ML-KEM-768'
        assert priv_bytes == base64.b64decode('cHJpdmF0ZQ==')

        parameter_set, pub_bytes = cb.read_keypair_file(
            'x', pub_path, 'public_key')
        assert parameter_set == u'ML-KEM-768'
        assert pub_bytes == base64.b64decode('cHVibGlj')

    def test_private_key_file_is_mode_0600(self, tmp_path):
        out = str(tmp_path / "a.key")
        cb.write_keypair_files(out, u'ML-KEM-768', 'cHVi', 'cHJpdg==')

        mode = (tmp_path / "a.key").stat().st_mode & 0o777
        assert mode == 0o600

    def test_read_missing_file_raises_validation_error(self, tmp_path):
        with pytest.raises(errors.ValidationError):
            cb.read_keypair_file(
                'x', str(tmp_path / "does-not-exist"), 'private_key')

    def test_read_malformed_json_raises_validation_error(self, tmp_path):
        path = tmp_path / "bad.key"
        path.write_text("not json")
        with pytest.raises(errors.ValidationError):
            cb.read_keypair_file('x', str(path), 'private_key')

    def test_read_missing_field_raises_validation_error(self, tmp_path):
        path = tmp_path / "incomplete.key"
        path.write_text(json.dumps(dict(kem_parameter_set=u'ML-KEM-768')))
        with pytest.raises(errors.ValidationError):
            cb.read_keypair_file('x', str(path), 'private_key')


class TestPrepareInfoFileRoundTrip:
    def test_write_and_read(self, tmp_path):
        out = str(tmp_path / "info.json")
        cb.write_prepare_info_file(out, u'b.example.test', u'sometoken')

        server, token = cb.read_prepare_info_file('x', out)
        assert server == u'b.example.test'
        assert token == u'sometoken'

    def test_is_mode_0600(self, tmp_path):
        out = str(tmp_path / "info.json")
        cb.write_prepare_info_file(out, u'b.example.test', u'sometoken')

        mode = (tmp_path / "info.json").stat().st_mode & 0o777
        assert mode == 0o600

    def test_read_missing_field_raises_validation_error(self, tmp_path):
        path = tmp_path / "incomplete.json"
        path.write_text(json.dumps(dict(server=u'b.example.test')))
        with pytest.raises(errors.ValidationError):
            cb.read_prepare_info_file('x', str(path))


@pytest.mark.usefixtures("patched_forward")
class TestTrustBootstrapInitForward:
    def test_writes_files_and_pops_keys_from_result(self, tmp_path):
        out = str(tmp_path / "a.key")
        cmd = make_command(cb.trust_bootstrap_init)

        with mock.patch.object(
                MethodOverride, 'forward', create=True,
                new=lambda *a, **kw: dict(result=dict(
                    kem_parameter_set=u'ML-KEM-768',
                    public_key='cHVibGlj',
                    private_key='cHJpdmF0ZQ==',
                ))):
            result = cmd.forward(out=out)

        assert 'public_key' not in result['result']
        assert 'private_key' not in result['result']
        assert result['result']['kem_parameter_set'] == u'ML-KEM-768'
        assert 'summary' in result

        parameter_set, priv_bytes = cb.read_keypair_file(
            'x', out, 'private_key')
        assert parameter_set == u'ML-KEM-768'
        assert priv_bytes == base64.b64decode('cHJpdmF0ZQ==')

    def test_without_out_leaves_result_untouched(self):
        cmd = make_command(cb.trust_bootstrap_init)

        with mock.patch.object(
                MethodOverride, 'forward', create=True,
                new=lambda *a, **kw: dict(result=dict(
                    kem_parameter_set=u'ML-KEM-768',
                    public_key='cHVibGlj',
                    private_key='cHJpdmF0ZQ==',
                ))):
            result = cmd.forward()

        assert result['result']['public_key'] == 'cHVibGlj'
        assert result['result']['private_key'] == 'cHJpdmF0ZQ=='
        assert 'summary' not in result


@pytest.mark.usefixtures("patched_forward")
class TestTrustBootstrapPrepareForward:
    def test_uses_public_key_file(self, tmp_path):
        pub_file = str(tmp_path / "remote.pub")
        cb.write_keypair_files(
            str(tmp_path / "remote"), u'ML-KEM-768', 'cHVibGlj', 'x')

        cmd = make_command(cb.trust_bootstrap_prepare)
        result = cmd.forward(
            u'b.example.test', remote_kem_public_key_file=pub_file)

        sent = result['result']
        assert sent['remote_kem_public_key'] == base64.b64decode('cHVibGlj')
        assert sent['kem_parameter_set'] == u'ML-KEM-768'
        assert 'remote_kem_public_key_file' not in sent

    def test_raw_and_file_are_mutually_exclusive(self, tmp_path):
        pub_file = str(tmp_path / "remote.pub")
        cb.write_keypair_files(
            str(tmp_path / "remote"), u'ML-KEM-768', 'cHVibGlj', 'x')

        cmd = make_command(cb.trust_bootstrap_prepare)
        with pytest.raises(errors.MutuallyExclusiveError):
            cmd.forward(
                u'b.example.test',
                remote_kem_public_key_file=pub_file,
                remote_kem_public_key=b'raw')

    def test_neither_raw_nor_file_raises(self):
        cmd = make_command(cb.trust_bootstrap_prepare)
        with pytest.raises(errors.ValidationError):
            cmd.forward(u'b.example.test')

    def test_writes_out_file_and_pops_token(self, tmp_path):
        out = str(tmp_path / "info.json")
        cmd = make_command(cb.trust_bootstrap_prepare)

        with mock.patch.object(
                MethodOverride, 'forward', create=True,
                new=lambda *a, **kw: dict(result=dict(
                    token=u'sometoken', server=u'b.example.test'))):
            result = cmd.forward(
                u'b.example.test', remote_kem_public_key=b'raw', out=out)

        assert 'token' not in result['result']
        assert result['result']['server'] == u'b.example.test'
        server, token = cb.read_prepare_info_file('x', out)
        assert server == u'b.example.test'
        assert token == u'sometoken'


@pytest.mark.usefixtures("patched_forward")
class TestTrustBootstrapRetrieveForward:
    def test_uses_private_key_file_and_prepare_info_file(self, tmp_path):
        priv_file = str(tmp_path / "a.key")
        cb.write_keypair_files(priv_file, u'ML-KEM-768', 'x', 'cHJpdg==')
        info_file = str(tmp_path / "info.json")
        cb.write_prepare_info_file(
            info_file, u'b.example.test', u'sometoken')

        cmd = make_command(cb.trust_bootstrap_retrieve)
        result = cmd.forward(
            kem_private_key_file=priv_file, prepare_info_file=info_file)

        sent = result['result']
        assert sent['kem_private_key'] == base64.b64decode('cHJpdg==')
        assert sent['kem_parameter_set'] == u'ML-KEM-768'
        assert sent['server'] == u'b.example.test'
        assert sent['token'] == u'sometoken'
        assert 'kem_private_key_file' not in sent
        assert 'prepare_info_file' not in sent

    def test_raw_key_and_file_are_mutually_exclusive(self, tmp_path):
        priv_file = str(tmp_path / "a.key")
        cb.write_keypair_files(priv_file, u'ML-KEM-768', 'x', 'cHJpdg==')

        cmd = make_command(cb.trust_bootstrap_retrieve)
        with pytest.raises(errors.MutuallyExclusiveError):
            cmd.forward(
                kem_private_key_file=priv_file,
                kem_private_key=b'raw',
                server=u's', token=u't')

    def test_server_token_and_file_are_mutually_exclusive(self, tmp_path):
        priv_file = str(tmp_path / "a.key")
        cb.write_keypair_files(priv_file, u'ML-KEM-768', 'x', 'cHJpdg==')
        info_file = str(tmp_path / "info.json")
        cb.write_prepare_info_file(info_file, u's', u't')

        cmd = make_command(cb.trust_bootstrap_retrieve)
        with pytest.raises(errors.MutuallyExclusiveError):
            cmd.forward(
                kem_private_key_file=priv_file,
                prepare_info_file=info_file,
                server=u's', token=u't')

    def test_missing_key_raises(self):
        cmd = make_command(cb.trust_bootstrap_retrieve)
        with pytest.raises(errors.ValidationError):
            cmd.forward(server=u's', token=u't')

    def test_missing_server_or_token_raises(self, tmp_path):
        priv_file = str(tmp_path / "a.key")
        cb.write_keypair_files(priv_file, u'ML-KEM-768', 'x', 'cHJpdg==')

        cmd = make_command(cb.trust_bootstrap_retrieve)
        with pytest.raises(errors.ValidationError):
            cmd.forward(kem_private_key_file=priv_file, server=u's')
