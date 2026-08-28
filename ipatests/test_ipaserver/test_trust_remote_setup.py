#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
"""Unit tests for configuring the remote IPA deployment's own half of
an IPA-to-IPA trust (ipaserver/plugins/trust.py
configure_remote_ipa_half).

When remote administrator credentials are given, the trust's remote
half (trust object, cross-realm principal and the ID range for our
domain) is created by running a local-only trust_add on the remote
deployment's own IPA API, authenticated as the given administrator.
"""
from __future__ import absolute_import

import datetime
import os
from unittest import mock

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ipalib import errors

from ipaserver.plugins import trust as trust_mod


def _make_ca_pem(common_name):
    """A throwaway self-signed CA certificate in PEM form."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = cx509.Name([
        cx509.NameAttribute(cx509.NameOID.COMMON_NAME, common_name)
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(
            now - datetime.timedelta(days=1))
        .not_valid_after(
            now + datetime.timedelta(days=365))
        .add_extension(
            cx509.BasicConstraints(ca=True, path_length=None),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class FakeRemoteApi:
    def __init__(self):
        self.Command = mock.MagicMock()
        self.bootstrap_kwargs = None
        self.finalized = 0

    def bootstrap(self, **kwargs):
        self.bootstrap_kwargs = kwargs

    def finalize(self):
        self.finalized += 1


class TestConfigureRemoteIpaHalf:
    def _run(self, api, bidirectional=True,
             kinit_side_effect=None, ca_chain_file=None):
        with mock.patch.object(trust_mod, 'create_api',
                               return_value=api), \
             mock.patch.object(
                trust_mod, 'kinit_password',
                side_effect=kinit_side_effect) as kinit:
            imported = trust_mod.configure_remote_ipa_half(
                u'b.example.test',
                u'b-server.example.test',
                u'admin',
                u'password',
                u'ipa.test',
                u'server.ipa.test',
                u'shared-secret',
                bidirectional,
                ca_chain_file)
        return kinit, imported

    def test_calls_remote_trust_add_with_matching_secret(self):
        api = FakeRemoteApi()
        self._run(api, bidirectional=True)

        api.Command.trust_add.assert_called_once_with(
            u'ipa.test',
            trust_type=u'ipa',
            trust_secret=u'shared-secret',
            realm_server=u'server.ipa.test',
            bidirectional=True)
        assert api.bootstrap_kwargs['in_server'] is True
        assert api.bootstrap_kwargs['xmlrpc_uri'] == (
            'https://b-server.example.test/ipa/xml')
        # the client API is finalized again after use
        assert api.finalized >= 2

    def test_kinit_uses_remote_admin_principal(self):
        api = FakeRemoteApi()
        kinit, _imported = self._run(api, bidirectional=False)

        kinit.assert_called_once_with(
            u'admin@B.EXAMPLE.TEST', u'password')
        assert api.Command.trust_add.call_args[1]['bidirectional'] is \
            False

    def test_kinit_failure_raises_validation_error(self):
        api = FakeRemoteApi()
        with pytest.raises(errors.ValidationError):
            self._run(api, kinit_side_effect=RuntimeError('bad password'))
        # no remote command may have been issued
        api.Command.trust_add.assert_not_called()

    def test_cert_verifier_installed_for_command_and_cleared_after(self):
        api = FakeRemoteApi()
        seen = {}

        def capture(*_args, **_kwargs):
            seen['verifier'] = trust_mod.context.cert_verifier

        api.Command.trust_add.side_effect = capture
        self._run(api)

        assert callable(seen['verifier'])
        # the verifier must not outlive the call
        assert trust_mod.context.cert_verifier is None

    def test_ca_chain_file_is_passed_to_the_verifier(self, tmp_path):
        api = FakeRemoteApi()
        chain_file = tmp_path / 'chain.pem'
        chain_file.write_bytes(_make_ca_pem('B Example Test IPA CA'))
        seen = {}

        def capture(*_args, **_kwargs):
            seen['verifier'] = trust_mod.context.cert_verifier

        api.Command.trust_add.side_effect = capture
        with mock.patch.object(
                trust_mod, '_fetch_remote_ipa_ca_chain') as fetch:
            _kinit, imported = self._run(
                api, ca_chain_file=str(chain_file))

        # the command ran under a verifier anchored on the given file;
        # no TOFU fetch or import may have happened
        anchor = seen['verifier'](u'b-server.example.test')
        assert anchor is not None
        assert open(anchor, 'rb').read() == chain_file.read_bytes()
        assert not fetch.called
        assert imported == []
        os.unlink(anchor)


class TestRemoteIpaCaVerifier:
    def test_tofu_imports_chain_and_returns_bundle(self):
        pem = _make_ca_pem('B Example Test IPA CA')
        with mock.patch.object(trust_mod, 'api', mock.MagicMock()), \
             mock.patch.object(
                trust_mod, '_fetch_remote_ipa_ca_chain',
                return_value=pem) as fetch, \
             mock.patch.object(
                trust_mod.certstore, 'put_ca_cert') as put:
            verifier, imported = \
                trust_mod._build_remote_ipa_ca_verifier(
                    u'b.example.test', None)
            path = verifier(u'b.example.test')

        assert fetch.called
        assert path is not None
        assert len(imported) == 1
        assert open(path, 'rb').read() == pem
        assert put.call_count == 1
        args, kwargs = put.call_args
        assert kwargs['trusted'] is True
        os.unlink(path)

    def test_tofu_returns_none_when_fetch_fails(self):
        with mock.patch.object(trust_mod, 'api', mock.MagicMock()), \
             mock.patch.object(
                trust_mod, '_fetch_remote_ipa_ca_chain',
                return_value=None) as fetch, \
             mock.patch.object(trust_mod.certstore, 'put_ca_cert') as put:
            verifier, imported = \
                trust_mod._build_remote_ipa_ca_verifier(
                    u'b.example.test', None)
            assert verifier(u'b.example.test') is None

        assert fetch.called
        assert not put.called
        assert imported == []

    def test_invalid_chain_returns_none(self):
        with mock.patch.object(trust_mod, 'api', mock.MagicMock()), \
             mock.patch.object(
                trust_mod, '_fetch_remote_ipa_ca_chain',
                return_value=b'not a certificate'):
            verifier, imported = \
                trust_mod._build_remote_ipa_ca_verifier(
                    u'b.example.test', None)
            assert verifier(u'b.example.test') is None
        assert imported == []

    def test_strict_mode_uses_file_without_fetch_or_import(self,
                                                           tmp_path):
        pem = _make_ca_pem('B Example Test IPA CA')
        chain_file = tmp_path / 'chain.pem'
        chain_file.write_bytes(pem)
        with mock.patch.object(trust_mod, 'api', mock.MagicMock()), \
             mock.patch.object(
                trust_mod, '_fetch_remote_ipa_ca_chain') as fetch, \
             mock.patch.object(trust_mod.certstore, 'put_ca_cert') as put:
            verifier, imported = \
                trust_mod._build_remote_ipa_ca_verifier(
                    u'b.example.test', str(chain_file))
            path = verifier(u'b.example.test')

        assert not fetch.called
        assert not put.called
        assert imported == []
        assert path is not None
        assert open(path, 'rb').read() == pem
        os.unlink(path)
