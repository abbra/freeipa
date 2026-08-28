#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
from __future__ import absolute_import

import base64
import hashlib
import json
from unittest import mock

import pytest

from cryptography.hazmat.primitives.serialization import Encoding

from ipalib import errors
from ipapython.dn import DN

from ipapython import cms_kem
from ipaserver.plugins import trust_bootstrap as tb


class FakeLDAP:
    def __init__(self, allow_write=True):
        self.added_entries = []
        self.deleted = []
        self.allow_write = allow_write

    def can_write(self, dn, attr):
        return self.allow_write

    def make_entry(self, dn, **kw):
        entry = dict(kw)
        entry['dn'] = dn
        return entry

    def add_entry(self, entry):
        self.added_entries.append(entry)

    def delete_entry(self, dn):
        self.deleted.append(dn)


class FakeApi:
    def __init__(self, allow_write=True):
        self.Backend = mock.MagicMock()
        self.Backend.ldap2 = FakeLDAP(allow_write=allow_write)
        self.Command = mock.MagicMock()
        self.env = mock.MagicMock()
        self.env.realm = 'IPA.TEST'
        self.env.domain = 'ipa.test'
        self.env.host = 'server.ipa.test'
        self.env.basedn = DN('dc=ipa,dc=test')
        self.env.container_virtual = DN(
            ('cn', 'virtual operations'), ('cn', 'etc'))


def make_command(cls, api):
    """Build a Command instance directly, bypassing API/plugin discovery.

    Plugin.__init__(self, api) is all these classes need; execute() only
    ever touches self.api.
    """
    return cls(api)


class TestVirtualOperationAccess:
    """check_access() (ipaserver/plugins/virtual.py VirtualCommand) is the
    real enforcement mechanism -- these confirm it is actually wired up
    for all three commands, same as cert_status/cert_request/etc."""

    @pytest.mark.parametrize("cls", [
        tb.trust_bootstrap_init,
        tb.trust_bootstrap_prepare,
        tb.trust_bootstrap_retrieve,
    ])
    def test_denied_without_write_access(self, cls):
        api = FakeApi(allow_write=False)
        cmd = make_command(cls, api)
        with pytest.raises(errors.ACIError):
            cmd.check_access()

    @pytest.mark.parametrize("cls", [
        tb.trust_bootstrap_init,
        tb.trust_bootstrap_prepare,
        tb.trust_bootstrap_retrieve,
    ])
    def test_allowed_with_write_access(self, cls):
        api = FakeApi(allow_write=True)
        cmd = make_command(cls, api)
        cmd.check_access()  # must not raise


class TestTrustBootstrapInit:
    def test_generates_usable_keypair(self):
        api = FakeApi()
        cmd = make_command(tb.trust_bootstrap_init, api)

        result = cmd.execute(kem_parameter_set=u'ML-KEM-768')['result']

        assert result['kem_parameter_set'] == u'ML-KEM-768'
        pub_key = cms_kem.kem_public_key_from_bytes(
            'ML-KEM-768', base64.b64decode(result['public_key']))
        priv_key = cms_kem.kem_private_key_from_bytes(
            'ML-KEM-768', base64.b64decode(result['private_key']))
        shared_secret, ciphertext = pub_key.encapsulate()
        assert priv_key.decapsulate(ciphertext) == shared_secret

    def test_requires_virtual_operation_access(self):
        api = FakeApi(allow_write=False)
        cmd = make_command(tb.trust_bootstrap_init, api)
        with pytest.raises(errors.ACIError):
            cmd.execute(kem_parameter_set=u'ML-KEM-768')


class TestTrustBootstrapPrepare:
    def test_seals_package_and_configures_local_trust(self):
        api = FakeApi()
        ldap = api.Backend.ldap2

        kem_priv, kem_pub = cms_kem.generate_kem_keypair('ML-KEM-768')
        remote_pub_bytes = kem_pub.public_bytes_raw()

        _sign_priv, ca_cert = cms_kem.generate_signing_keypair('EC')

        # Realm-wide chain identical to the KDC chain -- the common case,
        # should be de-duplicated (no separate realm_ca_certs in payload).
        with mock.patch.object(
                tb, '_get_kdc_ca_chain', return_value=[ca_cert]), \
             mock.patch.object(
                tb.certstore, 'get_ca_certs',
                return_value=[(ca_cert, 'Test CA', True, None, 1)]):
            cmd = make_command(tb.trust_bootstrap_prepare, api)
            result = cmd.execute(
                u'b.example.test',
                remote_kem_public_key=remote_pub_bytes,
                kem_parameter_set=u'ML-KEM-768',
                signature_algorithm=u'EC',
                ttl=3600,
                bidirectional=False,
            )['result']

        assert 'token' in result
        assert result['server'] == 'server.ipa.test'

        assert len(ldap.added_entries) == 1
        entry = ldap.added_entries[0]
        token_hash = hashlib.sha256(
            result['token'].encode('ascii')).hexdigest()
        assert entry['cn'] == [token_hash]
        assert 'ipatrustbootstrapciphertext' in entry
        assert 'ipatrustbootstrapexpires' in entry

        api.Command.trust_add.assert_called_once()
        call_args, call_kwargs = api.Command.trust_add.call_args
        assert call_args[0] == u'b.example.test'
        assert call_kwargs['trust_type'] == u'ipa'
        assert call_kwargs['bidirectional'] is False
        assert 'trust_secret' in call_kwargs
        # IPA-to-IPA trusts must use POSIX ID ranges even when the
        # admin does not pass --range-type
        assert call_kwargs['range_type'] == u'ipa-ad-trust-posix'

        sealed = entry['ipatrustbootstrapciphertext'][0]
        plaintext, _cert = cms_kem.open_and_verify(sealed, kem_priv)
        payload = json.loads(plaintext.decode('utf-8'))
        assert payload['trust_secret'] == call_kwargs['trust_secret']
        assert payload['domain'] == 'ipa.test'
        assert payload['realm'] == 'IPA.TEST'
        assert payload['kdc_ca_certs'] == [
            base64.b64encode(ca_cert.public_bytes(Encoding.DER)).decode(
                'ascii')]
        assert 'realm_ca_certs' not in payload

    def test_requires_virtual_operation_access(self):
        api = FakeApi(allow_write=False)
        _kem_priv, kem_pub = cms_kem.generate_kem_keypair('ML-KEM-768')
        cmd = make_command(tb.trust_bootstrap_prepare, api)
        with pytest.raises(errors.ACIError):
            cmd.execute(
                u'b.example.test',
                remote_kem_public_key=kem_pub.public_bytes_raw(),
                kem_parameter_set=u'ML-KEM-768',
                signature_algorithm=u'EC',
                ttl=3600,
            )

    def test_fails_when_no_pkinit_ca_bundle(self, tmp_path):
        # No paths.CACERT_PEM at all -- e.g. PKINIT never enabled here.
        api = FakeApi()
        _kem_priv, kem_pub = cms_kem.generate_kem_keypair('ML-KEM-768')

        with mock.patch.object(
                tb.paths, 'CACERT_PEM', str(tmp_path / "does-not-exist")):
            cmd = make_command(tb.trust_bootstrap_prepare, api)
            with pytest.raises(errors.NotFound):
                cmd.execute(
                    u'b.example.test',
                    remote_kem_public_key=kem_pub.public_bytes_raw(),
                    kem_parameter_set=u'ML-KEM-768',
                    signature_algorithm=u'EC',
                    ttl=3600,
                )

    def test_fails_when_pkinit_ca_bundle_empty(self, tmp_path):
        # paths.CACERT_PEM exists but empty -- self-signed KDC cert.
        api = FakeApi()
        _kem_priv, kem_pub = cms_kem.generate_kem_keypair('ML-KEM-768')
        empty_bundle = tmp_path / "cacert.pem"
        empty_bundle.write_text("")

        with mock.patch.object(tb.paths, 'CACERT_PEM', str(empty_bundle)):
            cmd = make_command(tb.trust_bootstrap_prepare, api)
            with pytest.raises(errors.NotFound):
                cmd.execute(
                    u'b.example.test',
                    remote_kem_public_key=kem_pub.public_bytes_raw(),
                    kem_parameter_set=u'ML-KEM-768',
                    signature_algorithm=u'EC',
                    ttl=3600,
                )

    def test_reads_actual_kdc_ca_bundle_file(self, tmp_path):
        # The real code path (no mocking of _get_kdc_ca_chain itself):
        # confirms trust_bootstrap_prepare's KDC chain comes from
        # paths.CACERT_PEM, independent of whatever the general CA store
        # returns (here: nothing).
        api = FakeApi()
        kem_priv, kem_pub = cms_kem.generate_kem_keypair('ML-KEM-768')
        _sign_priv, kdc_ca_cert = cms_kem.generate_signing_keypair('EC')

        bundle = tmp_path / "cacert.pem"
        bundle.write_bytes(kdc_ca_cert.public_bytes(Encoding.PEM))

        with mock.patch.object(tb.paths, 'CACERT_PEM', str(bundle)), \
             mock.patch.object(
                tb.certstore, 'get_ca_certs', return_value=[]):
            cmd = make_command(tb.trust_bootstrap_prepare, api)
            result = cmd.execute(
                u'b.example.test',
                remote_kem_public_key=kem_pub.public_bytes_raw(),
                kem_parameter_set=u'ML-KEM-768',
                signature_algorithm=u'EC',
                ttl=3600,
            )['result']

        entry = api.Backend.ldap2.added_entries[0]
        sealed = entry['ipatrustbootstrapciphertext'][0]
        plaintext, _cert = cms_kem.open_and_verify(sealed, kem_priv)
        payload = json.loads(plaintext.decode('utf-8'))
        assert payload['kdc_ca_certs'] == [base64.b64encode(
            kdc_ca_cert.public_bytes(Encoding.DER)).decode('ascii')]
        assert 'realm_ca_certs' not in payload
        assert 'token' in result

    def test_sends_separate_realm_chain_when_it_differs(self):
        # KDC PKINIT certificate issued by a different CA than the one
        # backing the deployment's general HTTPS/LDAP certs -- both
        # chains must reach the other side.
        api = FakeApi()
        kem_priv, kem_pub = cms_kem.generate_kem_keypair('ML-KEM-768')
        _p1, kdc_ca_cert = cms_kem.generate_signing_keypair('EC')
        _p2, realm_ca_cert = cms_kem.generate_signing_keypair('RSA')

        with mock.patch.object(
                tb, '_get_kdc_ca_chain', return_value=[kdc_ca_cert]), \
             mock.patch.object(
                tb.certstore, 'get_ca_certs',
                return_value=[(realm_ca_cert, 'Realm CA', True, None, 1)]):
            cmd = make_command(tb.trust_bootstrap_prepare, api)
            cmd.execute(
                u'b.example.test',
                remote_kem_public_key=kem_pub.public_bytes_raw(),
                kem_parameter_set=u'ML-KEM-768',
                signature_algorithm=u'EC',
                ttl=3600,
            )

        entry = api.Backend.ldap2.added_entries[0]
        sealed = entry['ipatrustbootstrapciphertext'][0]
        plaintext, _cert = cms_kem.open_and_verify(sealed, kem_priv)
        payload = json.loads(plaintext.decode('utf-8'))
        assert payload['kdc_ca_certs'] == [base64.b64encode(
            kdc_ca_cert.public_bytes(Encoding.DER)).decode('ascii')]
        assert payload['realm_ca_certs'] == [base64.b64encode(
            realm_ca_cert.public_bytes(Encoding.DER)).decode('ascii')]


class TestTrustBootstrapRetrieve:
    def _sealed_response(self, domain='b.example.test',
                         realm='B.EXAMPLE.TEST',
                         server='b-server.example.test',
                         trust_secret='s3cr3t',
                         realm_ca_cert=None):
        kem_priv, kem_pub = cms_kem.generate_kem_keypair('ML-KEM-768')
        sign_priv, sign_cert = cms_kem.generate_signing_keypair('EC')

        payload_dict = dict(
            realm=realm, domain=domain, server=server,
            trust_secret=trust_secret,
            kdc_ca_certs=[base64.b64encode(
                sign_cert.public_bytes(Encoding.DER)).decode('ascii')],
        )
        if realm_ca_cert is not None:
            payload_dict['realm_ca_certs'] = [base64.b64encode(
                realm_ca_cert.public_bytes(Encoding.DER)).decode('ascii')]
        payload = json.dumps(payload_dict).encode('utf-8')
        sealed = cms_kem.seal(payload, kem_pub, sign_priv, sign_cert)
        return kem_priv, sealed

    def test_opens_package_and_configures_local_trust(self):
        api = FakeApi()
        kem_priv, sealed = self._sealed_response()
        fake_response = mock.MagicMock(status_code=200, content=sealed)

        with mock.patch.object(
                tb.requests, 'get', return_value=fake_response), \
             mock.patch.object(tb, '_log_tofu_peer_certificate'), \
             mock.patch.object(tb.certstore, 'put_ca_cert') as put_ca_cert:
            cmd = make_command(tb.trust_bootstrap_retrieve, api)
            full_result = cmd.execute(
                server=u'b-server.example.test',
                token=u'sometoken',
                kem_private_key=kem_priv.private_bytes_raw(),
                kem_parameter_set=u'ML-KEM-768',
                bidirectional=False,
            )
            result = full_result['result']

        assert result['domain'] == 'b.example.test'
        assert result['realm'] == 'B.EXAMPLE.TEST'
        put_ca_cert.assert_called_once()
        _ldap, _basedn, _cert, _nick = put_ca_cert.call_args[0]
        assert put_ca_cert.call_args[1]['trusted'] is True
        assert put_ca_cert.call_args[1]['ext_key_usage'] == {
            tb.x509.EKU_PKINIT_KDC, tb.x509.EKU_PKINIT_CLIENT_AUTH}

        # certstore.put_ca_cert() alone doesn't reach any already-enrolled
        # server/client -- the admin still has to run ipa-certupdate
        # everywhere, and the command must say so rather than implying
        # the newly-trusted realm's KDC certs are already trusted fleet-wide.
        assert 'ipa-certupdate' in full_result['summary']

        api.Command.trust_add.assert_called_once()
        call_args, call_kwargs = api.Command.trust_add.call_args
        assert call_args[0] == 'b.example.test'
        assert call_kwargs['trust_type'] == u'ipa'
        assert call_kwargs['trust_secret'] == 's3cr3t'
        assert call_kwargs['realm_server'] == 'b-server.example.test'
        # IPA-to-IPA trusts must use POSIX ID ranges even when the
        # admin does not pass --range-type
        assert call_kwargs['range_type'] == u'ipa-ad-trust-posix'

    def test_imports_both_chains_when_sent_separately(self):
        api = FakeApi()
        _p, realm_ca_cert = cms_kem.generate_signing_keypair('RSA')
        kem_priv, sealed = self._sealed_response(realm_ca_cert=realm_ca_cert)
        fake_response = mock.MagicMock(status_code=200, content=sealed)

        with mock.patch.object(
                tb.requests, 'get', return_value=fake_response), \
             mock.patch.object(tb, '_log_tofu_peer_certificate'), \
             mock.patch.object(tb.certstore, 'put_ca_cert') as put_ca_cert:
            cmd = make_command(tb.trust_bootstrap_retrieve, api)
            full_result = cmd.execute(
                server=u'b-server.example.test',
                token=u'sometoken',
                kem_private_key=kem_priv.private_bytes_raw(),
                kem_parameter_set=u'ML-KEM-768',
            )

        assert put_ca_cert.call_count == 2
        first_call, second_call = put_ca_cert.call_args_list
        # KDC/PKINIT chain imported with the PKINIT EKU markers
        assert first_call.kwargs['ext_key_usage'] == {
            tb.x509.EKU_PKINIT_KDC, tb.x509.EKU_PKINIT_CLIENT_AUTH}
        # separate realm-wide chain imported as a plain trusted CA
        assert 'ext_key_usage' not in second_call.kwargs
        assert second_call.kwargs['trusted'] is True

        assert 'separate realm-wide CA certificate' in full_result['summary']

    def test_not_found_raises(self):
        api = FakeApi()
        fake_response = mock.MagicMock(status_code=404, content=b'')

        with mock.patch.object(
                tb.requests, 'get', return_value=fake_response), \
             mock.patch.object(tb, '_log_tofu_peer_certificate'):
            cmd = make_command(tb.trust_bootstrap_retrieve, api)
            with pytest.raises(errors.NotFound):
                cmd.execute(
                    server=u'b-server.example.test',
                    token=u'sometoken',
                    kem_private_key=b'\x00' * 64,
                    kem_parameter_set=u'ML-KEM-768',
                )

    def test_wrong_private_key_raises_validation_error(self):
        api = FakeApi()
        _correct_priv, sealed = self._sealed_response()
        other_priv, _other_pub = cms_kem.generate_kem_keypair('ML-KEM-768')
        fake_response = mock.MagicMock(status_code=200, content=sealed)

        with mock.patch.object(
                tb.requests, 'get', return_value=fake_response), \
             mock.patch.object(tb, '_log_tofu_peer_certificate'):
            cmd = make_command(tb.trust_bootstrap_retrieve, api)
            with pytest.raises(errors.ValidationError):
                cmd.execute(
                    server=u'b-server.example.test',
                    token=u'sometoken',
                    kem_private_key=other_priv.private_bytes_raw(),
                    kem_parameter_set=u'ML-KEM-768',
                )

    def test_requires_virtual_operation_access(self):
        api = FakeApi(allow_write=False)
        cmd = make_command(tb.trust_bootstrap_retrieve, api)
        with pytest.raises(errors.ACIError):
            cmd.execute(
                server=u'b-server.example.test',
                token=u'sometoken',
                kem_private_key=b'\x00' * 64,
                kem_parameter_set=u'ML-KEM-768',
            )
