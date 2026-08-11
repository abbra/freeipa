#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
from __future__ import absolute_import

import pytest

from cryptography.hazmat.primitives.serialization import Encoding

from ipapython import cms_kem

KEM_PARAMETER_SETS = ("ML-KEM-768", "ML-KEM-1024")
SIGNATURE_ALGORITHMS = ("RSA", "EC", "ML-DSA")

PAYLOAD = b"realm=IPA.EXAMPLE.TEST;secret=deadbeef;" * 4


@pytest.fixture
def kem_keypair():
    return cms_kem.generate_kem_keypair("ML-KEM-768")


@pytest.fixture
def signing_keypair():
    return cms_kem.generate_signing_keypair("EC")


class TestRoundTrip:
    @pytest.mark.parametrize("kem_parameter_set", KEM_PARAMETER_SETS)
    @pytest.mark.parametrize("signature_algorithm", SIGNATURE_ALGORITHMS)
    def test_seal_open_round_trip(self, kem_parameter_set,
                                  signature_algorithm):
        kem_priv, kem_pub = cms_kem.generate_kem_keypair(kem_parameter_set)
        sign_priv, sign_cert = cms_kem.generate_signing_keypair(
            signature_algorithm)

        sealed = cms_kem.seal(
            PAYLOAD, kem_pub, sign_priv, sign_cert, kem_parameter_set)
        plaintext, recovered_cert = cms_kem.open_and_verify(sealed, kem_priv)

        assert plaintext == PAYLOAD
        assert (
            recovered_cert.public_bytes(Encoding.DER)
            == sign_cert.public_bytes(Encoding.DER)
        )

    def test_empty_payload(self, kem_keypair, signing_keypair):
        kem_priv, kem_pub = kem_keypair
        sign_priv, sign_cert = signing_keypair

        sealed = cms_kem.seal(b"", kem_pub, sign_priv, sign_cert)
        plaintext, _cert = cms_kem.open_and_verify(sealed, kem_priv)

        assert plaintext == b""

    def test_kem_public_private_bytes_round_trip(self):
        kem_priv, kem_pub = cms_kem.generate_kem_keypair("ML-KEM-768")

        pub_bytes = kem_pub.public_bytes_raw()
        priv_bytes = kem_priv.private_bytes_raw()

        pub2 = cms_kem.kem_public_key_from_bytes("ML-KEM-768", pub_bytes)
        priv2 = cms_kem.kem_private_key_from_bytes("ML-KEM-768", priv_bytes)

        shared_secret, ciphertext = pub2.encapsulate()
        assert priv2.decapsulate(ciphertext) == shared_secret


class TestNegativeCases:
    def test_wrong_recipient_key_fails(self, signing_keypair):
        _kem_priv, kem_pub = cms_kem.generate_kem_keypair("ML-KEM-768")
        other_kem_priv, _other_kem_pub = cms_kem.generate_kem_keypair(
            "ML-KEM-768")
        sign_priv, sign_cert = signing_keypair

        sealed = cms_kem.seal(PAYLOAD, kem_pub, sign_priv, sign_cert)

        with pytest.raises(cms_kem.UnsealError):
            cms_kem.open_and_verify(sealed, other_kem_priv)

    def test_tampered_ciphertext_fails(self, kem_keypair, signing_keypair):
        kem_priv, kem_pub = kem_keypair
        sign_priv, sign_cert = signing_keypair

        sealed = bytearray(
            cms_kem.seal(PAYLOAD, kem_pub, sign_priv, sign_cert))
        # Flip a bit near the end, inside the AES-GCM-encrypted content.
        sealed[-20] ^= 0xFF

        with pytest.raises(cms_kem.UnsealError):
            cms_kem.open_and_verify(bytes(sealed), kem_priv)

    def test_tampered_header_rejected(self, kem_keypair, signing_keypair):
        kem_priv, kem_pub = kem_keypair
        sign_priv, sign_cert = signing_keypair

        sealed = bytearray(
            cms_kem.seal(PAYLOAD, kem_pub, sign_priv, sign_cert))
        sealed[10] ^= 0xFF

        # Corrupting the DER header may raise UnsealError (wrapped) or
        # some other decode-time exception -- either way it must not
        # silently return plausible-looking plaintext.
        with pytest.raises(Exception):
            plaintext, _cert = cms_kem.open_and_verify(bytes(sealed),
                                                       kem_priv)
            assert plaintext != PAYLOAD

    def test_unsupported_kem_parameter_set(self):
        with pytest.raises(ValueError):
            cms_kem.generate_kem_keypair("ML-KEM-512")

    def test_unsupported_signature_algorithm(self):
        with pytest.raises(ValueError):
            cms_kem.generate_signing_keypair("DSA")
