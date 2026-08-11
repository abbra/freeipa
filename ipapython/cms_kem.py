# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
"""CMS SignedData(EnvelopedData) sealing with an ML-KEM recipient.

Implements the minimum subset of RFC 5652 (Cryptographic Message Syntax)
and RFC 9629 (KEMRecipientInfo) needed to seal a small payload to a
one-time ML-KEM public key and sign the result with a configurable
classical or post-quantum signature algorithm (RSA, EC, or ML-DSA).

The wire format is modeled on the CMS structure used by Ahdapa's own
inter-node gossip protocol (SignedData wrapping EnvelopedData, ML-KEM for
key encapsulation, AES-256-GCM content encryption, AES-256 key wrap of the
content-encryption key), with one difference: the outer signature
algorithm is a runtime choice here rather than fixed to ECDSA P-256.

This module only ever builds and parses a single-recipient, single-signer
message. It intentionally does not implement general CMS (multiple
recipient types, signed/unsigned attributes, certificate chains).
"""

from __future__ import absolute_import

import os

from pyasn1.type import namedtype, tag, univ
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    ec, mldsa, mlkem, padding, rsa)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

# RFC 5652
ID_DATA = '1.2.840.113549.1.7.1'
ID_SIGNED_DATA = '1.2.840.113549.1.7.2'
ID_ENVELOPED_DATA = '1.2.840.113549.1.7.3'
ID_SHA256 = '2.16.840.1.101.3.4.2.1'

# RFC 9629 (CMS KEMRecipientInfo)
ID_ORI_KEM = '1.2.840.113549.1.9.16.13.3'

# RFC 8619 (HKDF algorithm identifiers for CMS)
ID_ALG_HKDF_WITH_SHA256 = '1.2.840.113549.1.9.16.3.28'

# NIST CSOR AES arc
ID_AES256_WRAP = '2.16.840.1.101.3.4.1.45'
# RFC 5084 (AES-GCM for CMS)
ID_AES256_GCM = '2.16.840.1.101.3.4.1.46'

KEK_INFO = b"ipa-trust-bootstrap-kek"
NONCE_LEN = 12
KEY_LEN = 32

_MLKEM_ALGORITHMS = {
    "ML-KEM-768": (mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey,
                   '2.16.840.1.101.3.4.4.2'),
    "ML-KEM-1024": (mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey,
                    '2.16.840.1.101.3.4.4.3'),
}

_MLDSA_ALGORITHMS = {
    "ML-DSA-44": mldsa.MLDSA44PrivateKey,
    "ML-DSA-65": mldsa.MLDSA65PrivateKey,
    "ML-DSA-87": mldsa.MLDSA87PrivateKey,
}

_MLDSA_PRIVATE_CLASSES = tuple(_MLDSA_ALGORITHMS.values())
_MLDSA_PUBLIC_CLASSES = (
    mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey,
)

_MLKEM_PUBLIC_CLASSES = tuple(
    pub for _priv, pub, _oid in _MLKEM_ALGORITHMS.values()
)
_MLKEM_PRIVATE_CLASSES = tuple(
    priv for priv, _pub, _oid in _MLKEM_ALGORITHMS.values()
)


class UnsealError(Exception):
    """Raised when a sealed CMS message cannot be verified or decrypted."""


# --- ASN.1 structures -------------------------------------------------

class _AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any()),
    )


class _KEMRecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(0)),
        # RecipientIdentifier CHOICE, subjectKeyIdentifier [0] alternative
        namedtype.NamedType(
            'rid',
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('kem', _AlgorithmIdentifier()),
        namedtype.NamedType('kemct', univ.OctetString()),
        namedtype.NamedType('kdf', _AlgorithmIdentifier()),
        namedtype.NamedType('kekLength', univ.Integer()),
        namedtype.NamedType('wrap', _AlgorithmIdentifier()),
        namedtype.NamedType('encryptedKey', univ.OctetString()),
    )


class _OtherRecipientInfo(univ.Sequence):
    # RecipientInfo ::= CHOICE { ..., ori [4] OtherRecipientInfo }
    # Encoded IMPLICIT so the outer tag is context-constructed 4 (0xa4)
    # instead of a plain SEQUENCE (0x30) -- this is the one CHOICE
    # alternative this module ever produces or consumes.
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('oriType', univ.ObjectIdentifier()),
        namedtype.NamedType('oriValue', univ.Any()),
    )


class _GCMParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('aes-nonce', univ.OctetString()),
        namedtype.NamedType('aes-ICVlen', univ.Integer()),
    )


class _EncryptedContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', univ.ObjectIdentifier()),
        namedtype.NamedType(
            'contentEncryptionAlgorithm', _AlgorithmIdentifier()),
        namedtype.OptionalNamedType(
            'encryptedContent',
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0))),
    )


class _EnvelopedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(2)),
        namedtype.NamedType(
            'recipientInfos', univ.SetOf(componentType=_OtherRecipientInfo())),
        namedtype.NamedType('encryptedContentInfo', _EncryptedContentInfo()),
    )


class _ContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', univ.ObjectIdentifier()),
        namedtype.NamedType(
            'content',
            univ.Any().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0))),
    )


class _EncapsulatedContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('eContentType', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType(
            'eContent',
            univ.OctetString().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0))),
    )


class _IssuerAndSerialNumber(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', univ.Any()),
        namedtype.NamedType('serialNumber', univ.Integer()),
    )


class _SignerInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(1)),
        namedtype.NamedType('sid', _IssuerAndSerialNumber()),
        namedtype.NamedType('digestAlgorithm', _AlgorithmIdentifier()),
        namedtype.NamedType('signatureAlgorithm', _AlgorithmIdentifier()),
        namedtype.NamedType('signature', univ.OctetString()),
    )


class _CertificateSet(univ.SetOf):
    # certificates [0] IMPLICIT CertificateSet OPTIONAL (RFC 5652). Each
    # element is a plain (untagged) Certificate SEQUENCE -- only the SET
    # itself carries the context tag.
    componentType = univ.Any()
    tagSet = univ.SetOf.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))


class _SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(1)),
        namedtype.NamedType(
            'digestAlgorithms', univ.SetOf(componentType=_AlgorithmIdentifier())
        ),
        namedtype.NamedType('encapContentInfo', _EncapsulatedContentInfo()),
        namedtype.NamedType('certificates', _CertificateSet()),
        namedtype.NamedType(
            'signerInfos', univ.SetOf(componentType=_SignerInfo())
        ),
    )


# --- small helpers ------------------------------------------------------

def _alg_id(oid, parameters_der=None):
    value = _AlgorithmIdentifier()
    value['algorithm'] = univ.ObjectIdentifier(oid)
    if parameters_der is not None:
        value['parameters'] = parameters_der
    return value


def _sign_data(private_key, data):
    """Sign data with an RSA, EC, or ML-DSA private key."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(
            data, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, _MLDSA_PRIVATE_CLASSES):
        return private_key.sign(data)
    raise TypeError(
        "unsupported signing key type: %s" % type(private_key))


def _verify_signature(public_key, signature, data):
    """Verify a signature made by _sign_data(). Raises on failure."""
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            signature, data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(public_key, _MLDSA_PUBLIC_CLASSES):
        public_key.verify(signature, data)
    else:
        raise TypeError(
            "unsupported verification key type: %s" % type(public_key))


def _kem_public_key_class(parameter_set):
    try:
        return _MLKEM_ALGORITHMS[parameter_set]
    except KeyError:
        raise ValueError(
            "unsupported ML-KEM parameter set: %r" % (parameter_set,))


# --- public API -----------------------------------------------------

def generate_kem_keypair(parameter_set="ML-KEM-768"):
    """Generate a one-time ML-KEM keypair.

    Returns (private_key, public_key). Neither is wrapped in a
    certificate: ML-KEM keys cannot sign, so RFC 5652's
    RecipientIdentifier only ever needs a bare public key here, never a
    certificate.
    """
    priv_cls, _pub_cls, _oid = _kem_public_key_class(parameter_set)
    private_key = priv_cls.generate()
    return private_key, private_key.public_key()


def kem_public_key_from_bytes(parameter_set, data):
    """Load an ML-KEM public key from its raw SPKI DER bytes."""
    _priv_cls, pub_cls, _oid = _kem_public_key_class(parameter_set)
    return pub_cls.from_public_bytes(data)


def kem_private_key_from_bytes(parameter_set, data):
    """Load an ML-KEM private key from its raw seed bytes."""
    priv_cls, _pub_cls, _oid = _kem_public_key_class(parameter_set)
    return priv_cls.from_seed_bytes(data)


def generate_signing_keypair(algorithm="EC", subject_cn="ipa-trust-bootstrap",
                             validity_days=7):
    """Generate a fresh signing keypair and a minimal self-signed cert.

    :param algorithm: one of "RSA", "EC", "ML-DSA".
    :returns: (private_key, certificate)
    """
    import datetime
    from cryptography.x509.oid import NameOID

    algorithm = algorithm.upper()
    if algorithm == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072)
        sign_algorithm = hashes.SHA256()
    elif algorithm == "EC":
        private_key = ec.generate_private_key(ec.SECP256R1())
        sign_algorithm = hashes.SHA256()
    elif algorithm == "ML-DSA":
        private_key = mldsa.MLDSA65PrivateKey.generate()
        sign_algorithm = None
    else:
        raise ValueError("unsupported signature algorithm: %r" % (algorithm,))

    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
    )
    certificate = builder.sign(private_key, sign_algorithm)
    return private_key, certificate


def seal(plaintext, recipient_kem_public_key, signing_private_key,
         signing_cert, kem_parameter_set="ML-KEM-768"):
    """Seal plaintext to recipient_kem_public_key, signed by signing_private_key

    :returns: DER-encoded ContentInfo(SignedData(EnvelopedData))
    """
    _priv_cls, _pub_cls, kem_oid = _kem_public_key_class(kem_parameter_set)

    # --- inner EnvelopedData ---
    cek = os.urandom(KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext, None)

    shared_secret, kemct = recipient_kem_public_key.encapsulate()
    kek = HKDF(
        algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=KEK_INFO,
    ).derive(shared_secret)
    encrypted_key = aes_key_wrap(kek, cek)

    ori = _OtherRecipientInfo()
    ori['oriType'] = univ.ObjectIdentifier(ID_ORI_KEM)
    kem_ri = _KEMRecipientInfo()
    kem_ri['rid'] = os.urandom(20)  # arbitrary identifier; single recipient
    kem_ri['kem'] = _alg_id(kem_oid)
    kem_ri['kemct'] = kemct
    kem_ri['kdf'] = _alg_id(ID_ALG_HKDF_WITH_SHA256)
    kem_ri['kekLength'] = KEY_LEN
    kem_ri['wrap'] = _alg_id(ID_AES256_WRAP)
    kem_ri['encryptedKey'] = encrypted_key
    ori['oriValue'] = der_encoder.encode(kem_ri)

    gcm_params = _GCMParameters()
    gcm_params['aes-nonce'] = nonce
    gcm_params['aes-ICVlen'] = 16

    enveloped = _EnvelopedData()
    enveloped['version'] = 2
    enveloped['recipientInfos'] = univ.SetOf(
        componentType=_OtherRecipientInfo()
    )
    enveloped['recipientInfos'].append(ori)
    enveloped['encryptedContentInfo'] = _EncryptedContentInfo()
    enveloped['encryptedContentInfo']['contentType'] = univ.ObjectIdentifier(
        ID_DATA
    )
    enveloped['encryptedContentInfo']['contentEncryptionAlgorithm'] = _alg_id(
        ID_AES256_GCM, der_encoder.encode(gcm_params))
    enveloped['encryptedContentInfo']['encryptedContent'] = ciphertext

    enveloped_content_info = _ContentInfo()
    enveloped_content_info['contentType'] = univ.ObjectIdentifier(
        ID_ENVELOPED_DATA
    )
    enveloped_content_info['content'] = der_encoder.encode(enveloped)
    enveloped_der = der_encoder.encode(enveloped_content_info)

    # --- outer SignedData ---
    signature = _sign_data(signing_private_key, enveloped_der)

    signer_info = _SignerInfo()
    signer_info['version'] = 1
    signer_info['sid'] = _IssuerAndSerialNumber()
    signer_info['sid']['issuer'] = signing_cert.issuer.public_bytes()
    signer_info['sid']['serialNumber'] = signing_cert.serial_number
    # Dispatch by the embedded certificate's key type at verify time
    # rather than by parsing these OIDs, so their exact values are
    # descriptive only.
    signer_info['digestAlgorithm'] = _alg_id(ID_SHA256)
    signer_info['signatureAlgorithm'] = _alg_id(
        signing_cert.signature_algorithm_oid.dotted_string)
    signer_info['signature'] = signature

    signed = _SignedData()
    signed['version'] = 1
    signed['digestAlgorithms'] = univ.SetOf(
        componentType=_AlgorithmIdentifier()
    )
    signed['digestAlgorithms'].append(_alg_id(ID_SHA256))
    signed['encapContentInfo'] = _EncapsulatedContentInfo()
    signed['encapContentInfo']['eContentType'] = univ.ObjectIdentifier(
        ID_ENVELOPED_DATA)
    signed['encapContentInfo']['eContent'] = enveloped_der
    signed['certificates'] = _CertificateSet()
    signed['certificates'].append(
        univ.Any(signing_cert.public_bytes(Encoding.DER)))
    signed['signerInfos'] = univ.SetOf(componentType=_SignerInfo())
    signed['signerInfos'].append(signer_info)

    signed_content_info = _ContentInfo()
    signed_content_info['contentType'] = univ.ObjectIdentifier(ID_SIGNED_DATA)
    signed_content_info['content'] = der_encoder.encode(signed)
    return der_encoder.encode(signed_content_info)


def open_and_verify(der, recipient_kem_private_key):
    """Verify and decrypt a message produced by seal().

    The embedded signing certificate is trusted on first use (TOFU) --
    there is no independent verification that it belongs to the expected
    sender, only that the signature over the sealed content is valid and
    the content has not been tampered with.

    :returns: (plaintext, signing_cert)
    :raises UnsealError: if signature verification or decryption fails.
    """
    try:
        signed_content_info, rest = der_decoder.decode(
            der, asn1Spec=_ContentInfo())
        if rest:
            raise UnsealError("trailing bytes after outer ContentInfo")
        if str(signed_content_info['contentType']) != ID_SIGNED_DATA:
            raise UnsealError("outer ContentInfo is not SignedData")
        signed, rest = der_decoder.decode(
            bytes(signed_content_info['content']), asn1Spec=_SignedData())
        if rest:
            raise UnsealError("trailing bytes after SignedData")

        cert_der = bytes(signed['certificates'][0])
        signing_cert = x509.load_der_x509_certificate(cert_der)

        enveloped_der = bytes(signed['encapContentInfo']['eContent'])
        signer_info = signed['signerInfos'][0]
        signature = bytes(signer_info['signature'])

        _verify_signature(
            signing_cert.public_key(), signature, enveloped_der)

        enveloped_content_info, rest = der_decoder.decode(
            enveloped_der, asn1Spec=_ContentInfo())
        if rest:
            raise UnsealError("trailing bytes after inner ContentInfo")
        if str(enveloped_content_info['contentType']) != ID_ENVELOPED_DATA:
            raise UnsealError("inner ContentInfo is not EnvelopedData")
        enveloped, rest = der_decoder.decode(
            bytes(enveloped_content_info['content']), asn1Spec=_EnvelopedData())
        if rest:
            raise UnsealError("trailing bytes after EnvelopedData")

        ori = enveloped['recipientInfos'][0]
        if str(ori['oriType']) != ID_ORI_KEM:
            raise UnsealError("unsupported RecipientInfo type: not KEM")
        kem_ri, rest = der_decoder.decode(
            bytes(ori['oriValue']), asn1Spec=_KEMRecipientInfo())
        if rest:
            raise UnsealError("trailing bytes after KEMRecipientInfo")

        kemct = bytes(kem_ri['kemct'])
        encrypted_key = bytes(kem_ri['encryptedKey'])

        shared_secret = recipient_kem_private_key.decapsulate(kemct)
        kek = HKDF(
            algorithm=hashes.SHA256(), length=KEY_LEN, salt=None,
            info=KEK_INFO,
        ).derive(shared_secret)
        cek = aes_key_unwrap(kek, encrypted_key)

        eci = enveloped['encryptedContentInfo']
        params_der = bytes(eci['contentEncryptionAlgorithm']['parameters'])
        gcm_params, rest = der_decoder.decode(
            params_der, asn1Spec=_GCMParameters())
        nonce = bytes(gcm_params['aes-nonce'])
        ciphertext = bytes(eci['encryptedContent'])

        plaintext = AESGCM(cek).decrypt(nonce, ciphertext, None)
    except UnsealError:
        raise
    except Exception as e:
        raise UnsealError("failed to open sealed CMS message: %s" % e)

    return plaintext, signing_cert
