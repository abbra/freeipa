# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.

"""ipa-otpd's client credential at the integrated IdP (ahdapa).

DARC (Device Authorization with Return Confirmation): ipa-otpd on each KDC
host is a confidential OAuth 2.0 client of ahdapa, ``ipa-otpd-<fqdn>``,
authenticated with ``private_key_jwt`` (RFC 7523). The key lives in a
PKCS#12 file readable only by root, which ``oidc_child`` loads; the public
key is registered inline in ahdapa's static clients file. Each KDC host has
its own client, so ahdapa can tell hosts apart for throttling and
revocation.
"""

from __future__ import absolute_import

import base64
import datetime
import json
import logging
import os
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from ipaplatform.paths import paths
from ipapython import ipautil

logger = logging.getLogger(__name__)

OTPD_CLIENT_PREFIX = 'ipa-otpd-'
# Long-lived: the certificate only carries the key for oidc_child, which
# derives the JWK (and its x5t#S256) from it; ahdapa trusts the registered
# public key, not the certificate.
CERT_VALIDITY_DAYS = 3650


def otpd_client_id(fqdn):
    """Per-KDC-host OAuth2 client_id of ipa-otpd at ahdapa.

    Must match AHDAPA_OTPD_CLIENT_PREFIX in daemons/ipa-otpd/oauth2.c.
    """
    return '{}{}'.format(OTPD_CLIENT_PREFIX, fqdn)


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _write_private(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _generate(fqdn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, otpd_client_id(fqdn))])
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False,
                          crl_sign=False, encipher_only=False,
                          decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    password = secrets.token_urlsafe(32)
    blob = pkcs12.serialize_key_and_certificates(
        otpd_client_id(fqdn).encode('utf-8'), key, cert, None,
        serialization.BestAvailableEncryption(password.encode('utf-8')))
    return blob, password


def _load(p12_path, password_path):
    with open(password_path, 'rb') as f:
        password = f.read().strip()
    with open(p12_path, 'rb') as f:
        key, _cert, _extra = pkcs12.load_key_and_certificates(
            f.read(), password)
    return key


def ensure_credential(fqdn):
    """Create the PKCS#12 key and its password once; return the public key.

    Idempotent: an existing credential is kept, so re-running install or
    upgrade does not invalidate the registration on other replicas' view.
    """
    os.makedirs(paths.IPA_OTPD_STATE_DIR, mode=0o700, exist_ok=True)
    os.chmod(paths.IPA_OTPD_STATE_DIR, 0o700)

    if (os.path.exists(paths.IPA_OTPD_AHDAPA_P12)
            and os.path.exists(paths.IPA_OTPD_AHDAPA_P12_PASSWORD)):
        try:
            return _load(paths.IPA_OTPD_AHDAPA_P12,
                         paths.IPA_OTPD_AHDAPA_P12_PASSWORD).public_key()
        except (ValueError, OSError) as e:
            logger.warning('Replacing unreadable ipa-otpd client key: %s', e)

    blob, password = _generate(fqdn)
    _write_private(paths.IPA_OTPD_AHDAPA_P12_PASSWORD,
                   password.encode('utf-8') + b'\n')
    _write_private(paths.IPA_OTPD_AHDAPA_P12, blob)
    logger.debug('Created ipa-otpd client key %s', paths.IPA_OTPD_AHDAPA_P12)
    return _load(paths.IPA_OTPD_AHDAPA_P12,
                 paths.IPA_OTPD_AHDAPA_P12_PASSWORD).public_key()


def public_jwk(public_key):
    """RFC 7517 JWK of an EC P-256 public key."""
    numbers = public_key.public_numbers()
    return {
        'kty': 'EC',
        'crv': 'P-256',
        'x': _b64url(numbers.x.to_bytes(32, 'big')),
        'y': _b64url(numbers.y.to_bytes(32, 'big')),
        'use': 'sig',
        'alg': 'ES256',
    }


def jwks_toml(public_key):
    """The client's JWKS as a TOML inline table for clients.toml."""
    jwk = public_jwk(public_key)
    fields = ', '.join(
        '{} = {}'.format(k, json.dumps(v)) for k, v in jwk.items())
    return '{{ keys = [ {{ {} }} ] }}'.format(fields)


def remove_credential():
    for path in (paths.IPA_OTPD_AHDAPA_P12,
                 paths.IPA_OTPD_AHDAPA_P12_PASSWORD):
        ipautil.remove_file(path)
