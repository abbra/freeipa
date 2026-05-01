# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
X.509 Certificate Utilities for DN Conversion

This module provides helper functions to convert between synta certificate
objects and IPA's DN representation, eliminating code duplication across
ipathinca modules.
"""

import logging
from typing import List, Tuple

import synta
import synta.ext
import synta.oids
import synta.oids.attr as _name_oids

from ipapython.dn import DN

logger = logging.getLogger(__name__)

# Map synta OID strings → short DN attribute names
OID_TO_SHORTNAME = {
    str(_name_oids.COMMON_NAME): "CN",
    str(_name_oids.ORGANIZATION): "O",
    str(_name_oids.ORG_UNIT): "OU",
    str(_name_oids.COUNTRY): "C",
    str(_name_oids.LOCALITY): "L",
    str(_name_oids.STATE): "ST",
    str(_name_oids.EMAIL_ADDRESS): "emailAddress",
    str(_name_oids.STREET): "street",
    str(_name_oids.DOMAIN_COMPONENT): "DC",
    str(_name_oids.USER_ID): "UID",
    str(_name_oids.SERIAL_NUMBER): "serialNumber",
    str(_name_oids.SURNAME): "SN",
    str(_name_oids.GIVEN_NAME): "givenName",
    str(_name_oids.TITLE): "title",
    str(_name_oids.GENERATION_QUALIFIER): "generationQualifier",
    str(_name_oids.DN_QUALIFIER): "dnQualifier",
    str(_name_oids.PSEUDONYM): "pseudonym",
}

# Reverse mapping: short name → OID dotted string
SHORTNAME_TO_OID = {
    "CN": str(_name_oids.COMMON_NAME),
    "O": str(_name_oids.ORGANIZATION),
    "OU": str(_name_oids.ORG_UNIT),
    "C": str(_name_oids.COUNTRY),
    "L": str(_name_oids.LOCALITY),
    "ST": str(_name_oids.STATE),
    "emailAddress": str(_name_oids.EMAIL_ADDRESS),
    "EMAILADDRESS": str(_name_oids.EMAIL_ADDRESS),
    "email": str(_name_oids.EMAIL_ADDRESS),
    "street": str(_name_oids.STREET),
    "DC": str(_name_oids.DOMAIN_COMPONENT),
    "UID": str(_name_oids.USER_ID),
    "serialNumber": str(_name_oids.SERIAL_NUMBER),
    "SN": str(_name_oids.SURNAME),
    "givenName": str(_name_oids.GIVEN_NAME),
    "title": str(_name_oids.TITLE),
    "generationQualifier": str(_name_oids.GENERATION_QUALIFIER),
    "dnQualifier": str(_name_oids.DN_QUALIFIER),
    "pseudonym": str(_name_oids.PSEUDONYM),
}

# Standard DN component ordering (most-specific to least-specific)
_STANDARD_DN_ORDER = ["CN", "OU", "O", "L", "ST", "C", "DC", "UID"]


def cert_name_to_ipa_dn(name_der: bytes, reverse: bool = True) -> DN:
    """
    Convert a DER-encoded X.509 Name to an IPA DN.

    Args:
        name_der: DER-encoded subject/issuer name bytes
                  (e.g. cert.subject_raw_der)
        reverse: If True (default), reverse the RDN order so the result
                 is in most-specific-first (RFC 4514 display) order.

    Returns:
        IPA DN object
    """
    attrs = synta.parse_name_attrs(name_der)
    components = []
    for oid_str, value in attrs:
        attr_name = OID_TO_SHORTNAME.get(oid_str, oid_str)
        components.append((attr_name, value))
    if reverse:
        components = list(reversed(components))
    return DN(*components)


def ipa_dn_to_name_der(dn_string: str) -> bytes:
    """
    Convert an IPA DN string to a DER-encoded X.509 Name.

    Args:
        dn_string: DN string in IPA/RFC 4514 format (e.g. "CN=Test,O=EXAMPLE")

    Returns:
        DER-encoded name bytes suitable for synta CertificateBuilder/CsrBuilder
    """
    ipa_dn = DN(dn_string)
    nb = synta.NameBuilder()
    # IPA DN iterates most-specific-first (CN, then O).
    # synta.NameBuilder appends in call order and encodes in that order,
    # so reverse the IPA DN to get least-specific-first (O, then CN) which
    # produces the correct RFC 5280 encoding.
    for rdn in reversed(list(ipa_dn)):
        attr_upper = rdn.attr.upper()
        oid_str = SHORTNAME_TO_OID.get(rdn.attr) or SHORTNAME_TO_OID.get(
            attr_upper
        )
        if oid_str:
            nb = nb.add_attr(oid_str, rdn.value)
        else:
            logger.warning("Unknown DN attribute type: %s, skipping", rdn.attr)
    return nb.build()


# Keep the old name as an alias so callers can be updated incrementally.
ipa_dn_to_x509_name = ipa_dn_to_name_der


def get_subject_dn_str(cert) -> str:
    """
    Return the certificate's subject DN as an IPA DN string.

    Args:
        cert: synta.Certificate or ipalib.x509.IPACertificate object
    """
    name_der = (
        cert.subject_raw_der
        if hasattr(cert, 'subject_raw_der')
        else cert._synta_cert.subject_raw_der
    )
    return str(cert_name_to_ipa_dn(name_der))


def get_issuer_dn_str(cert) -> str:
    """Return the certificate's issuer DN as an IPA DN string."""
    name_der = (
        cert.issuer_raw_der
        if hasattr(cert, 'issuer_raw_der')
        else cert._synta_cert.issuer_raw_der
    )
    return str(cert_name_to_ipa_dn(name_der))


def get_subject_dn(cert) -> DN:
    """Return the certificate's subject as an IPA DN object."""
    name_der = (
        cert.subject_raw_der
        if hasattr(cert, 'subject_raw_der')
        else cert._synta_cert.subject_raw_der
    )
    return cert_name_to_ipa_dn(name_der)


def get_issuer_dn(cert) -> DN:
    """Return the certificate's issuer as an IPA DN object."""
    name_der = (
        cert.issuer_raw_der
        if hasattr(cert, 'issuer_raw_der')
        else cert._synta_cert.issuer_raw_der
    )
    return cert_name_to_ipa_dn(name_der)


def get_dn_components(name_der: bytes) -> List[Tuple[str, str]]:
    """
    Extract DN components as (attribute_name, value) tuples,
    most-specific-first.

    Args:
        name_der: DER-encoded name bytes

    Returns:
        List of (attr_name, value) tuples
    """
    attrs = synta.parse_name_attrs(name_der)
    components = []
    for oid_str, value in reversed(attrs):
        attr_name = OID_TO_SHORTNAME.get(oid_str, oid_str)
        components.append((attr_name, value))
    return components


def build_name_der(attributes, reverse: bool = False) -> bytes:
    """
    Build a DER-encoded X.509 Name from a dict or list of (attr, value) tuples.

    Args:
        attributes: dict {'CN': 'Test', 'O': 'Example'} or
                    list of tuples [('CN', 'Test'), ('O', 'Example')]
        reverse: If False (default), attributes are in natural/display order
                 (most-specific-first: CN, O, C) and will be reversed for X.509
                 internal encoding. If True, already in reverse order.

    Returns:
        DER-encoded name bytes
    """
    if isinstance(attributes, dict):
        attr_list = list(attributes.items())
    else:
        attr_list = list(attributes)

    # Order components consistently: most-specific-first
    ordered_attrs = []
    for standard_name in _STANDARD_DN_ORDER:
        for attr_name, attr_value in attr_list:
            if attr_name.upper() == standard_name.upper():
                ordered_attrs.append((attr_name, attr_value))
                break
    for attr_name, attr_value in attr_list:
        if attr_name.upper() not in _STANDARD_DN_ORDER:
            ordered_attrs.append((attr_name, attr_value))

    # synta.NameBuilder encodes in call order; to produce the correct
    # least-specific-first DER encoding, pass attrs in reverse display order
    if reverse:
        to_encode = list(reversed(ordered_attrs))
    else:
        to_encode = ordered_attrs

    nb = synta.NameBuilder()
    for attr_name, attr_value in to_encode:
        oid_str = SHORTNAME_TO_OID.get(attr_name) or SHORTNAME_TO_OID.get(
            attr_name.upper()
        )
        if oid_str:
            nb = nb.add_attr(oid_str, attr_value)
        else:
            logger.warning("Unknown DN attribute: %s, skipping", attr_name)
    return nb.build()


# Keep old name as alias.
build_x509_name = build_name_der


def load_certificate_from_ldap_data(cert_data) -> synta.Certificate:
    """
    Load a certificate from LDAP entry data (handles multiple formats).

    Args:
        cert_data: Certificate data from LDAP (bytes, str, or synta.Certificate)

    Returns:
        synta.Certificate object

    Raises:
        ValueError: If the certificate data cannot be decoded
    """
    if isinstance(cert_data, synta.Certificate):
        return cert_data
    # Accept IPACertificate (has _synta_cert attribute)
    if hasattr(cert_data, '_synta_cert'):
        return cert_data._synta_cert
    # Accept objects that expose public_bytes (legacy IPACertificate)
    if hasattr(cert_data, 'public_bytes'):
        from ipalib.x509 import IPACertificate
        if isinstance(cert_data, IPACertificate):
            return cert_data._synta_cert
        cert_bytes = cert_data.public_bytes('DER')
        return synta.Certificate.from_der(cert_bytes)

    if isinstance(cert_data, str):
        cert_bytes = cert_data.encode('latin-1')
    else:
        cert_bytes = cert_data

    try:
        return synta.Certificate.from_der(cert_bytes)
    except Exception as der_error:
        logger.debug(
            "DER certificate loading failed, trying PEM: %s", der_error
        )
        try:
            return synta.Certificate.from_pem(cert_bytes)
        except Exception as e:
            raise ValueError(
                f"Could not load certificate from LDAP data: {e}"
            ) from e


def decode_ldap_attribute(value, expected_type: type = str):
    """Decode LDAP attribute value to the expected Python type."""
    if value is None:
        return None
    if isinstance(value, bytes) and expected_type == str:
        return value.decode('utf-8')
    if isinstance(value, (str, bytes)) and expected_type == int:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        return int(value)
    if isinstance(value, (str, bytes)) and expected_type == bool:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        return value.upper() in ('TRUE', '1', 'YES')
    return value


def parse_signature_algorithm(algorithm_string: str) -> str:
    """
    Parse a Dogtag-style algorithm string to a synta hash algorithm name.

    Args:
        algorithm_string: e.g. "SHA256withRSA", "SHA384withEC", "ML-DSA-65"

    Returns:
        Hash algorithm name string suitable for synta (e.g. "sha256"),
        or "" for algorithms that do not use a pre-hash (ML-DSA).
    """
    alg_upper = algorithm_string.upper()
    if 'ML-DSA' in alg_upper or 'MLDSA' in alg_upper:
        return ""  # ML-DSA: no pre-hash; synta ignores algorithm
    if 'SHA512' in alg_upper:
        return 'sha512'
    if 'SHA384' in alg_upper:
        return 'sha384'
    if 'SHA256' in alg_upper:
        return 'sha256'
    if 'SHA1' in alg_upper:
        return 'sha1'
    if 'MD5' in alg_upper or 'MD2' in alg_upper:
        return 'md5'
    raise ValueError(f"Unknown signature algorithm: {algorithm_string}")


def get_default_algorithm_for_key(public_key) -> str:
    """
    Infer the appropriate Dogtag-style algorithm string for a synta PublicKey.

    Args:
        public_key: synta.PublicKey object

    Returns:
        Dogtag-style algorithm string (e.g. "SHA256withRSA")
    """
    key_type = getattr(public_key, 'key_type', 'rsa')
    if key_type == 'rsa':
        return 'SHA256withRSA'
    if key_type == 'ec':
        return 'SHA256withEC'
    if key_type in ('mldsa', 'ml-dsa'):
        # ML-DSA level depends on key_size / parameter set
        size = getattr(public_key, 'key_size', 65)
        return f'ML-DSA-{size}'
    logger.warning(
        "Unknown key type %s, defaulting to SHA256withRSA", key_type
    )
    return 'SHA256withRSA'


def get_certificate_signature_algorithm(certificate) -> str:
    """
    Return the Dogtag-style algorithm string that was used to sign a cert.

    Args:
        certificate: synta.Certificate or ipalib.x509.IPACertificate

    Returns:
        Dogtag-style algorithm string (e.g. "SHA256withRSA")
    """
    synta_cert = (
        certificate._synta_cert
        if hasattr(certificate, '_synta_cert')
        else certificate
    )
    alg_name = synta_cert.signature_hash_algorithm_name
    sig_oid = str(synta_cert.signature_algorithm_oid)

    # ML-DSA OIDs: 2.16.840.1.101.3.4.3.17/18/19 → ML-DSA-44/65/87
    _MLDSA_OIDS = {
        '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
        '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
        '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
    }
    if sig_oid in _MLDSA_OIDS:
        return _MLDSA_OIDS[sig_oid]

    if alg_name is None:
        alg_name = 'sha256'

    # Determine key type from the public key
    try:
        spki_der = synta_cert.subject_public_key_info_der
        pk = synta.PublicKey.from_der(spki_der)
        key_type = pk.key_type
    except Exception:
        key_type = 'rsa'

    hash_str = alg_name.upper().replace('-', '')
    if key_type == 'rsa':
        return f'{hash_str}withRSA'
    if key_type == 'ec':
        return f'{hash_str}withEC'
    logger.warning("Unknown key type %s, using RSA", key_type)
    return f'{hash_str}withRSA'


# ---------------------------------------------------------------------------
# Extension builder helpers
# Each returns (oid_str, der_bytes) so callers can do:
#   oid, ext_der = get_ca_key_usage_extension()
#   builder = builder.add_extension(oid, True, ext_der)
# ---------------------------------------------------------------------------

def get_ca_key_usage_extension() -> Tuple[str, bytes]:
    """Return (oid, DER) for CA certificate KeyUsage."""
    bits = (
        synta.ext.KU_DIGITAL_SIGNATURE
        | synta.ext.KU_KEY_CERT_SIGN
        | synta.ext.KU_CRL_SIGN
    )
    return str(synta.oids.KEY_USAGE), synta.ext.key_usage(bits)


def get_service_key_usage_extension() -> Tuple[str, bytes]:
    """Return (oid, DER) for service/server certificate KeyUsage."""
    bits = synta.ext.KU_DIGITAL_SIGNATURE | synta.ext.KU_KEY_ENCIPHERMENT
    return str(synta.oids.KEY_USAGE), synta.ext.key_usage(bits)


def get_ocsp_key_usage_extension() -> Tuple[str, bytes]:
    """Return (oid, DER) for OCSP signing certificate KeyUsage.

    RFC 5280 §4.2.1.3 and RFC 6960 §4.2.2.2 allow only digitalSignature for
    OCSP responder certs.  keyEncipherment and dataEncipherment must not be set.
    """
    bits = synta.ext.KU_DIGITAL_SIGNATURE
    return str(synta.oids.KEY_USAGE), synta.ext.key_usage(bits)


def get_subsystem_key_usage_extension() -> Tuple[str, bytes]:
    """Return (oid, DER) for CA subsystem certificate KeyUsage."""
    bits = synta.ext.KU_DIGITAL_SIGNATURE | synta.ext.KU_KEY_ENCIPHERMENT
    return str(synta.oids.KEY_USAGE), synta.ext.key_usage(bits)


def get_audit_key_usage_extension() -> Tuple[str, bytes]:
    """Return (oid, DER) for audit signing certificate KeyUsage."""
    bits = synta.ext.KU_DIGITAL_SIGNATURE | synta.ext.KU_NON_REPUDIATION
    return str(synta.oids.KEY_USAGE), synta.ext.key_usage(bits)


def get_server_extended_key_usage() -> Tuple[str, bytes]:
    """Return (oid, DER) for server/service certificate ExtendedKeyUsage."""
    der = (
        synta.ext.ExtendedKeyUsageBuilder()
        .server_auth()
        .client_auth()
        .build()
    )
    return str(synta.oids.EXTENDED_KEY_USAGE), der


def get_ocsp_extended_key_usage() -> Tuple[str, bytes]:
    """Return (oid, DER) for OCSP signing ExtendedKeyUsage."""
    der = synta.ext.ExtendedKeyUsageBuilder().ocsp_signing().build()
    return str(synta.oids.EXTENDED_KEY_USAGE), der


def get_subsystem_extended_key_usage() -> Tuple[str, bytes]:
    """Return (oid, DER) for CA subsystem ExtendedKeyUsage."""
    der = (
        synta.ext.ExtendedKeyUsageBuilder()
        .client_auth()
        .server_auth()
        .build()
    )
    return str(synta.oids.EXTENDED_KEY_USAGE), der


def get_pkinit_extended_key_usage() -> Tuple[str, bytes]:
    """Return (oid, DER) for PKINIT KDC ExtendedKeyUsage."""
    der = (
        synta.ext.ExtendedKeyUsageBuilder()
        .add_oid([1, 3, 6, 1, 5, 2, 3, 5])  # id-pkinit-KPKdc
        .build()
    )
    return str(synta.oids.EXTENDED_KEY_USAGE), der
