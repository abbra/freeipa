# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Tests for X.509 utility functions

Tests DN conversion, OID mappings, signature algorithm parsing,
key usage extensions, and build_name_der / build_x509_name.
"""

import pytest
import synta
import synta.ext
import synta.oids
import synta.oids.attr as _attr_oids

from ipathinca.x509_utils import (
    OID_TO_SHORTNAME,
    SHORTNAME_TO_OID,
    cert_name_to_ipa_dn,
    ipa_dn_to_x509_name,
    build_x509_name,
    get_dn_components,
    decode_ldap_attribute,
    parse_signature_algorithm,
    get_default_algorithm_for_key,
    get_ca_key_usage_extension,
    get_service_key_usage_extension,
    get_ocsp_key_usage_extension,
    get_subsystem_key_usage_extension,
    get_audit_key_usage_extension,
    get_server_extended_key_usage,
    get_ocsp_extended_key_usage,
    get_subsystem_extended_key_usage,
    get_pkinit_extended_key_usage,
)


# ======================================================================
# OID mappings
# ======================================================================


class TestOIDMappings:
    """Test OID_TO_SHORTNAME and SHORTNAME_TO_OID."""

    def test_common_oids_present(self):
        """Common OIDs are mapped."""
        assert str(_attr_oids.COMMON_NAME) in OID_TO_SHORTNAME
        assert str(_attr_oids.ORGANIZATION) in OID_TO_SHORTNAME
        assert str(_attr_oids.COUNTRY) in OID_TO_SHORTNAME
        assert str(_attr_oids.DOMAIN_COMPONENT) in OID_TO_SHORTNAME

    def test_shortname_to_oid_cn(self):
        """CN maps to COMMON_NAME OID dotted string."""
        assert SHORTNAME_TO_OID["CN"] == str(_attr_oids.COMMON_NAME)

    def test_shortname_to_oid_email_variants(self):
        """emailAddress has case variants."""
        assert SHORTNAME_TO_OID["emailAddress"] == str(_attr_oids.EMAIL_ADDRESS)
        assert SHORTNAME_TO_OID["EMAILADDRESS"] == str(_attr_oids.EMAIL_ADDRESS)
        assert SHORTNAME_TO_OID["email"] == str(_attr_oids.EMAIL_ADDRESS)

    def test_bidirectional_consistency(self):
        """Every OID_TO_SHORTNAME entry has a reverse mapping."""
        for oid, shortname in OID_TO_SHORTNAME.items():
            assert (
                shortname in SHORTNAME_TO_OID
            ), f"Missing reverse mapping for {shortname}"
            assert SHORTNAME_TO_OID[shortname] == oid


# ======================================================================
# DN conversion
# ======================================================================


class TestDNConversion:
    """Test DN conversion functions."""

    def _make_name_der(self, *attrs):
        """Build DER from (oid_const, value) pairs in the given order."""
        nb = synta.NameBuilder()
        for oid_const, value in attrs:
            nb = nb.add_attr(str(oid_const), value)
        return nb.build()

    def test_cert_name_to_ipa_dn_simple(self):
        """Convert DER-encoded Name to IPA DN."""
        name_der = self._make_name_der(
            (_attr_oids.ORGANIZATION, "EXAMPLE.COM"),
            (_attr_oids.COMMON_NAME, "Test User"),
        )
        dn = cert_name_to_ipa_dn(name_der)
        dn_str = str(dn)
        assert "CN=Test User" in dn_str
        assert "O=EXAMPLE.COM" in dn_str

    def test_cert_name_to_ipa_dn_reverse_default(self):
        """Default reverse=True reverses order for IPA format."""
        name_der = self._make_name_der(
            (_attr_oids.ORGANIZATION, "EXAMPLE.COM"),
            (_attr_oids.COMMON_NAME, "Test"),
        )
        dn = cert_name_to_ipa_dn(name_der, reverse=True)
        dn_str = str(dn)
        # CN should come first in IPA DN format
        assert dn_str.startswith("CN=")

    def test_ipa_dn_to_x509_name(self):
        """Convert IPA DN string to DER-encoded Name."""
        der = ipa_dn_to_x509_name("CN=Test,O=EXAMPLE.COM")
        attrs = dict(synta.parse_name_attrs(der))
        assert attrs.get(str(_attr_oids.COMMON_NAME)) == "Test"
        assert attrs.get(str(_attr_oids.ORGANIZATION)) == "EXAMPLE.COM"

    def test_get_dn_components(self):
        """get_dn_components returns correct tuples, most-specific-first."""
        # Encode with O first (least-specific) then CN (most-specific)
        name_der = self._make_name_der(
            (_attr_oids.ORGANIZATION, "EXAMPLE.COM"),
            (_attr_oids.COMMON_NAME, "Test"),
        )
        components = get_dn_components(name_der)
        # Most-specific-first after reversal
        assert components[0] == ("CN", "Test")
        assert components[1] == ("O", "EXAMPLE.COM")


# ======================================================================
# build_x509_name / build_name_der
# ======================================================================


class TestBuildX509Name:
    """Test build_x509_name utility (returns DER bytes)."""

    def test_from_list_of_tuples(self):
        """Build from list of tuples."""
        der = build_x509_name([("CN", "Test"), ("O", "Example")])
        attrs = dict(synta.parse_name_attrs(der))
        assert attrs.get(str(_attr_oids.COMMON_NAME)) == "Test"
        assert attrs.get(str(_attr_oids.ORGANIZATION)) == "Example"

    def test_from_dict(self):
        """Build from dict."""
        der = build_x509_name({"CN": "Test", "O": "Example"})
        attrs = dict(synta.parse_name_attrs(der))
        assert attrs.get(str(_attr_oids.COMMON_NAME)) == "Test"
        assert attrs.get(str(_attr_oids.ORGANIZATION)) == "Example"

    def test_standard_dn_ordering_applied(self):
        """All attributes survive reordering by STANDARD_DN_ORDER."""
        der = build_x509_name(
            [
                ("O", "Org"),
                ("C", "US"),
                ("CN", "Test"),
            ]
        )
        attrs = dict(synta.parse_name_attrs(der))
        assert attrs.get(str(_attr_oids.COMMON_NAME)) == "Test"
        assert attrs.get(str(_attr_oids.ORGANIZATION)) == "Org"
        assert attrs.get(str(_attr_oids.COUNTRY)) == "US"

    def test_reverse_gives_display_order(self):
        """reverse=True produces CN-first display order."""
        der = build_x509_name(
            [("O", "Example"), ("CN", "Test")], reverse=True
        )
        components = get_dn_components(der)
        assert components[0][0] == "CN"


# ======================================================================
# decode_ldap_attribute
# ======================================================================


class TestDecodeLdapAttribute:
    """Test LDAP attribute decoding."""

    def test_bytes_to_str(self):
        """Decode bytes to str."""
        assert decode_ldap_attribute(b"hello") == "hello"

    def test_str_passthrough(self):
        """str passes through unchanged."""
        assert decode_ldap_attribute("hello") == "hello"

    def test_bytes_to_int(self):
        """Decode bytes to int."""
        assert decode_ldap_attribute(b"42", int) == 42

    def test_str_to_int(self):
        """Decode str to int."""
        assert decode_ldap_attribute("42", int) == 42

    def test_bytes_to_bool_true(self):
        """Decode bytes to bool (TRUE)."""
        assert decode_ldap_attribute(b"TRUE", bool) is True
        assert decode_ldap_attribute(b"1", bool) is True
        assert decode_ldap_attribute(b"YES", bool) is True

    def test_bytes_to_bool_false(self):
        """Decode bytes to bool (FALSE)."""
        assert decode_ldap_attribute(b"FALSE", bool) is False
        assert decode_ldap_attribute(b"no", bool) is False

    def test_none(self):
        """None returns None."""
        assert decode_ldap_attribute(None) is None


# ======================================================================
# Signature algorithm parsing
# ======================================================================


class TestParseSignatureAlgorithm:
    """Test parse_signature_algorithm."""

    def test_sha256_with_rsa(self):
        """SHA256withRSA returns 'sha256'."""
        assert parse_signature_algorithm("SHA256withRSA") == 'sha256'

    def test_sha384_with_rsa(self):
        """SHA384withRSA returns 'sha384'."""
        assert parse_signature_algorithm("SHA384withRSA") == 'sha384'

    def test_sha512_with_rsa(self):
        """SHA512withRSA returns 'sha512'."""
        assert parse_signature_algorithm("SHA512withRSA") == 'sha512'

    def test_sha1_with_rsa(self):
        """SHA1withRSA returns 'sha1'."""
        assert parse_signature_algorithm("SHA1withRSA") == 'sha1'

    def test_sha256_with_ec(self):
        """SHA256withEC returns 'sha256'."""
        assert parse_signature_algorithm("SHA256withEC") == 'sha256'

    def test_case_insensitive(self):
        """Algorithm parsing is case-insensitive."""
        assert parse_signature_algorithm("sha256withRSA") == 'sha256'

    def test_mldsa_returns_none(self):
        """ML-DSA returns None (no pre-hash)."""
        assert parse_signature_algorithm("ML-DSA-65") is None

    def test_unknown_raises(self):
        """Unknown algorithm raises ValueError."""
        with pytest.raises(ValueError):
            parse_signature_algorithm("UnknownAlgorithm")


# ======================================================================
# get_default_algorithm_for_key
# ======================================================================


class TestDefaultAlgorithmForKey:
    """Test get_default_algorithm_for_key."""

    def test_rsa_key(self):
        """RSA key returns SHA256withRSA."""
        key = synta.PrivateKey.generate_rsa(2048)
        assert get_default_algorithm_for_key(key.public_key) == "SHA256withRSA"

    def test_ec_key(self):
        """EC key returns SHA256withEC."""
        key = synta.PrivateKey.generate_ec('P-256')
        assert get_default_algorithm_for_key(key.public_key) == "SHA256withEC"


# ======================================================================
# KeyUsage extensions
# ======================================================================


class TestKeyUsageExtensions:
    """Test KeyUsage extension builders return (oid_str, der) tuples."""

    def test_ca_key_usage(self):
        """CA KeyUsage allows cert signing, CRL signing, digital sig."""
        oid_str, der = get_ca_key_usage_extension()
        assert oid_str == str(synta.oids.KEY_USAGE)
        expected = synta.ext.key_usage(
            synta.ext.KU_DIGITAL_SIGNATURE
            | synta.ext.KU_KEY_CERT_SIGN
            | synta.ext.KU_CRL_SIGN
        )
        assert der == expected

    def test_service_key_usage(self):
        """Service KeyUsage allows digital sig and key encipherment."""
        oid_str, der = get_service_key_usage_extension()
        assert oid_str == str(synta.oids.KEY_USAGE)
        expected = synta.ext.key_usage(
            synta.ext.KU_DIGITAL_SIGNATURE | synta.ext.KU_KEY_ENCIPHERMENT
        )
        assert der == expected

    def test_ocsp_key_usage(self):
        """OCSP KeyUsage allows digital sig, key and data encipherment."""
        oid_str, der = get_ocsp_key_usage_extension()
        assert oid_str == str(synta.oids.KEY_USAGE)
        expected = synta.ext.key_usage(
            synta.ext.KU_DIGITAL_SIGNATURE
            | synta.ext.KU_KEY_ENCIPHERMENT
            | synta.ext.KU_DATA_ENCIPHERMENT
        )
        assert der == expected

    def test_audit_key_usage(self):
        """Audit KeyUsage includes non-repudiation (content_commitment)."""
        oid_str, der = get_audit_key_usage_extension()
        assert oid_str == str(synta.oids.KEY_USAGE)
        expected = synta.ext.key_usage(
            synta.ext.KU_DIGITAL_SIGNATURE | synta.ext.KU_NON_REPUDIATION
        )
        assert der == expected

    def test_subsystem_key_usage(self):
        """Subsystem KeyUsage allows digital sig and key encipherment."""
        oid_str, der = get_subsystem_key_usage_extension()
        assert oid_str == str(synta.oids.KEY_USAGE)
        expected = synta.ext.key_usage(
            synta.ext.KU_DIGITAL_SIGNATURE | synta.ext.KU_KEY_ENCIPHERMENT
        )
        assert der == expected


# ======================================================================
# ExtendedKeyUsage extensions
# ======================================================================


class TestExtendedKeyUsageExtensions:
    """Test ExtendedKeyUsage extension builders return (oid_str, der) tuples."""

    def test_server_eku(self):
        """Server EKU includes server and client auth."""
        oid_str, der = get_server_extended_key_usage()
        assert oid_str == str(synta.oids.EXTENDED_KEY_USAGE)
        expected = (
            synta.ext.ExtendedKeyUsageBuilder()
            .server_auth()
            .client_auth()
            .build()
        )
        assert der == expected

    def test_ocsp_eku(self):
        """OCSP EKU includes OCSP signing."""
        oid_str, der = get_ocsp_extended_key_usage()
        assert oid_str == str(synta.oids.EXTENDED_KEY_USAGE)
        expected = synta.ext.ExtendedKeyUsageBuilder().ocsp_signing().build()
        assert der == expected

    def test_subsystem_eku(self):
        """Subsystem EKU includes client and server auth."""
        oid_str, der = get_subsystem_extended_key_usage()
        assert oid_str == str(synta.oids.EXTENDED_KEY_USAGE)
        expected = (
            synta.ext.ExtendedKeyUsageBuilder()
            .client_auth()
            .server_auth()
            .build()
        )
        assert der == expected

    def test_pkinit_eku(self):
        """PKINIT EKU includes KDC OID (1.3.6.1.5.2.3.5)."""
        oid_str, der = get_pkinit_extended_key_usage()
        assert oid_str == str(synta.oids.EXTENDED_KEY_USAGE)
        expected = (
            synta.ext.ExtendedKeyUsageBuilder()
            .add_oid([1, 3, 6, 1, 5, 2, 3, 5])
            .build()
        )
        assert der == expected
