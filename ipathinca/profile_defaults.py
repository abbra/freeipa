"""
Certificate profile default plugins

This module implements default plugins that provide values for certificate
fields during issuance.
"""

import logging
from typing import Dict, Any
from datetime import datetime, timedelta, timezone

import synta
import synta.ext
import synta.oids

import ipathinca
from ipathinca import x509_utils
from ipathinca.profile import Default

logger = logging.getLogger(__name__)


class UserKeyDefault(Default):
    """userKeyDefaultImpl - uses public key from CSR"""

    def apply(self, builder, csr, context: dict):
        """Apply public key from CSR"""
        return builder.public_key_der(csr.subject_public_key_info_der)


class SubjectNameDefault(Default):
    """subjectNameDefaultImpl - sets certificate subject DN"""

    def __init__(self, name: str = None, **kwargs):
        """Initialize subject name default

        Args:
            name: Subject DN template with variables
        """
        self.name_template = name or ""

    def apply(self, builder, csr, context: dict):
        """Apply subject DN with variable substitution"""
        from ipathinca.profile import extract_request_variable

        dn_str = extract_request_variable(self.name_template, csr, context)

        # Convert to DER-encoded Name bytes
        subject_der = x509_utils.ipa_dn_to_x509_name(dn_str)

        # Store final subject DN in context for constraint validation
        # This allows SubjectNameConstraint to validate the FINAL subject
        # that will go into the certificate, not just the CSR subject
        context["final_subject_dn"] = dn_str
        context["final_subject_name"] = subject_der

        return builder.subject_name(subject_der)


class ValidityDefault(Default):
    """validityDefaultImpl - sets certificate validity period"""

    def __init__(self, range: str = None, startTime: str = None, **kwargs):
        """Initialize validity default

        Args:
            range: Validity period in days
            startTime: Offset from now in seconds (usually 0)
        """
        self.range_days = int(range) if range else 365
        self.start_time = int(startTime) if startTime else 0

    def apply(self, builder, csr, context: dict):
        """Apply validity period from profile configuration

        Sets notBefore and notAfter based on the profile's range parameter.
        Does NOT clamp — matching Dogtag's ValidityDefault.populate() which
        simply applies the configured range.  Enforcement is done by the
        ValidityConstraint in the validation step.
        """
        now = datetime.now(timezone.utc)
        not_before = now + timedelta(seconds=self.start_time)
        not_after = not_before + timedelta(days=self.range_days)

        # Store in context for constraint validation
        context["validity_days"] = self.range_days

        return (
            builder.not_valid_before_utc(not_before)
            .not_valid_after_utc(not_after)
        )


class SigningAlgDefault(Default):
    """signingAlgDefaultImpl - selects certificate signing algorithm"""

    def __init__(self, signingAlg: str = None, **kwargs):
        """Initialize signing algorithm default

        Args:
            signingAlg: Algorithm string or "-" for server decides
        """
        self.signing_alg = signingAlg or "-"

    def apply(self, builder, csr, context: dict):
        """Select signing algorithm"""
        if self.signing_alg == "-":
            # Server decides based on key type
            try:
                pub_key = synta.PublicKey.from_der(
                    csr.subject_public_key_info_der
                )
            except Exception:
                pub_key = None
            algorithm = self._infer_from_key(pub_key)
        else:
            algorithm = self.signing_alg

        # Store in context for signing and constraint validation
        context["signing_algorithm"] = algorithm

        return builder

    def _infer_from_key(self, public_key) -> str:
        """Infer appropriate algorithm from public key type

        Uses default_signing_algorithm from configuration (matching Dogtag's
        ca.signing.defaultSigningAlgorithm). Falls back to key-type inference
        if config not available.
        """
        # Read default from configuration (matches Dogtag CS.cfg behavior)
        try:
            default_alg = ipathinca.get_config_value(
                "ca", "default_signing_algorithm", default="SHA256withRSA"
            )
            logger.debug(
                "Using default signing algorithm from config: %s", default_alg
            )
            return default_alg
        except Exception as e:
            logger.warning(
                "Could not read default_signing_algorithm from config: %s", e
            )
            # Fallback: infer from key type
            key_type = getattr(public_key, 'key_type', 'rsa')
            if key_type == 'ec':
                return "SHA256withEC"
            else:
                return "SHA256withRSA"  # Safe default


class AuthorityKeyIdentifierExtDefault(Default):
    """authorityKeyIdentifierExtDefaultImpl - adds AKI extension"""

    def __init__(self, **kwargs):
        """Initialize AKI default"""

    def apply(self, builder, csr, context: dict):
        """Add Authority Key Identifier extension"""
        # Get CA certificate from context
        ca_cert = context.get("ca_certificate")
        if not ca_cert:
            return builder

        try:
            # Build AKI from CA's SPKI
            spki_der = ca_cert.subject_public_key_info_der
            aki_der = synta.ext.authority_key_identifier(spki_der)
            builder = builder.add_extension(
                str(synta.oids.AUTHORITY_KEY_IDENTIFIER), False, aki_der
            )
        except Exception as e:
            logger.warning("Failed to add AKI: %s", e)

        return builder


class SubjectKeyIdentifierExtDefault(Default):
    """subjectKeyIdentifierExtDefaultImpl - adds SKI extension"""

    def __init__(self, critical: str = None, **kwargs):
        """Initialize SKI default"""
        self.critical = (critical or "false").lower() == "true"

    def apply(self, builder, csr, context: dict):
        """Add Subject Key Identifier extension"""
        ski_der = synta.ext.subject_key_identifier(csr.subject_public_key_info_der)
        return builder.add_extension(
            str(synta.oids.SUBJECT_KEY_IDENTIFIER), self.critical, ski_der
        )


class KeyUsageExtDefault(Default):
    """keyUsageExtDefaultImpl - adds key usage extension"""

    def __init__(
        self,
        keyUsageCritical: str = None,
        keyUsageDigitalSignature: str = None,
        keyUsageNonRepudiation: str = None,
        keyUsageKeyEncipherment: str = None,
        keyUsageDataEncipherment: str = None,
        keyUsageKeyAgreement: str = None,
        keyUsageKeyCertSign: str = None,
        keyUsageCrlSign: str = None,
        keyUsageEncipherOnly: str = None,
        keyUsageDecipherOnly: str = None,
        **kwargs,
    ):
        """Initialize key usage default"""
        self.critical = (keyUsageCritical or "false").lower() == "true"
        self.digital_signature = (
            keyUsageDigitalSignature or "false"
        ).lower() == "true"
        self.content_commitment = (
            keyUsageNonRepudiation or "false"
        ).lower() == "true"
        self.key_encipherment = (
            keyUsageKeyEncipherment or "false"
        ).lower() == "true"
        self.data_encipherment = (
            keyUsageDataEncipherment or "false"
        ).lower() == "true"
        self.key_agreement = (
            keyUsageKeyAgreement or "false"
        ).lower() == "true"
        self.key_cert_sign = (keyUsageKeyCertSign or "false").lower() == "true"
        self.crl_sign = (keyUsageCrlSign or "false").lower() == "true"
        self.encipher_only = (
            keyUsageEncipherOnly or "false"
        ).lower() == "true"
        self.decipher_only = (
            keyUsageDecipherOnly or "false"
        ).lower() == "true"

    def apply(self, builder, csr, context: dict):
        """Add key usage extension"""
        bits = 0
        if self.digital_signature:
            bits |= synta.ext.KU_DIGITAL_SIGNATURE
        if self.content_commitment:
            bits |= synta.ext.KU_NON_REPUDIATION
        if self.key_encipherment:
            bits |= synta.ext.KU_KEY_ENCIPHERMENT
        if self.data_encipherment:
            bits |= synta.ext.KU_DATA_ENCIPHERMENT
        if self.key_agreement:
            bits |= synta.ext.KU_KEY_AGREEMENT
        if self.key_cert_sign:
            bits |= synta.ext.KU_KEY_CERT_SIGN
        if self.crl_sign:
            bits |= synta.ext.KU_CRL_SIGN
        if self.encipher_only:
            bits |= synta.ext.KU_ENCIPHER_ONLY
        if self.decipher_only:
            bits |= synta.ext.KU_DECIPHER_ONLY

        key_usage_der = synta.ext.key_usage(bits)

        # Store in context for constraint validation
        context["key_usage_bits"] = bits

        return builder.add_extension(
            str(synta.oids.KEY_USAGE), self.critical, key_usage_der
        )


class ExtendedKeyUsageExtDefault(Default):
    """extendedKeyUsageExtDefaultImpl - adds extended key usage extension"""

    def __init__(
        self,
        exKeyUsageCritical: str = None,
        exKeyUsageOIDs: str = None,
        **kwargs,
    ):
        """Initialize extended key usage default

        Args:
            exKeyUsageCritical: "true" or "false"
            exKeyUsageOIDs: Comma-separated list of OIDs
        """
        self.critical = (exKeyUsageCritical or "false").lower() == "true"
        self.oids = []

        if exKeyUsageOIDs:
            for oid_str in exKeyUsageOIDs.split(","):
                oid_str = oid_str.strip()
                # Map common OIDs
                oid = self._parse_oid(oid_str)
                if oid:
                    self.oids.append(oid)

    def _parse_oid(self, oid_str: str):
        """Validate and return OID string, or None if invalid"""
        # Validate it looks like a dotted OID
        parts = oid_str.split(".")
        if len(parts) < 2:
            logger.warning("Invalid OID: %s", oid_str)
            return None
        try:
            list(int(p) for p in parts)
            return oid_str
        except ValueError:
            logger.warning("Invalid OID: %s", oid_str)
            return None

    def apply(self, builder, csr, context: dict):
        """Add extended key usage extension"""
        if not self.oids:
            return builder

        eku_builder = synta.ext.ExtendedKeyUsageBuilder()
        for oid_str in self.oids:
            eku_builder = eku_builder.add_oid(
                [int(p) for p in oid_str.split(".")]
            )
        eku_der = eku_builder.build()

        # Store in context for constraint validation
        context["extended_key_usage_oids"] = self.oids

        return builder.add_extension(
            str(synta.oids.EXTENDED_KEY_USAGE), self.critical, eku_der
        )


class CRLDistributionPointsExtDefault(Default):
    """crlDistributionPointsExtDefaultImpl - adds CRL distribution points"""

    def __init__(
        self,
        crlDistPointsCritical: str = None,
        crlDistPointsNum: str = None,
        **kwargs,
    ):
        """Initialize CRL distribution points default"""
        self.critical = (crlDistPointsCritical or "false").lower() == "true"
        self.num_points = int(crlDistPointsNum) if crlDistPointsNum else 0
        self.points = []

        # Parse distribution points
        for i in range(self.num_points):
            enabled = (
                kwargs.get(f"crlDistPointsEnable_{i}", "false").lower()
                == "true"
            )
            if not enabled:
                continue

            point_name = kwargs.get(f"crlDistPointsPointName_{i}", "")
            point_type = kwargs.get(f"crlDistPointsPointType_{i}", "")
            issuer_name = kwargs.get(f"crlDistPointsIssuerName_{i}", "")
            issuer_type = kwargs.get(f"crlDistPointsIssuerType_{i}", "")

            if point_name:
                self.points.append(
                    {
                        "point_name": point_name,
                        "point_type": point_type,
                        "issuer_name": issuer_name,
                        "issuer_type": issuer_type,
                    }
                )

    def apply(self, builder, csr, context: dict):
        """Add CRL distribution points extension"""
        if not self.points:
            return builder

        cdp_builder = synta.ext.CDP()
        added = False
        for point_data in self.points:
            if point_data["point_type"] == "URIName":
                cdp_builder = cdp_builder.full_name_uri(
                    point_data["point_name"]
                )
                added = True

        if added:
            cdp_der = cdp_builder.build()
            builder = builder.add_extension(
                str(synta.oids.CRL_DISTRIBUTION_POINTS), self.critical, cdp_der
            )

        return builder


class AuthInfoAccessExtDefault(Default):
    """authInfoAccessExtDefaultImpl - adds Authority Information Access"""

    def __init__(
        self,
        authInfoAccessCritical: str = None,
        authInfoAccessNumADs: str = None,
        **kwargs,
    ):
        """Initialize AIA default"""
        self.critical = (authInfoAccessCritical or "false").lower() == "true"
        self.num_ads = int(authInfoAccessNumADs) if authInfoAccessNumADs else 0
        self.access_descriptions = []

        # Parse access descriptions
        for i in range(self.num_ads):
            enabled = (
                kwargs.get(f"authInfoAccessADEnable_{i}", "false").lower()
                == "true"
            )
            if not enabled:
                continue

            method = kwargs.get(f"authInfoAccessADMethod_{i}", "")
            location = kwargs.get(f"authInfoAccessADLocation_{i}", "")
            location_type = kwargs.get(f"authInfoAccessADLocationType_{i}", "")

            if method and location:
                self.access_descriptions.append(
                    {
                        "method": method,
                        "location": location,
                        "location_type": location_type,
                    }
                )

    def apply(self, builder, csr, context: dict):
        """Add Authority Information Access extension"""
        if not self.access_descriptions:
            return builder

        # OCSP: 1.3.6.1.5.5.7.48.1  CA Issuers: 1.3.6.1.5.5.7.48.2
        _OCSP_OID = "1.3.6.1.5.5.7.48.1"
        _CA_ISSUERS_OID = "1.3.6.1.5.5.7.48.2"

        aia_builder = synta.ext.AIA()
        added = False
        for ad in self.access_descriptions:
            if ad["location_type"] != "URIName":
                logger.warning(
                    "Unsupported AIA location type: %s", ad["location_type"]
                )
                continue
            method = ad["method"]
            location = ad["location"]
            if method == _OCSP_OID:
                aia_builder = aia_builder.ocsp(location)
                added = True
            elif method == _CA_ISSUERS_OID:
                aia_builder = aia_builder.ca_issuers(location)
                added = True
            else:
                logger.warning(
                    "Unsupported AIA method OID: %s", method
                )

        if added:
            aia_der = aia_builder.build()
            builder = builder.add_extension(
                str(synta.oids.AUTHORITY_INFO_ACCESS), self.critical, aia_der
            )

        return builder


class UserExtensionDefault(Default):
    """userExtensionDefaultImpl - uses extension from CSR"""

    def __init__(self, userExtOID: str = None, **kwargs):
        """Initialize user extension default

        Args:
            userExtOID: OID of extension to copy from CSR
        """
        self.oid_str = userExtOID

    def apply(self, builder, csr, context: dict):
        """Copy extension from CSR to certificate"""
        if not self.oid_str:
            return builder

        try:
            # Track which extensions have been added in context
            if "extensions_added" not in context:
                context["extensions_added"] = set()

            # Skip if this extension was already added by another policy
            if self.oid_str in context["extensions_added"]:
                logger.debug(
                    "Extension %s already added, skipping", self.oid_str
                )
                return builder

            # Try to get extension value DER from CSR
            ext_der = csr.get_extension_value_der(self.oid_str)
            if ext_der is not None:
                # Copy as non-critical; CSR does not carry criticality flags
                builder = builder.add_extension(self.oid_str, False, ext_der)
                # Mark this extension as added
                context["extensions_added"].add(self.oid_str)
                logger.debug("Added extension %s from CSR", self.oid_str)

        except Exception as e:
            logger.warning(
                "Failed to copy user extension %s: %s", self.oid_str, e
            )

        return builder


class CommonNameToSANDefault(Default):
    """commonNameToSANDefaultImpl - copies CN to Subject Alternative Name"""

    def __init__(self, **kwargs):
        """Initialize CN to SAN default"""

    def apply(self, builder, csr, context: dict):
        """Copy CN from subject to SAN as DNSName"""
        try:
            # Track which extensions have been added in context
            if "extensions_added" not in context:
                context["extensions_added"] = set()

            # SAN extension OID is 2.5.29.17
            san_oid = str(synta.oids.SUBJECT_ALT_NAME)

            # Skip if SAN extension was already added by another policy
            if san_oid in context["extensions_added"]:
                logger.debug(
                    "SAN extension already added by another policy, skipping "
                    "CN to SAN copy"
                )
                return builder

            # Get CN from subject DER
            cn = None
            for oid_str, value in synta.parse_name_attrs(csr.subject_raw_der):
                if oid_str == str(synta.oids.attr.COMMON_NAME):
                    cn = value
                    break

            if not cn:
                return builder

            # Add as DNSName in SAN
            san_der = synta.ext.SAN().dns_name(cn).build()
            builder = builder.add_extension(san_oid, False, san_der)

            # Mark SAN extension as added
            context["extensions_added"].add(san_oid)
            logger.debug("Added SAN extension with CN=%s", cn)

        except Exception as e:
            logger.warning("Failed to copy CN to SAN: %s", e)

        return builder


class SANToCNDefault(Default):
    """sanToCNDefaultImpl - copies SAN to Common Name (inverse of
    commonNameToSAN)"""

    def __init__(self, **kwargs):
        """Initialize SAN to CN default"""

    def apply(self, builder, csr, context: dict):
        """Copy first DNS name from SAN to CN in subject"""
        import synta.general_name as gn

        try:
            # Get SAN extension from CSR
            for tag_num, content in csr.subject_alt_names():
                if tag_num == gn.DNS_NAME:
                    # Use SAN DNS name as CN
                    # This will be used if the profile sets subject from SAN
                    # For now, we just pass through - the subject will be set
                    # by another default plugin
                    break

        except Exception as e:
            logger.warning("Failed to copy SAN to CN: %s", e)

        return builder


class UserSubjectNameDefault(Default):
    """userSubjectNameDefaultImpl - uses subject name from request/CSR"""

    def __init__(self, **kwargs):
        """Initialize user subject name default"""

    def apply(self, builder, csr, context: dict):
        """Use subject name directly from CSR

        This default simply uses the subject DN from the CSR as-is,
        without modification or variable substitution.
        """
        # Use subject DER from CSR directly
        subject_der = csr.subject_raw_der

        # Store in context for constraint validation
        context["final_subject_dn"] = csr.subject

        return builder.subject_name(subject_der)


class OCSPNoCheckExtDefault(Default):
    """ocspNoCheckExtDefaultImpl - adds OCSP No Check extension"""

    def __init__(self, critical: str = "false", **kwargs):
        """Initialize OCSP No Check extension default

        Args:
            critical: Whether extension is critical ("true"/"false")
        """
        self.critical = critical.lower() == "true"

    def apply(self, builder, csr, context: dict):
        """Add OCSP No Check extension

        This extension indicates that the certificate is an OCSP responder
        certificate and should not be checked for revocation.
        """
        # OCSP No Check OID: 1.3.6.1.5.5.7.48.1.5
        # Value is a DER NULL (0x05 0x00)
        _OCSP_NO_CHECK_OID = "1.3.6.1.5.5.7.48.1.5"
        try:
            builder = builder.add_extension(
                _OCSP_NO_CHECK_OID, self.critical, b"\x05\x00"
            )
        except Exception as e:
            logger.warning("Failed to add OCSP No Check extension: %s", e)

        return builder


# Default factory
def create_default(class_id: str, params: Dict[str, Any]) -> Default:
    """Factory to instantiate defaults from .cfg data

    Args:
        class_id: Default class identifier
        params: Default parameters

    Returns:
        Instantiated Default object
    """
    default_map = {
        "userKeyDefaultImpl": UserKeyDefault,
        "subjectNameDefaultImpl": SubjectNameDefault,
        "validityDefaultImpl": ValidityDefault,
        "signingAlgDefaultImpl": SigningAlgDefault,
        "authorityKeyIdentifierExtDefaultImpl": (
            AuthorityKeyIdentifierExtDefault
        ),
        "subjectKeyIdentifierExtDefaultImpl": SubjectKeyIdentifierExtDefault,
        "keyUsageExtDefaultImpl": KeyUsageExtDefault,
        "extendedKeyUsageExtDefaultImpl": ExtendedKeyUsageExtDefault,
        "crlDistributionPointsExtDefaultImpl": CRLDistributionPointsExtDefault,
        "authInfoAccessExtDefaultImpl": AuthInfoAccessExtDefault,
        "userExtensionDefaultImpl": UserExtensionDefault,
        "commonNameToSANDefaultImpl": CommonNameToSANDefault,
        "sanToCNDefaultImpl": SANToCNDefault,
        "userSubjectNameDefaultImpl": UserSubjectNameDefault,
        "ocspNoCheckExtDefaultImpl": OCSPNoCheckExtDefault,
    }

    default_class = default_map.get(class_id)
    if not default_class:
        logger.warning(
            "Unknown default class '%s', using UserKeyDefault", class_id
        )
        return UserKeyDefault()

    try:
        return default_class(**params)
    except Exception as e:
        logger.error("Failed to create default %s: %s", class_id, e)
        raise
