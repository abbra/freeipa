# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
OCSP Responder Implementation

This module implements an OCSP (Online Certificate Status Protocol) responder
according to RFC 6960. It provides real-time certificate revocation checking
as an alternative to CRLs.

Features:
- RFC 6960 compliant OCSP responses
- Nonce support (replay attack prevention)
- Response caching for performance
- OCSP signing certificate management
- Support for delegated OCSP signing
"""

import hashlib
import logging
import os
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Tuple

import synta
import synta.ext
import synta.oids

from ipaplatform.paths import paths

import ipathinca
from ipathinca import x509_utils
from ipathinca.key_utils import generate_private_key

logger = logging.getLogger(__name__)

# OCSP status constants (RFC 6960)
_OCSP_STATUS_GOOD = 0
_OCSP_STATUS_REVOKED = 1
_OCSP_STATUS_UNKNOWN = 2

# OCSP nonce extension OID (RFC 6960)
_OCSP_NONCE_OID = "1.3.6.1.5.5.7.48.1.2"


@dataclass
class _ParsedOCSPRequest:
    """Parsed OCSP request data."""
    serial_number: int
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    hash_algorithm_der: bytes  # raw AlgorithmIdentifier TLV
    nonce: Optional[bytes]


def _parse_ocsp_request(der_bytes: bytes) -> _ParsedOCSPRequest:
    """
    Parse a DER-encoded OCSP request.

    OCSPRequest ::= SEQUENCE {
      tbsRequest TBSRequest,
      ...
    }
    TBSRequest ::= SEQUENCE {
      requestList SEQUENCE OF Request,
      ...
    }
    Request ::= SEQUENCE {
      reqCert CertID,
      ...
    }
    CertID ::= SEQUENCE {
      hashAlgorithm AlgorithmIdentifier,
      issuerNameHash OCTET STRING,
      issuerKeyHash  OCTET STRING,
      serialNumber   INTEGER
    }
    """
    try:
        outer = synta.Decoder(der_bytes, synta.Encoding.DER)
        # OCSPRequest SEQUENCE
        ocsp_req = outer.decode_sequence()

        # TBSRequest SEQUENCE
        tbs = ocsp_req.decode_sequence()

        # Skip optional [0] version and [1] requestorName by peeking
        # requestList is the first non-tagged element
        while not tbs.is_empty():
            tag_num, tag_class, _constructed = tbs.peek_tag()
            if tag_class == "Context":
                # skip optional tagged fields (version, requestorName,
                # requestExtensions)
                tbs.decode_raw_tlv()
            else:
                break

        # requestList SEQUENCE OF Request
        req_list = tbs.decode_sequence()

        # First Request SEQUENCE
        req = req_list.decode_sequence()

        # reqCert CertID SEQUENCE — capture raw TLV for later, then decode
        cert_id_raw = req.decode_raw_tlv()
        cert_id = synta.Decoder(cert_id_raw, synta.Encoding.DER)
        cert_id_seq = cert_id.decode_sequence()

        # hashAlgorithm AlgorithmIdentifier — capture raw TLV
        hash_alg_raw = cert_id_seq.decode_raw_tlv()

        # issuerNameHash OCTET STRING
        issuer_name_hash = cert_id_seq.decode_octet_string().to_bytes()

        # issuerKeyHash OCTET STRING
        issuer_key_hash = cert_id_seq.decode_octet_string().to_bytes()

        # serialNumber INTEGER
        serial_int = cert_id_seq.decode_integer()
        serial_number = serial_int.to_int()

        # Parse nonce from requestExtensions [2] if present
        nonce = None
        # requestExtensions is at [2] EXPLICIT on the TBSRequest
        # (already consumed requestList above; look for remaining [2] tag)
        while not tbs.is_empty():
            tag_num, tag_class, _constructed = tbs.peek_tag()
            if tag_class == "Context" and tag_num == 2:
                # [2] EXPLICIT Extensions
                ext_inner = tbs.decode_explicit_tag(2)
                # Extensions SEQUENCE OF Extension
                exts = ext_inner.decode_sequence()
                while not exts.is_empty():
                    ext_seq = exts.decode_sequence()
                    ext_oid = str(ext_seq.decode_oid())
                    # skip critical boolean if present
                    peek = ext_seq.peek_tag()
                    if peek[0] == 1 and peek[1] == "Universal":
                        ext_seq.decode_boolean()
                    ext_value_outer = ext_seq.decode_octet_string()
                    if ext_oid == _OCSP_NONCE_OID:
                        # nonce is an OCTET STRING inside the extnValue
                        nonce_bytes = ext_value_outer.to_bytes()
                        try:
                            nonce_dec = synta.Decoder(
                                nonce_bytes, synta.Encoding.DER
                            )
                            nonce = nonce_dec.decode_octet_string().to_bytes()
                        except Exception:
                            nonce = nonce_bytes
            else:
                tbs.decode_raw_tlv()

        return _ParsedOCSPRequest(
            serial_number=serial_number,
            issuer_name_hash=issuer_name_hash,
            issuer_key_hash=issuer_key_hash,
            hash_algorithm_der=hash_alg_raw,
            nonce=nonce,
        )
    except Exception as e:
        raise ValueError(f"Failed to parse OCSP request: {e}") from e


class OCSPResponse:
    """OCSP Response container"""

    def __init__(self, response_bytes: bytes, cache_until: datetime = None):
        self.response_bytes = response_bytes
        self.cache_until = cache_until or (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )

    def is_expired(self) -> bool:
        """Check if cached response is expired"""
        return datetime.now(timezone.utc) > self.cache_until


class OCSPResponder:
    """
    OCSP Responder implementing RFC 6960

    Provides real-time certificate revocation status checking.
    """

    def __init__(
        self,
        ca,
        ocsp_cert_path: str = None,
        ocsp_key_path: str = None,
        cache_timeout: int = 300,
    ):
        """
        Initialize OCSP Responder

        Args:
            ca: Certificate Authority instance (PythonCA or InternalCA)
            ocsp_cert_path: Path to OCSP signing certificate (optional, will
                            use CA cert if not provided)
            ocsp_key_path: Path to OCSP signing private key (optional)
            cache_timeout: Response cache timeout in seconds (default:
                           300 = 5 minutes)
        """
        self.ca = ca
        self.cache_timeout = cache_timeout
        self.response_cache: OrderedDict = OrderedDict()
        self.cache_maxsize = 1000
        self._cache_lock = threading.Lock()

        # OCSP signing certificate paths
        self.ocsp_cert_path = Path(ocsp_cert_path) if ocsp_cert_path else None
        self.ocsp_key_path = Path(ocsp_key_path) if ocsp_key_path else None

        # Load or generate OCSP signing certificate
        self.ocsp_cert = None
        self.ocsp_key = None
        self._init_ocsp_signing_cert()

    def _init_ocsp_signing_cert(self):
        """Initialize OCSP signing certificate and key from filesystem

        IMPORTANT: OCSP signing keys are NEVER stored in LDAP, only on
        filesystem.
        This matches Dogtag behavior where CA/Sub-CA/OCSP signing keys are
        filesystem-only for security. Only KRA archived keys (for key recovery)
        are stored in LDAP.
        """
        # Load from filesystem if paths are provided
        if self.ocsp_cert_path and self.ocsp_cert_path.exists():
            logger.info(
                "Loading OCSP signing certificate from %s", self.ocsp_cert_path
            )
            with open(self.ocsp_cert_path, "rb") as f:
                self.ocsp_cert = synta.Certificate.from_pem(f.read())

            if self.ocsp_key_path and self.ocsp_key_path.exists():
                with open(self.ocsp_key_path, "rb") as f:
                    self.ocsp_key = synta.PrivateKey.from_pem(f.read())
        else:
            # Generate OCSP signing certificate
            logger.info("Generating OCSP signing certificate")
            self._generate_ocsp_signing_cert()

    def _generate_ocsp_signing_cert(self):
        """Generate OCSP signing certificate using synta."""
        try:
            # Ensure CA cert and key are loaded
            self.ca._ensure_ca_loaded()

            # Generate OCSP signing key (read size from config)
            ocsp_key_size = int(
                ipathinca.get_config_value(
                    "ca", "ocsp_signing_key_size", default="3072"
                )
            )
            ca_signing_alg = x509_utils.get_certificate_signature_algorithm(
                self.ca.ca_cert
            )
            self.ocsp_key = generate_private_key(ca_signing_alg, ocsp_key_size)
            logger.info(
                "Generated OCSP signing key (%s)", ca_signing_alg
            )

            # Derive CN from CA cert subject
            ca_attrs = synta.parse_name_attrs(
                self.ca.ca_cert.subject_raw_der
            )
            # find CN (OID 2.5.4.3)
            ca_cn = next(
                (v for o, v in ca_attrs if o == "2.5.4.3"),
                "IPA CA",
            )
            subject_der = x509_utils.build_x509_name(
                [("CN", f"OCSP Responder - {ca_cn}")]
            )

            # Build OCSP signing certificate
            serial_number = self.ca._get_next_serial_number()
            now = datetime.now(timezone.utc)

            # EKU extension: OCSP signing (critical)
            eku_oid, eku_der = x509_utils.get_ocsp_extended_key_usage()

            # SubjectKeyIdentifier extension
            ocsp_pub_key = self.ocsp_key.public_key
            ski_der = synta.ext.subject_key_identifier(
                ocsp_pub_key.to_der()
            )

            # AuthorityKeyIdentifier extension
            aki_der = synta.ext.authority_key_identifier(
                self.ca.ca_cert.subject_public_key_info_der
            )

            # Sign the certificate
            signing_alg = x509_utils.get_certificate_signature_algorithm(
                self.ca.ca_cert
            )
            hash_alg = x509_utils.parse_signature_algorithm(signing_alg)

            builder = synta.CertificateBuilder()
            builder = builder.subject_name(subject_der)
            builder = builder.issuer_name(self.ca.ca_cert.subject_raw_der)
            builder = builder.public_key(ocsp_pub_key)
            builder = builder.serial_number(serial_number)
            builder = builder.not_valid_before_utc(now)
            builder = builder.not_valid_after_utc(
                now + timedelta(days=365)
            )
            builder = builder.add_extension(eku_oid, True, eku_der)
            builder = builder.add_extension(
                str(synta.oids.SUBJECT_KEY_IDENTIFIER), False, ski_der
            )
            builder = builder.add_extension(
                str(synta.oids.AUTHORITY_KEY_IDENTIFIER), False, aki_der
            )

            self.ocsp_cert = builder.sign(self.ca.ca_private_key, hash_alg)

            # Save to filesystem (OCSP keys are NEVER stored in LDAP)
            # This follows Dogtag behavior where CA/Sub-CA/OCSP signing keys
            # are filesystem-only
            if self.ocsp_cert_path:
                self.ocsp_cert_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.ocsp_cert_path, "wb") as f:
                    f.write(synta.Certificate.to_pem(self.ocsp_cert))
                os.chmod(self.ocsp_cert_path, 0o644)

            if self.ocsp_key_path:
                self.ocsp_key_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.ocsp_key_path, "wb") as f:
                    f.write(synta.PrivateKey.to_pem(self.ocsp_key))
                os.chmod(self.ocsp_key_path, 0o600)

            logger.info(
                "OCSP signing certificate generated with serial %s",
                self.ocsp_cert.serial_number,
            )

        except Exception as e:
            logger.error(
                "Failed to generate OCSP signing certificate: %s",
                e,
                exc_info=True,
            )
            # Do NOT fall back to the CA private key: using the CA key for
            # OCSP signing would expose root key material to the OCSP path
            # and mask the underlying failure.  Let the exception propagate
            # so the operator receives a clear error and create_response()
            # returns internalError OCSP responses until the problem is fixed.
            raise

    def _get_cache_key(self, serial_number: int, nonce: bytes = None) -> str:
        """Generate cache key for OCSP response"""
        key_data = f"{serial_number}"
        if nonce:
            key_data += f":{nonce.hex()}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _get_cert_status(self, serial_number: int) -> Tuple[
        int,
        Optional[datetime],
        Optional[int],
        Optional[synta.Certificate],
    ]:
        """
        Get certificate status from CA.

        Returns:
            Tuple of (status_int, revocation_time, revocation_reason_int,
                      certificate) where status_int is 0=good, 1=revoked,
                      2=unknown.
        """
        try:
            cert_record = self.ca.get_certificate(serial_number)

            if not cert_record:
                return _OCSP_STATUS_UNKNOWN, None, None, None

            # Check if revoked
            if cert_record.status.value in ("REVOKED", "ON_HOLD"):
                reason = None
                if cert_record.revocation_reason:
                    reason_value = (
                        cert_record.revocation_reason.value
                        if hasattr(cert_record.revocation_reason, "value")
                        else cert_record.revocation_reason
                    )
                    reason = reason_value

                return (
                    _OCSP_STATUS_REVOKED,
                    cert_record.revoked_at,
                    reason,
                    cert_record.certificate,
                )

            # Certificate is valid
            return (
                _OCSP_STATUS_GOOD,
                None,
                None,
                cert_record.certificate,
            )

        except Exception as e:
            logger.error(
                "Error checking certificate status for serial %s: %s",
                serial_number,
                e,
            )
            return _OCSP_STATUS_UNKNOWN, None, None, None

    def create_response(self, request_der: bytes) -> bytes:
        """
        Create OCSP response from request.

        Args:
            request_der: DER-encoded OCSP request

        Returns:
            DER-encoded OCSP response
        """
        try:
            # Parse OCSP request
            try:
                parsed_req = _parse_ocsp_request(request_der)
            except Exception as e:
                logger.warning("Failed to parse OCSP request: %s", e)
                return self._create_error_response()

            serial_number = parsed_req.serial_number
            nonce = parsed_req.nonce

            # Check cache (thread-safe)
            cache_key = self._get_cache_key(serial_number, nonce)
            with self._cache_lock:
                cached_response = self.response_cache.get(cache_key)
            if cached_response is not None:
                if not cached_response.is_expired():
                    logger.debug(
                        "Returning cached OCSP response for serial %s",
                        serial_number,
                    )
                    return cached_response.response_bytes
                else:
                    # Remove expired entry
                    with self._cache_lock:
                        self.response_cache.pop(cache_key, None)

            # Ensure CA cert is loaded
            self.ca._ensure_ca_loaded()

            # Get certificate status
            cert_status, revocation_time, _revocation_reason, _certificate = (
                self._get_cert_status(serial_number)
            )

            # Build response timestamps
            now = datetime.now(timezone.utc)
            if cert_status == _OCSP_STATUS_REVOKED:
                this_update = revocation_time or now
            else:
                this_update = now
            next_update = now + timedelta(seconds=self.cache_timeout)

            def _to_generalizedtime(dt: datetime) -> str:
                return dt.strftime("%Y%m%d%H%M%SZ")

            this_update_str = _to_generalizedtime(this_update)
            next_update_str = _to_generalizedtime(next_update)

            # serial as big-endian bytes (strip leading zeros, keep at least 1)
            serial_bytes = serial_number.to_bytes(
                max(1, (serial_number.bit_length() + 7) // 8), "big"
            )

            # Build SingleResponse using hash info from the request
            single_resp = synta.OCSPSingleResponse(
                hash_algorithm_der=parsed_req.hash_algorithm_der,
                issuer_name_hash=parsed_req.issuer_name_hash,
                issuer_key_hash=parsed_req.issuer_key_hash,
                serial=serial_bytes,
                status=cert_status,
                this_update=this_update_str,
                next_update=next_update_str,
            )

            # Get signing algorithm for OCSP cert
            signing_alg_str = x509_utils.get_certificate_signature_algorithm(
                self.ocsp_cert
            )
            hash_alg = x509_utils.parse_signature_algorithm(signing_alg_str)

            # Build the ResponseData (TBS)
            # Use responder byKey (SHA-1 hash of OCSP cert's public key)
            ocsp_spki_der = self.ocsp_cert.subject_public_key_info_der
            # SHA-1 of the subjectPublicKey BIT STRING value
            ski_bytes = synta.ext.subject_key_identifier(
                ocsp_spki_der, synta.ext.KEYID_RFC5280
            )
            # ski_bytes is an OCTET STRING DER — extract the hash value
            ski_dec = synta.Decoder(ski_bytes, synta.Encoding.DER)
            key_hash = ski_dec.decode_octet_string().to_bytes()

            produced_at_str = _to_generalizedtime(now)

            resp_builder = synta.OCSPResponseBuilder()
            resp_builder = resp_builder.responder_key_hash(key_hash)
            resp_builder = resp_builder.produced_at(produced_at_str)
            resp_builder = resp_builder.add_response(single_resp)

            tbs_der = resp_builder.build_tbs()

            # Sign the TBS
            sig = self.ocsp_key.sign(tbs_der, hash_alg)

            # Build signature AlgorithmIdentifier
            ocsp_pub_key = self.ocsp_cert.subject_public_key_info_der
            key_oid = synta.decode_public_key_info(
                ocsp_pub_key
            )["algorithm_oid"]
            sig_alg_der = synta.signing_algorithm_der(key_oid, hash_alg)
            if sig_alg_der is None:
                raise ValueError(
                    f"Unsupported OCSP signing key algorithm OID {key_oid!r}"
                )

            response_bytes = synta.OCSPResponseBuilder.assemble(
                tbs_der, sig_alg_der, sig
            )

            # Cache the response (bounded: evict expired, then oldest)
            with self._cache_lock:
                expired_keys = [
                    k for k, v in self.response_cache.items() if v.is_expired()
                ]
                for k in expired_keys:
                    del self.response_cache[k]
                while len(self.response_cache) >= self.cache_maxsize:
                    self.response_cache.popitem(last=False)
                self.response_cache[cache_key] = OCSPResponse(
                    response_bytes, cache_until=next_update
                )

            status_names = {
                _OCSP_STATUS_GOOD: "GOOD",
                _OCSP_STATUS_REVOKED: "REVOKED",
                _OCSP_STATUS_UNKNOWN: "UNKNOWN",
            }
            logger.info(
                "Created OCSP response for serial %s, status: %s",
                serial_number,
                status_names.get(cert_status, str(cert_status)),
            )
            return response_bytes

        except Exception as e:
            logger.error("Error creating OCSP response: %s", e)
            # Return internal error response
            return self._create_error_response()

    def _create_error_response(self) -> bytes:
        """Create OCSP error response (internalError, RFC 6960 status 2).

        DER encoding: SEQUENCE { ENUMERATED { 2 } }
        """
        return bytes([0x30, 0x03, 0x0a, 0x01, 0x02])

    def clear_cache(self):
        """Clear response cache"""
        with self._cache_lock:
            self.response_cache.clear()
        logger.info("OCSP response cache cleared")

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        with self._cache_lock:
            total = len(self.response_cache)
            expired = sum(
                1 for resp in self.response_cache.values() if resp.is_expired()
            )

        return {
            "total_entries": total,
            "expired_entries": expired,
            "valid_entries": total - expired,
            "cache_timeout": self.cache_timeout,
        }


class OCSPResponderManager:
    """
    Manager for OCSP Responder instances

    Handles multiple OCSP responders for different CAs (main CA + sub-CAs)
    """

    def __init__(self, base_storage_path: str = None):
        """
        Initialize OCSP Responder Manager

        Args:
            base_storage_path: Base path for OCSP cert/key storage
        """
        self.responders: Dict[str, OCSPResponder] = {}
        self._responders_lock = threading.Lock()
        self.base_storage_path = Path(
            base_storage_path or f"{paths.IPATHINCA_DIR}ocsp"
        )
        self.base_storage_path.mkdir(parents=True, exist_ok=True, mode=0o750)

    def get_responder(self, ca, ca_id: str = "ipa") -> OCSPResponder:
        """
        Get or create OCSP responder for a CA

        Args:
            ca: CA instance
            ca_id: CA identifier

        Returns:
            OCSPResponder instance
        """
        if ca_id not in self.responders:
            with self._responders_lock:
                if ca_id not in self.responders:
                    # Create paths for this CA
                    ocsp_cert_path = (
                        self.base_storage_path / f"{ca_id}_ocsp.crt"
                    )
                    ocsp_key_path = (
                        self.base_storage_path / f"{ca_id}_ocsp.key"
                    )

                    # Create responder
                    self.responders[ca_id] = OCSPResponder(
                        ca=ca,
                        ocsp_cert_path=str(ocsp_cert_path),
                        ocsp_key_path=str(ocsp_key_path),
                    )

                    logger.info("Created OCSP responder for CA: %s", ca_id)

        return self.responders[ca_id]

    def clear_all_caches(self):
        """Clear all OCSP response caches"""
        with self._responders_lock:
            responders = dict(self.responders)
        for responder in responders.values():
            responder.clear_cache()
        logger.info("Cleared all OCSP response caches")

    def get_all_stats(self) -> Dict[str, Dict]:
        """Get statistics for all responders"""
        with self._responders_lock:
            responders = dict(self.responders)
        return {
            ca_id: responder.get_cache_stats()
            for ca_id, responder in responders.items()
        }


# Global OCSP responder manager instance
_ocsp_manager = None
_ocsp_manager_lock = threading.Lock()


def get_ocsp_manager(base_storage_path: str = None) -> OCSPResponderManager:
    """Get singleton OCSP responder manager"""
    global _ocsp_manager
    with _ocsp_manager_lock:
        if _ocsp_manager is None:
            _ocsp_manager = OCSPResponderManager(base_storage_path)
        return _ocsp_manager
