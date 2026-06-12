# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Shared utility functions for Ipacta REST API blueprints."""

import base64
import logging
import secrets

from flask import make_response

from ipacta.rest_api_helpers import success_response

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PKCS#7 degenerate SignedData (certificate-chain-only) helper
# ---------------------------------------------------------------------------

def _encode_length(n: int) -> bytes:
    """Encode a DER length field (supports up to 4-byte lengths)."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    elif n < 0x1000000:
        return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])
    elif n < 0x100000000:
        return bytes(
            [0x84, n >> 24, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]
        )
    else:
        raise ValueError(f"Length too large for DER encoding: {n}")


def _build_pkcs7_chain_pem(certs) -> bytes:
    """
    Serialize a list of synta.Certificate objects as a PKCS#7 degenerate
    SignedData PEM block (-----BEGIN PKCS7-----).

    This matches the output of pkcs7.serialize_certificates(..., PEM).
    """
    # Concatenate DER encodings of all certs
    certs_der = b"".join(c.to_der() for c in certs)
    # [0] IMPLICIT certificates
    certs_tagged = b"\xa0" + _encode_length(len(certs_der)) + certs_der
    # Empty SET for digestAlgorithms
    empty_set = b"\x31\x00"
    # EncapContentInfo: SEQUENCE { OID id-data }
    oid_data = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
    encap = b"\x30" + _encode_length(len(oid_data)) + oid_data
    # Version INTEGER 1
    version = b"\x02\x01\x01"
    # Empty SET for signerInfos
    empty_signers = b"\x31\x00"
    # SignedData SEQUENCE
    sd_content = version + empty_set + encap + certs_tagged + empty_signers
    signed_data = b"\x30" + _encode_length(len(sd_content)) + sd_content
    # [0] EXPLICIT wrapper
    explicit_0 = b"\xa0" + _encode_length(len(signed_data)) + signed_data
    # id-signedData OID
    oid_sd = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
    # ContentInfo SEQUENCE
    ci_body = oid_sd + explicit_0
    pkcs7_der = b"\x30" + _encode_length(len(ci_body)) + ci_body
    # PEM-encode
    b64 = base64.b64encode(pkcs7_der).decode("ascii")
    lines = [b64[i: i + 64] for i in range(0, len(b64), 64)]
    return (
        "-----BEGIN PKCS7-----\n"
        + "\n".join(lines)
        + "\n-----END PKCS7-----\n"
    ).encode("ascii")


# ---------------------------------------------------------------------------
# Account login/logout shared helpers
# ---------------------------------------------------------------------------

def _account_login():
    """Shared implementation for account login endpoint.

    IPA's dogtag plugin (ipaserver/plugins/dogtag.py) expects a JSESSIONID
    cookie in the login response so it can attach the cookie to subsequent
    requests.  The cookie value is never validated server-side: every
    protected endpoint is guarded by require_agent_auth(), which re-validates
    the client TLS certificate on every request regardless of cookie state.
    The JSESSIONID is therefore a Dogtag compatibility shim only.

    DO NOT add server-side session validation based on JSESSIONID value —
    the security boundary is the per-request client certificate check, not
    this cookie.

    Used by both CA and KRA subsystems.
    """
    # Dogtag compat: return a JSESSIONID cookie value (not stored server-side)
    session_token = secrets.token_hex(32)

    response = make_response(success_response({"Status": "success"}))
    response.set_cookie(
        "JSESSIONID",
        session_token,
        max_age=1800,  # 30 minutes
        httponly=True,
        secure=True,
        samesite="Strict",
    )
    return response


def _account_logout():
    """Shared implementation for account logout endpoint (v1 REST API).

    Clears session cookie. Returns 200 with success message.
    """
    response = make_response(success_response({"Status": "success"}))
    # Clear the session cookie
    response.set_cookie("JSESSIONID", "", max_age=0)
    return response


def _account_logout_v2():
    """Shared implementation for account logout endpoint (v2 REST API).

    Clears session cookie. Returns 204 No Content (Dogtag v2 compatibility).
    """
    response = make_response("", 204)
    # Clear the session cookie
    response.set_cookie("JSESSIONID", "", max_age=0)
    return response


# ---------------------------------------------------------------------------
# Certificate search helper
# ---------------------------------------------------------------------------

def _search_certificates(request, ca_backend):
    """
    Internal helper for certificate search (handles both GET and POST)

    Parses PKI-style search parameters and converts them to backend format.
    Supports both URL query parameters (GET) and JSON body (POST).

    Parameter mapping from PKI to backend:
    - serialFrom/serialTo -> min_serial_number/max_serial_number
    - commonName -> subject (common name search)
    - issuerDN -> issuer
    - status -> status
    - issuedOnFrom/issuedOnTo -> issued_on_from/issued_on_to
    - validNotBeforeFrom/validNotBeforeTo
      -> valid_not_before_from/valid_not_before_to
    - validNotAfterFrom/validNotAfterTo
      -> valid_not_after_from/valid_not_after_to
    - revokedOnFrom/revokedOnTo -> revoked_on_from/revoked_on_to
    - matchExactly -> exactly
    """
    from ipacta.rest_api_helpers import CertificateHandler

    # Parse pagination parameters from URL (both GET and POST)
    size = request.args.get("size", type=int)
    start = request.args.get("start", type=int, default=0)
    max_results = request.args.get("maxResults", type=int)
    max_time = request.args.get("maxTime", type=int)

    # Parse search criteria based on request method
    search_request = {}

    if request.method == "POST":
        # POST request - JSON body contains search criteria
        search_request = request.get_json() or {}
    else:
        # GET request - URL parameters (build from query string)
        # This is used by some older clients
        search_request = dict(request.args)
        # Remove pagination params from search criteria
        for key in ["size", "start", "maxResults", "maxTime"]:
            search_request.pop(key, None)

    # Map PKI parameter names to backend parameter names
    # Based on pki/cert.py CertSearchRequest.search_params mapping
    criteria = {}

    # Serial number range
    if "serialFrom" in search_request:
        criteria["min_serial_number"] = search_request["serialFrom"]
    if "serialTo" in search_request:
        criteria["max_serial_number"] = search_request["serialTo"]

    # Subject fields (mapped to subject search in backend)
    if "commonName" in search_request:
        criteria["subject"] = search_request["commonName"]
    if "eMail" in search_request:
        criteria["email"] = search_request["eMail"]
    if "userID" in search_request:
        criteria["user_id"] = search_request["userID"]
    if "orgUnit" in search_request:
        criteria["org_unit"] = search_request["orgUnit"]
    if "org" in search_request:
        criteria["org"] = search_request["org"]
    if "locality" in search_request:
        criteria["locality"] = search_request["locality"]
    if "state" in search_request:
        criteria["state"] = search_request["state"]
    if "country" in search_request:
        criteria["country"] = search_request["country"]

    # Match exactly flag
    if "matchExactly" in search_request:
        criteria["exactly"] = search_request["matchExactly"]

    # Issuer DN
    if "issuerDN" in search_request:
        criteria["issuer"] = search_request["issuerDN"]

    # Status
    if "status" in search_request:
        criteria["status"] = search_request["status"]

    # Revocation info
    if "revokedBy" in search_request:
        criteria["revoked_by"] = search_request["revokedBy"]
    if "revokedOnFrom" in search_request:
        criteria["revoked_on_from"] = search_request["revokedOnFrom"]
    if "revokedOnTo" in search_request:
        criteria["revoked_on_to"] = search_request["revokedOnTo"]
    if "revocationReason" in search_request:
        criteria["revocation_reason"] = search_request["revocationReason"]

    # Issuance info
    if "issuedBy" in search_request:
        criteria["issued_by"] = search_request["issuedBy"]
    if "issuedOnFrom" in search_request:
        criteria["issued_on_from"] = search_request["issuedOnFrom"]
    if "issuedOnTo" in search_request:
        criteria["issued_on_to"] = search_request["issuedOnTo"]

    # Validity dates
    if "validNotBeforeFrom" in search_request:
        criteria["valid_not_before_from"] = search_request[
            "validNotBeforeFrom"
        ]
    if "validNotBeforeTo" in search_request:
        criteria["valid_not_before_to"] = search_request["validNotBeforeTo"]
    if "validNotAfterFrom" in search_request:
        criteria["valid_not_after_from"] = search_request["validNotAfterFrom"]
    if "validNotAfterTo" in search_request:
        criteria["valid_not_after_to"] = search_request["validNotAfterTo"]

    # Certificate type filters
    if "certTypeSubEmailCA" in search_request:
        criteria["cert_type_sub_email_ca"] = search_request[
            "certTypeSubEmailCA"
        ]
    if "certTypeSubSSLCA" in search_request:
        criteria["cert_type_sub_ssl_ca"] = search_request["certTypeSubSSLCA"]
    if "certTypeSecureEmail" in search_request:
        criteria["cert_type_secure_email"] = search_request[
            "certTypeSecureEmail"
        ]
    if "certTypeSSLClient" in search_request:
        criteria["cert_type_ssl_client"] = search_request["certTypeSSLClient"]
    if "certTypeSSLServer" in search_request:
        criteria["cert_type_ssl_server"] = search_request["certTypeSSLServer"]

    # Add pagination parameters to criteria
    if size is not None:
        criteria["sizelimit"] = size
    elif max_results is not None:
        criteria["sizelimit"] = max_results

    if start is not None:
        criteria["offset"] = start

    if max_time is not None:
        criteria["timelimit"] = max_time

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Certificate search criteria: %s", criteria)

    # Execute search through handler
    return CertificateHandler.search(criteria, ca_backend)
