# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
JSON Web Key (JWK) implementation without jose dependency

Extracted from acme.py to avoid circular imports between
acme and storage_acme.
"""

import base64
import hashlib
import json
from typing import Dict, Any

import synta


class JWK:
    """JSON Web Key implementation without jose dependency"""

    @staticmethod
    def from_cryptography_key(key) -> Dict[str, Any]:
        """Convert synta key to JWK format"""
        # Normalise: private key → its public key
        if isinstance(key, synta.PrivateKey):
            key = key.public_key

        if not isinstance(key, synta.PublicKey):
            raise ValueError(f"Unsupported key type: {type(key)}")

        key_type = key.key_type
        if key_type == "rsa":
            return {
                "kty": "RSA",
                "n": JWK._encode_bytes(key.modulus),
                "e": JWK._encode_bytes(key.public_exponent),
            }
        elif key_type == "ec":
            curve = key.curve_name  # Already 'P-256', 'P-384', 'P-521'
            if curve not in ("P-256", "P-384", "P-521"):
                raise ValueError(f"Unsupported curve: {curve}")
            return {
                "kty": "EC",
                "crv": curve,
                "x": JWK._encode_bytes(key.x),
                "y": JWK._encode_bytes(key.y),
            }
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

    @staticmethod
    def _encode_bytes(value: bytes) -> str:
        """Encode bytes to base64url (stripping trailing '=')"""
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    @staticmethod
    def thumbprint(jwk_dict: Dict[str, Any]) -> str:
        """Calculate JWK thumbprint (RFC 7638)"""
        if "kty" not in jwk_dict:
            raise ValueError("Missing required JWK field: kty")
        kty = jwk_dict["kty"]
        if kty == "RSA":
            for field in ("e", "n"):
                if field not in jwk_dict:
                    raise ValueError(
                        f"Missing required RSA JWK field: {field}"
                    )
            canonical = {
                "e": jwk_dict["e"],
                "kty": kty,
                "n": jwk_dict["n"],
            }
        elif kty == "EC":
            for field in ("crv", "x", "y"):
                if field not in jwk_dict:
                    raise ValueError(f"Missing required EC JWK field: {field}")
            canonical = {
                "crv": jwk_dict["crv"],
                "kty": kty,
                "x": jwk_dict["x"],
                "y": jwk_dict["y"],
            }
        else:
            raise ValueError(f"Unsupported key type: {kty}")

        json_bytes = json.dumps(canonical, separators=(",", ":")).encode(
            "utf-8"
        )
        digest = hashlib.sha256(json_bytes).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")
