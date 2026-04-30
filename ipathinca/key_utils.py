# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Key generation utilities for ipathinca.

Centralises private-key generation so that certs.py, nss_utils.py, and
ocsp.py can all dispatch on algorithm type without circular imports.
"""

from __future__ import absolute_import

import logging

import synta

logger = logging.getLogger(__name__)

# Map NSS/Dogtag curve names to the names synta's generate_ec() expects.
_NSS_CURVE_MAP = {
    "nistp256": "P-256",
    "nistp384": "P-384",
    "nistp521": "P-521",
}


def generate_private_key(
    signing_alg: str, key_size: int, ec_curve: str = "P-256"
) -> synta.PrivateKey:
    """Generate a private key appropriate for the given signing algorithm.

    Args:
        signing_alg: PKI algorithm string such as ``"SHA256withRSA"``,
                     ``"SHA256withEC"``, or ``"ML-DSA-65"``.
        key_size:    RSA key size in bits (ignored for EC and ML-DSA).
        ec_curve:    EC curve name in either synta form ("P-256") or NSS/Dogtag
                     form ("nistp256"). Ignored for RSA and ML-DSA.

    Returns:
        A freshly generated :class:`synta.PrivateKey`.

    Raises:
        ValueError: For unknown ML-DSA parameter sets.
    """
    alg_upper = signing_alg.upper()

    if "ML-DSA" in alg_upper or "MLDSA" in alg_upper:
        for param_set in ("ML-DSA-87", "ML-DSA-65", "ML-DSA-44"):
            if param_set in alg_upper:
                logger.debug("Generating %s private key", param_set)
                return synta.PrivateKey.generate_ml_dsa(param_set)
        raise ValueError(
            f"Unknown ML-DSA parameter set in signing algorithm:"
            f" {signing_alg!r}"
        )

    if "EC" in alg_upper or "ECDSA" in alg_upper:
        synta_curve = _NSS_CURVE_MAP.get(ec_curve.lower(), ec_curve)
        logger.debug("Generating EC private key (%s)", synta_curve)
        return synta.PrivateKey.generate_ec(synta_curve)

    logger.debug("Generating %d-bit RSA private key", key_size)
    return synta.PrivateKey.generate_rsa(key_size)
