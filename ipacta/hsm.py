# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Hardware Security Module (HSM) Support

Provides PKCS#11 integration for storing CA private keys in Hardware
Security Modules (HSMs).  All token management and signing is handled by
synta's PKCS#11 support (``synta.pkcs11`` management API and
``synta.PrivateKey.from_pkcs11_uri()`` for signing), which drives tokens
via OpenSSL's pkcs11-provider.
"""

import hashlib
import logging
import os
import re
import subprocess
import tempfile
import threading
from typing import Optional, Dict, Any, List

import synta

from ipalib import errors
from ipacta.exceptions import CAConfigurationError
from ipacta.key_utils import generate_private_key, DEFAULT_RSA_KEY_SIZE

logger = logging.getLogger(__name__)

_PIN_VALUE_RE = re.compile(r'(?<=\?|&)pin-value=[^&]*', re.IGNORECASE)


def _sanitize_uri(uri: str) -> str:
    """Return a PKCS#11 URI with any pin-value= component replaced by '***'.

    Use this whenever a URI needs to appear in a log message or exception
    string to avoid leaking the HSM PIN into log files.
    """
    return _PIN_VALUE_RE.sub("pin-value=***", uri)


try:
    import synta.pkcs11 as _pkcs11

    _PKCS11_AVAILABLE = True
except ImportError:
    _pkcs11 = None  # type: ignore[assignment]
    _PKCS11_AVAILABLE = False
    logger.warning(
        "synta.pkcs11 not available — HSM support disabled. "
        "Upgrade synta to a version that includes the pkcs11-mgmt feature."
    )


class HSMConfig:
    """HSM Configuration"""

    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        config = config_dict or {}

        # PKCS#11 library path (e.g., /usr/lib64/pkcs11/libsofthsm2.so)
        self.pkcs11_library = config.get(
            "pkcs11_library", "/usr/lib64/pkcs11/libsofthsm2.so"
        )

        # Slot label (used in PKCS#11 URIs)
        self.slot_label = config.get("slot_label", "IPA-CA")

        # Token PIN (required — no insecure default)
        self.token_pin = config.get("token_pin")
        if not self.token_pin:
            raise CAConfigurationError(
                "HSM token_pin must be explicitly configured"
            )

        # Key label prefix
        self.key_label_prefix = config.get("key_label_prefix", "ipa-ca")

    def validate(self) -> bool:
        if not os.path.exists(self.pkcs11_library):
            logger.error("PKCS#11 library not found: %s", self.pkcs11_library)
            return False
        if not self.slot_label:
            logger.error("slot_label must be specified")
            return False
        return True


class HSMKeyBackend:
    """HSM Key Backend

    Manages CA private keys stored in Hardware Security Modules via synta's
    PKCS#11 management API.  Signing is handled separately by
    :class:`HSMPrivateKeyProxy`.
    """

    def __init__(self, config: HSMConfig):
        self.config = config

        if not self.config.validate():
            raise CAConfigurationError("Invalid HSM configuration")

        if not _PKCS11_AVAILABLE:
            raise errors.DependencyError(
                error=(
                    "synta.pkcs11 is not available. "
                    "Upgrade synta to enable HSM support."
                )
            )

        token_uri = (
            f"pkcs11:token={self.config.slot_label}"
            f"?pin-value={self.config.token_pin}"
        )
        try:
            self.token = _pkcs11.Pkcs11Token(  # pylint: disable=no-member
                token_uri, self.config.pkcs11_library
            )
        except ValueError as e:
            safe_msg = _sanitize_uri(str(e))
            raise errors.CertificateOperationError(
                error=f"Failed to load PKCS#11 library: {safe_msg}"
            ) from e

        # Verify the named token is present and accessible.
        try:
            slots = _pkcs11.list_slots(  # pylint: disable=no-member
                module=self.config.pkcs11_library
            )
        except ValueError as e:
            raise errors.CertificateOperationError(
                error=f"Failed to enumerate HSM slots: {e}"
            ) from e
        found = any(
            s.token_label == self.config.slot_label for s in slots
        )
        if not found:
            labels = [s.token_label for s in slots]
            raise errors.NotFound(
                reason=(
                    f"No HSM token with label '{self.config.slot_label}' "
                    f"found; available: {labels}"
                )
            )
        logger.info(
            "HSM token '%s' found via %s",
            self.config.slot_label,
            self.config.pkcs11_library,
        )

    def _make_key_uri(self, key_label: str) -> str:
        """Build a PKCS#11 URI identifying a private key on this token."""
        return (
            f"pkcs11:token={self.config.slot_label}"
            f";object={key_label}"
            f";type=private"
            f"?pin-value={self.config.token_pin}"
        )

    def _import_pkcs8_key(self, key_label: str, pkcs8_der: bytes) -> None:
        """Import a PKCS#8 DER key into SoftHSM2 via softhsm2-util.

        Used as a fallback for ML-DSA when the token does not support
        native key generation (PKCS#11 3.0 ``CKK_ML_DSA`` is not yet
        universal).  A software key is generated by synta and imported
        as a persistent token object.  SoftHSM2-specific.

        Note: softhsm2-util does not support reading the PIN from a file
        or via stdin; the ``--pin`` argument is required.  This exposes the
        PIN in ``/proc/<pid>/cmdline`` for the subprocess duration.  This
        path is only used during CA installation (not at runtime) and only
        with SoftHSM2 (not a real HSM).  Production deployments should use
        an HSM that supports native PKCS#11 3.0 ML-DSA key generation,
        which avoids this fallback entirely.
        """
        # Use mkstemp so that the file has mode 0600 from the start,
        # avoiding the TOCTOU window of NamedTemporaryFile + chmod.
        fd, tmp_path = tempfile.mkstemp(suffix=".pk8")
        os.chmod(tmp_path, 0o600)
        try:
            os.write(fd, pkcs8_der)
            os.close(fd)
            fd = -1

            # Derive a unique CKA_ID from the key label so that multiple
            # ML-DSA keys on the same token do not collide.
            key_id = hashlib.sha1(
                key_label.encode(), usedforsecurity=False
            ).hexdigest()[:8]

            cmd = [
                "softhsm2-util",
                "--import", tmp_path,
                "--token", self.config.slot_label,
                "--label", key_label,
                "--id", key_id,
                "--pin", self.config.token_pin,
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                raise errors.CertificateOperationError(
                    error=(
                        f"softhsm2-util --import failed for key "
                        f"{key_label!r}: {result.stderr.strip()}"
                    )
                )
            logger.info("Imported PKCS#8 key into HSM: %s", key_label)
        finally:
            if fd != -1:
                os.close(fd)
            os.unlink(tmp_path)

    def generate_key_pair(
        self,
        key_label: str,
        key_size: int = DEFAULT_RSA_KEY_SIZE,
        signing_alg: str = "SHA256withRSA",
    ) -> None:
        """Generate (or import) a key pair on the HSM token.

        For RSA and EC, the key pair is generated directly on-token via
        PKCS#11 ``C_GenerateKeyPair``.  For ML-DSA, native on-token
        generation is attempted first (requires PKCS#11 3.0); if the HSM
        does not support it, the key is generated in software by synta and
        imported via ``softhsm2-util`` (SoftHSM2 only).

        Args:
            key_label:   Label for the key on the HSM token.
            key_size:    RSA key size in bits (ignored for EC and ML-DSA).
            signing_alg: PKI signing algorithm (e.g. ``"ML-DSA-65"``).
        """
        alg_upper = signing_alg.upper()
        logger.info(
            "Generating %s key pair on HSM with label: %s",
            signing_alg,
            key_label,
        )

        if "ML-DSA" in alg_upper or "MLDSA" in alg_upper:
            for param_set in ("ML-DSA-87", "ML-DSA-65", "ML-DSA-44"):
                if param_set in alg_upper:
                    break
            else:
                raise ValueError(
                    f"Unknown ML-DSA parameter set: {signing_alg!r}"
                )
            try:
                self.token.generate_key_pair("ml-dsa", param_set, key_label)
                logger.info(
                    "Generated ML-DSA key natively on HSM: %s", key_label
                )
                return
            except ValueError:
                logger.warning(
                    "HSM token '%s' does not support native ML-DSA key "
                    "generation (requires PKCS#11 3.0); falling back to "
                    "software generation and import via softhsm2-util for "
                    "key '%s'. Key material will briefly exist in process "
                    "memory.",
                    self.config.slot_label,
                    key_label,
                )
            soft_key = generate_private_key(signing_alg, 0)
            self._import_pkcs8_key(key_label, soft_key.to_der())
            return

        try:
            if "EC" in alg_upper or "ECDSA" in alg_upper:
                self.token.generate_key_pair("ec", "P-256", key_label)
            else:
                self.token.generate_key_pair("rsa", key_size, key_label)
        except ValueError as e:
            raise errors.CertificateOperationError(
                error=f"Failed to generate key pair on HSM: {e}"
            ) from e

        logger.info(
            "Generated %s key pair on HSM: %s", signing_alg, key_label
        )

    def find_key(self, key_label: str) -> bool:
        """Return True if a private key with this label exists on the token.

        Raises:
            errors.CertificateOperationError: On HSM communication failure.
        """
        try:
            return self.token.find_key(self._make_key_uri(key_label))
        except ValueError as e:
            raise errors.CertificateOperationError(
                error=f"Error finding key '{key_label}' in HSM: {e}"
            ) from e

    def delete_key(self, key_label: str) -> None:
        """Destroy the named private key (and its public key) from the token."""
        logger.info("Deleting key from HSM: %s", key_label)
        try:
            self.token.delete_key(self._make_key_uri(key_label))
            logger.info("Deleted key from HSM: %s", key_label)
        except ValueError as e:
            raise errors.CertificateOperationError(
                error=f"Failed to delete key from HSM: {e}"
            ) from e

    def list_keys(self) -> List[str]:
        """Return labels of all private keys on this token.

        Raises:
            errors.CertificateOperationError: On HSM communication failure.
        """
        try:
            return [k.label for k in self.token.list_keys()]
        except ValueError as e:
            raise errors.CertificateOperationError(
                error=f"Failed to list keys in HSM: {e}"
            ) from e

    def close(self) -> None:
        """No-op: synta manages PKCS#11 sessions per-operation."""


class HSMPrivateKeyProxy:
    """Proxy for an HSM-backed private key using synta's PKCS#11 URI support.

    Signing is delegated to :func:`synta.PrivateKey.from_pkcs11_uri` which
    loads the key from the token via OpenSSL's pkcs11-provider.  This handles
    all key types (RSA, EC, ML-DSA) transparently without hard-coded PKCS#11
    mechanisms.

    Key generation is handled by :class:`HSMKeyBackend`; this class only
    manages the signing interface.
    """

    def __init__(self, hsm_backend: HSMKeyBackend, key_label: str):
        self.hsm_backend = hsm_backend
        self.key_label = key_label
        self._synta_key: Optional[synta.PrivateKey] = None
        self._public_key_cache: Optional[synta.PublicKey] = None
        self._key_lock = threading.Lock()

    def _load_key(self) -> synta.PrivateKey:
        """Load the key from the HSM via synta PKCS#11 URI (lazy, cached)."""
        with self._key_lock:
            if self._synta_key is None:
                slot_label = self.hsm_backend.config.slot_label
                pin = self.hsm_backend.config.token_pin
                uri = (
                    f"pkcs11:token={slot_label}"
                    f";object={self.key_label}"
                    f";type=private"
                    f"?pin-value={pin}"
                )
                logger.debug(
                    "Loading HSM key via PKCS#11 URI for label: %s",
                    self.key_label,
                )
                try:
                    self._synta_key = synta.PrivateKey.from_pkcs11_uri(uri)
                except Exception as e:
                    # Sanitise the error message: synta may echo the URI back
                    # in the exception string, which would expose pin-value=.
                    safe_msg = _sanitize_uri(str(e))
                    raise errors.CertificateOperationError(
                        error=(
                            f"Failed to load HSM key '{self.key_label}': "
                            f"{safe_msg}"
                        )
                    ) from e
            return self._synta_key

    def sign(
        self,
        data: bytes,
        hash_algorithm: Optional[str] = None,
        context: Optional[bytes] = None,
    ) -> bytes:
        """Sign data using the HSM key.

        Delegates to synta, which selects the correct PKCS#11 mechanism for
        the key type.  Pass ``hash_algorithm=None`` for ML-DSA (no pre-hash).
        ``context`` is the ML-DSA domain-separation string (FIPS 204).
        """
        return self._load_key().sign(data, hash_algorithm, context)

    @property
    def public_key(self) -> synta.PublicKey:
        """Extract the public key from the HSM-loaded key."""
        if self._public_key_cache is None:
            self._public_key_cache = self._load_key().public_key
        return self._public_key_cache

    @property
    def key_size(self) -> Optional[int]:
        """Key size in bits, or None for ML-DSA and Ed* keys."""
        return self._load_key().key_size


_HSM_BACKEND = None
_HSM_BACKEND_LOCK = threading.Lock()


def get_hsm_backend(config: HSMConfig = None) -> Optional[HSMKeyBackend]:
    """Get or create the module-level HSMKeyBackend singleton.

    Returns None if no config is provided (HSM not configured).
    Raises on initialization failure so the caller gets a precise error.
    """
    global _HSM_BACKEND  # pylint: disable=global-statement

    with _HSM_BACKEND_LOCK:
        if _HSM_BACKEND is None and config:
            _HSM_BACKEND = HSMKeyBackend(config)
            logger.info("HSM backend initialized")

        return _HSM_BACKEND


def is_hsm_available() -> bool:
    """Return True if synta.pkcs11 is importable and HSM support is enabled."""
    return _PKCS11_AVAILABLE


def list_pkcs11_slots(library_path: str) -> List[Dict[str, Any]]:
    """List all PKCS#11 token slots for the given library.

    Args:
        library_path: Path to the PKCS#11 shared library.

    Returns:
        List of slot-info dicts (slot_id, token_label, manufacturer_id,
        model, serial_number, flags).
    """
    if not _PKCS11_AVAILABLE:
        raise errors.DependencyError(
            error=(
                "synta.pkcs11 is not available. "
                "Upgrade synta to enable HSM support."
            )
        )
    try:
        slots = _pkcs11.list_slots(  # pylint: disable=no-member
            module=library_path
        )
    except ValueError as e:
        raise CAConfigurationError(
            f"Failed to list PKCS#11 slots: {e}"
        ) from e

    return [
        {
            "slot_id": s.slot_id,
            "token_label": s.token_label,
            "manufacturer_id": s.manufacturer_id,
            "model": s.model,
            "serial_number": s.serial_number,
            "flags": s.flags,
        }
        for s in slots
    ]


def get_hsm_info(
    library_path: str,
    slot_id: Optional[int] = None,
    slot_label: Optional[str] = None,
) -> Dict[str, Any]:
    """Return information about a specific HSM token.

    Searches by ``slot_id`` or ``slot_label``; at least one must be given.

    Args:
        library_path: Path to the PKCS#11 shared library.
        slot_id:      Numeric slot ID (searched first if provided).
        slot_label:   Token label (used when slot_id is None).

    Returns:
        Dict with library_path, slot_id, token_label, manufacturer_id,
        model, serial_number, flags.
    """
    if not _PKCS11_AVAILABLE:
        raise errors.DependencyError(
            error=(
                "synta.pkcs11 is not available. "
                "Upgrade synta to enable HSM support."
            )
        )
    if slot_id is None and not slot_label:
        raise ValueError("Either slot_id or slot_label must be provided")

    try:
        slots = _pkcs11.list_slots(  # pylint: disable=no-member
            module=library_path
        )
    except ValueError as e:
        raise CAConfigurationError(
            f"Failed to enumerate HSM slots: {e}"
        ) from e

    for s in slots:
        if (slot_id is not None and s.slot_id == slot_id) or (
            slot_label and s.token_label == slot_label
        ):
            return {
                "library_path": library_path,
                "slot_id": s.slot_id,
                "token_label": s.token_label,
                "manufacturer_id": s.manufacturer_id,
                "model": s.model,
                "serial_number": s.serial_number,
                "flags": s.flags,
            }

    raise CAConfigurationError(
        f"No HSM slot found matching slot_id={slot_id!r} or "
        f"slot_label={slot_label!r}"
    )
