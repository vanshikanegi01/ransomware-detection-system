"""AES-256-GCM authenticated encryption engine for protected vault storage.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

NONCE_SIZE = 12  # Standard 96-bit nonce for AES-GCM
KEY_SIZE_BYTES = 32  # 256-bit AES key


class EncryptionError(Exception):
    """Base exception for encryption and decryption errors."""


class DecryptionIntegrityError(EncryptionError):
    """Raised when ciphertext authentication tag validation fails (tampering/corruption)."""


def generate_aes_key() -> bytes:
    """Generate a cryptographically secure 256-bit (32-byte) AES key.

    Returns:
        32 random bytes from os.urandom.
    """
    return AESGCM.generate_key(bit_length=256)


def derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derive a 256-bit AES key from a passphrase and salt using PBKDF2-HMAC-SHA256.

    NOTE: For development and testing only. Production deployments should use
    hardware security modules (HSM), secure key management services (KMS),
    or OS-level secure storage (e.g., Windows DPAPI).

    Args:
        passphrase: Secret passphrase string.
        salt: Minimum 16-byte cryptographic salt.
        iterations: Number of PBKDF2 iterations (default 100,000).

    Returns:
        32-byte derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_bytes(data: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Encrypt raw byte data using AES-256-GCM authenticated encryption.

    The output format prepends the 12-byte random nonce to the authenticated ciphertext.

    Args:
        data: Plaintext data bytes.
        key: 32-byte AES-256 key.
        associated_data: Optional authenticated metadata (AAD).

    Returns:
        Combined byte string: `nonce (12 bytes) + ciphertext + auth_tag (16 bytes)`.

    Raises:
        ValueError: If the key length is not exactly 32 bytes.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 requires a 32-byte key; received {len(key)} bytes.")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)
    return nonce + ciphertext


def decrypt_bytes(payload: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Decrypt and authenticate an AES-256-GCM encrypted payload.

    Args:
        payload: Combined `nonce (12 bytes) + ciphertext + auth_tag`.
        key: 32-byte AES-256 key.
        associated_data: Optional authenticated metadata that was supplied during encryption.

    Returns:
        Decrypted plaintext byte string.

    Raises:
        ValueError: If key or payload length is invalid.
        DecryptionIntegrityError: If authentication tag verification fails (tampered data or wrong key).
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 requires a 32-byte key; received {len(key)} bytes.")

    if len(payload) < NONCE_SIZE + 16:  # 12-byte nonce + 16-byte minimum GCM tag
        raise DecryptionIntegrityError("Ciphertext payload is truncated or too short for AES-GCM.")

    nonce = payload[:NONCE_SIZE]
    ciphertext = payload[NONCE_SIZE:]
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as e:
        raise DecryptionIntegrityError(
            "AES-256-GCM authentication failed: data corrupted, tampered, or invalid key."
        ) from e


def encrypt_file(
    source_path: Union[str, Path],
    dest_path: Union[str, Path],
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> None:
    """Encrypt a file from disk and write the protected payload to destination.

    Args:
        source_path: Path to plaintext source file.
        dest_path: Target path in protected vault.
        key: 32-byte AES-256 key.
        associated_data: Optional authenticated metadata.
    """
    src = Path(source_path)
    dst = Path(dest_path)

    if not src.is_file():
        raise FileNotFoundError(f"Source file not found for encryption: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)
    plaintext = src.read_bytes()
    encrypted_data = encrypt_bytes(plaintext, key, associated_data=associated_data)
    dst.write_bytes(encrypted_data)


def decrypt_file(
    source_path: Union[str, Path],
    dest_path: Union[str, Path],
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> None:
    """Decrypt a protected vault file and write the restored plaintext to destination.

    Args:
        source_path: Path to encrypted vault file.
        dest_path: Target destination path for restored plaintext.
        key: 32-byte AES-256 key.
        associated_data: Optional authenticated metadata.
    """
    src = Path(source_path)
    dst = Path(dest_path)

    if not src.is_file():
        raise FileNotFoundError(f"Encrypted vault file not found: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)
    payload = src.read_bytes()
    plaintext = decrypt_bytes(payload, key, associated_data=associated_data)
    dst.write_bytes(plaintext)
