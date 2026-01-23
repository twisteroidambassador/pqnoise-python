"""
This module contains concrete implementations using pynacl.

https://github.com/pyca/pynacl

AEAD encryption mix-in classes are included.
They can be combined with e.g. the stdlib provider class to create a fully concrete provider.
"""

from nacl.exceptions import CryptoError
from nacl.bindings import (
    crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_aes256gcm_encrypt,
    crypto_aead_aes256gcm_decrypt,
)

from ..exceptions import CryptographicValueError
from ..types import BytesLike


class ChaCha20Poly1305MixIn:
    """
    Mix-in class for ChaCha20Poly1305 AEAD encryption.
    """
    def _aead_format_nonce(self, nonce: int) -> bytes:
        return bytes(4) + nonce.to_bytes(8, 'little')

    def aead_encrypt(self, key: bytes, nonce: int, associated_data: BytesLike, plaintext: BytesLike) -> BytesLike:
        try:
            return crypto_aead_chacha20poly1305_ietf_encrypt(
                bytes(plaintext),
                bytes(associated_data),
                self._aead_format_nonce(nonce),
                key,
            )
        except (ValueError, CryptoError):
            raise CryptographicValueError('Encryption failed')
    
    def aead_decrypt(self, key: bytes, nonce: int, associated_data: BytesLike, ciphertext: BytesLike) -> BytesLike:
        try:
            return crypto_aead_chacha20poly1305_ietf_decrypt(
                bytes(ciphertext),
                bytes(associated_data),
                self._aead_format_nonce(nonce),
                key,
            )
        except (ValueError, CryptoError):
            raise CryptographicValueError('Tag verification failed')


class AES256GCMMixIn:
    """
    Mix-in class for AES-256-GCM AEAD encryption.
    """
    def _aead_format_nonce(self, nonce: int) -> bytes:
        return nonce.to_bytes(12, 'big')

    def aead_encrypt(self, key: bytes, nonce: int, associated_data: BytesLike, plaintext: BytesLike) -> BytesLike:
        try:
            return crypto_aead_aes256gcm_encrypt(
                bytes(plaintext),
                bytes(associated_data),
                self._aead_format_nonce(nonce),
                key,
            )
        except (ValueError, CryptoError):
            raise CryptographicValueError('Encryption failed')
    
    def aead_decrypt(self, key: bytes, nonce: int, associated_data: BytesLike, ciphertext: BytesLike) -> BytesLike:
        try:
            return crypto_aead_aes256gcm_decrypt(
                bytes(ciphertext),
                bytes(associated_data),
                self._aead_format_nonce(nonce),
                key,
            )
        except (ValueError, CryptoError):
            raise CryptographicValueError('Tag verification failed')