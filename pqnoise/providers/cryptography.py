"""
This module contains concrete implementations using pyca/cryptography.

https://github.com/pyca/cryptography/

The Provider class, its AEAD encryption and hashing operations are included.
"""


from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.hashes import Hash, HashAlgorithm, SHA256, SHA512, BLAKE2s, BLAKE2b
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from ..exceptions import CryptographicValueError
from ..types import BytesLike
from .base import BaseProvider, BaseKEMPrivateKey, BaseKEMPublicKey



class BaseCryptographyProvider(BaseProvider):
    """
    Base class for provider.

    This class does not include implemenatation of AEAD encryption.
    Remember to add a mix-in class for that.
    """
    def __init__(
            self,
            hash_algorithm: HashAlgorithm,
            ephemeral_private_key_type: type[BaseKEMPrivateKey],
            ephemeral_public_key_type: type[BaseKEMPublicKey],
            initiator_private_key_type: type[BaseKEMPrivateKey],
            initiator_public_key_type: type[BaseKEMPublicKey],
            responder_private_key_type: type[BaseKEMPrivateKey],
            responder_public_key_type: type[BaseKEMPublicKey],

    ) -> None:
        super().__init__()
        self._hash_algorithm = hash_algorithm
        self._ephemeral_private_key_type = ephemeral_private_key_type
        self._ephemeral_public_key_type = ephemeral_public_key_type
        self._initiator_private_key_type = initiator_private_key_type
        self._initiator_public_key_type = initiator_public_key_type
        self._responder_private_key_type = responder_private_key_type
        self._responder_public_key_type = responder_public_key_type
    
    @property
    def hash_length(self) -> int:
        return self._hash_algorithm.digest_size
    
    @property
    def ephemeral_private_key_type(self) -> type[BaseKEMPrivateKey]:
        return self._ephemeral_private_key_type
    
    @property
    def ephemeral_public_key_type(self) -> type[BaseKEMPublicKey]:
        return self._ephemeral_public_key_type
    
    @property
    def initiator_static_private_key_type(self) -> type[BaseKEMPrivateKey]:
        return self._initiator_private_key_type
    
    @property
    def initiator_static_public_key_type(self) -> type[BaseKEMPublicKey]:
        return self._initiator_public_key_type
    
    @property
    def responder_static_private_key_type(self) -> type[BaseKEMPrivateKey]:
        return self._responder_private_key_type
    
    @property
    def responder_static_public_key_type(self) -> type[BaseKEMPublicKey]:
        return self._responder_public_key_type

    def hash(self, data: BytesLike) -> BytesLike:
        hash = Hash(self._hash_algorithm)
        hash.update(data)
        return hash.finalize()
    
    def hkdf_double(self, chaining_key: bytes, input_key_material: BytesLike) -> tuple[BytesLike, BytesLike]:
        hkdf = HKDF(
            self._hash_algorithm,
            2 * self._hash_algorithm.digest_size,
            chaining_key,
            None,
        )
        output = hkdf.derive(input_key_material)
        output_mv = memoryview(output)
        return output_mv[:self._hash_algorithm.digest_size], output_mv[self._hash_algorithm.digest_size:]
    
    def hkdf_triple(self, chaining_key: bytes, input_key_material: BytesLike) -> tuple[BytesLike, BytesLike, BytesLike]:
        hkdf = HKDF(
            self._hash_algorithm,
            3 * self._hash_algorithm.digest_size,
            chaining_key,
            None,
        )
        output = hkdf.derive(input_key_material)
        output_mv = memoryview(output)
        return (
            output_mv[:self._hash_algorithm.digest_size],
            output_mv[self._hash_algorithm.digest_size:2*self._hash_algorithm.digest_size],
            output_mv[2*self._hash_algorithm.digest_size:],
        )


class ChaCha20Poly1305MixIn:
    """
    Mix-in class for ChaCha20Poly1305 AEAD encryption.
    """
    def _aead_format_nonce(self, nonce: int) -> bytes:
        return bytes(4) + nonce.to_bytes(8, 'little')

    def aead_encrypt(self, key: bytes, nonce: int, associated_data: BytesLike, plaintext: BytesLike) -> BytesLike:
        chacha = ChaCha20Poly1305(key)
        try:
            return chacha.encrypt(
                self._aead_format_nonce(nonce),
                plaintext,
                associated_data
            )
        except OverflowError:
            raise CryptographicValueError('Plaintext too long')
    
    def aead_decrypt(self, key: bytes, nonce: int, associated_data: BytesLike, ciphertext: BytesLike) -> BytesLike:
        chacha = ChaCha20Poly1305(key)
        try:
            return chacha.decrypt(
                self._aead_format_nonce(nonce),
                ciphertext,
                associated_data,
            )
        except InvalidTag:
            raise CryptographicValueError('Tag verification failed')


class AESGCMMixIn:
    """
    Mix-in class for AES GCM AEAD encryption.
    """
    def _aead_format_nonce(self, nonce: int) -> bytes:
        return nonce.to_bytes(12, 'big')
    
    def aead_encrypt(self, key: bytes, nonce: int, associated_data: BytesLike, plaintext: BytesLike) -> BytesLike:
        aesgcm = AESGCM(key)
        try:
            return aesgcm.encrypt(
                self._aead_format_nonce(nonce),
                plaintext,
                associated_data
            )
        except OverflowError:
            raise CryptographicValueError('Plaintext too long')
    
    def aead_decrypt(self, key: bytes, nonce: int, associated_data: BytesLike, ciphertext: BytesLike) -> BytesLike:
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(
                self._aead_format_nonce(nonce),
                ciphertext,
                associated_data,
            )
        except InvalidTag:
            raise CryptographicValueError('Tag verification failed')


class ChaCha20Poly1305Provider(ChaCha20Poly1305MixIn, BaseCryptographyProvider):
    """
    This is an example class, showing how to create a concrete provider using ChaPoly encryption.
    """
    pass


class ChaPoly_SHA256_Provider(ChaCha20Poly1305Provider):
    """
    This is an example class, showing how to fix a hash choice into a concrete provider class.
    """
    def __init__(
            self,
            ephemeral_private_key_type: type[BaseKEMPrivateKey],
            ephemeral_public_key_type: type[BaseKEMPublicKey],
            initiator_private_key_type: type[BaseKEMPrivateKey],
            initiator_public_key_type: type[BaseKEMPublicKey],
            responder_private_key_type: type[BaseKEMPrivateKey],
            responder_public_key_type: type[BaseKEMPublicKey],
    ) -> None:
        super().__init__(
            SHA256(),
            ephemeral_private_key_type,
            ephemeral_public_key_type,
            initiator_private_key_type,
            initiator_public_key_type,
            responder_private_key_type,
            responder_public_key_type,
        )