"""
This module contains concrete implementations using liboqs-python.

https://github.com/open-quantum-safe/liboqs-python

Private and Public Key classes implementing ML-KEM-{512, 768, 1024} are provided.
"""

from typing import ClassVar, Self

import oqs

from ..exceptions import CryptographicValueError
from ..types import BytesLike
from .base import BaseKEMPrivateKey, BaseKEMPublicKey


class _BaseOQSKEMPrivateKey(BaseKEMPrivateKey):
    """
    Base class for ML-KEM private keys.

    liboqs does not expose a method to extract the public key bytes from private key bytes,
    even though the public key is simply concatenated into the private key,
    so this class stores both public key bytes separately. 
    """
    _algorithm: ClassVar[str]

    def __init__(self, kem: oqs.KeyEncapsulation, public_key_bytes: bytes) -> None:
        super().__init__()
        self._kem = kem
        self._public_key_bytes = public_key_bytes

    @classmethod
    def generate_key(cls) -> Self:
        kem = oqs.KeyEncapsulation(cls._algorithm)
        try:
            public_key_bytes = kem.generate_keypair()
        except RuntimeError:
            raise CryptographicValueError('Cannot generate keypair')
        return cls(kem, public_key_bytes)
    
    def get_public_key_bytes(self) -> BytesLike:
        return self._public_key_bytes
    
    def decapsulate(self, ciphertext: BytesLike) -> BytesLike:
        try:
            return self._kem.decap_secret(bytes(ciphertext))
        except RuntimeError:
            raise CryptographicValueError('Decapsulation failed')
        
    @classmethod
    def from_seed(cls, seed: BytesLike) -> Self:
        kem = oqs.KeyEncapsulation(cls._algorithm)
        try:
            public_key_bytes = kem.generate_keypair_seed(bytes(seed))
        except (RuntimeError, ValueError):
            raise CryptographicValueError('Cannot generate keypair from seed')
        return cls(kem, public_key_bytes)


class _BaseOQSKEMPublicKey(BaseKEMPublicKey):
    """
    Base class for ML-KEM public keys.
    """
    _algorithm: ClassVar[str]

    def __init__(self, public_key_bytes: bytes) -> None:
        super().__init__()
        self._public_key_bytes = public_key_bytes
        self._kem = oqs.KeyEncapsulation(self._algorithm)
    
    @classmethod
    def from_bytes(cls, public_key_bytes: BytesLike) -> Self:
        return cls(public_key_bytes)
    
    def to_bytes(self) -> BytesLike:
        return self._public_key_bytes
    
    def encapsulate(self) -> tuple[BytesLike, BytesLike]:
        try:
            ciphertext, shared_secret = self._kem.encap_secret(bytes(self._public_key_bytes))
            return ciphertext, shared_secret
        except RuntimeError:
            raise CryptographicValueError('Encapsulation failed')


def _make_classes(algorithm: str) -> tuple[type[_BaseOQSKEMPrivateKey], type[_BaseOQSKEMPublicKey]]:
    kem = oqs.KeyEncapsulation(algorithm)

    algorithm_short_name = algorithm.replace('-', '')
    private_class_name = f'{algorithm_short_name}PrivateKey'
    public_class_name = f'{algorithm_short_name}PubliceKey'

    private_class = type(
        private_class_name,
        (_BaseOQSKEMPrivateKey,),
        {
            '_algorithm': algorithm,
            'private_key_length': kem.length_secret_key,
            'ciphertext_length': kem.length_ciphertext,
        }
    )

    public_class = type(
        public_class_name,
        (_BaseOQSKEMPublicKey,),
        {
            '_algorithm': algorithm,
            'public_key_length': kem.length_public_key,
            'ciphertext_length': kem.length_ciphertext,
        }
    )

    return private_class, public_class


MLKEM512PrivateKey, MLKEM512PublicKey = _make_classes('ML-KEM-512')
MLKEM768PrivateKey, MLKEM768PublicKey = _make_classes('ML-KEM-768')
MLKEM1024PrivateKey, MLKEM1024PublicKey = _make_classes('ML-KEM-1024')