"""
This module contains concrete implementations using alkindi.

https://github.com/alraddady/alkindi

Private and Public Key classes implementing ML-KEM-{512, 768, 1024} are provided.
"""


from typing import ClassVar, Self

import alkindi

from ..exceptions import CryptographicValueError
from ..types import BytesLike
from .base import BaseKEMPrivateKey, BaseKEMPublicKey


class _BaseAlkindiMLKEMPrivateKey(BaseKEMPrivateKey):
    """
    Base class for private keys.

    Alkindi does not expose algorithm parameters such as key lengths,
    so these class variables are hardcoded in subclasses.

    Alkindi also does not expose a method to extract the public key bytes from private key bytes,
    even though the public key is simply concatenated into the private key,
    so this class stores both private and public key bytes.
    """
    _algorithm: ClassVar[str]

    def __init__(self, private_key_bytes: bytes, public_key_bytes: bytes) -> None:
        super().__init__()
        self._private_key_bytes = private_key_bytes
        self._public_key_bytes = public_key_bytes
    
    @classmethod
    def generate_key(cls) -> Self:
        keypair = alkindi.KEM.generate_keypair(cls._algorithm)
        return cls(keypair.private_key, keypair.public_key)
    
    def get_public_key_bytes(self) -> BytesLike:
        return self._public_key_bytes
    
    def decapsulate(self, ciphertext: BytesLike) -> BytesLike:
        try:
            return alkindi.KEM.decapsulate(self._algorithm, self._private_key_bytes, bytes(ciphertext))
        except alkindi.OpenSSLError:
            raise CryptographicValueError('Decapsulation failed')


class _BaseAlkindiMLKEMPublicKey(BaseKEMPublicKey):
    """
    Base class for public keys.

    Notes from _BaseAlkindiMLKEMPrivateKey also apply.
    """
    _algorithm: ClassVar[str]

    def __init__(self, public_key_bytes: bytes) -> None:
        super().__init__()
        self._public_key_bytes = public_key_bytes
    
    @classmethod
    def from_bytes(cls, public_key_bytes: BytesLike) -> Self:
        return cls(bytes(public_key_bytes))
    
    def to_bytes(self) -> BytesLike:
        return self._public_key_bytes
    
    def encapsulate(self) -> tuple[BytesLike, BytesLike]:
        try:
            ciphertext, shared_secret = alkindi.KEM.encapsulate(self._algorithm, self._public_key_bytes)
            return ciphertext, shared_secret
        except alkindi.OpenSSLError:
            raise CryptographicValueError('Encapsulation failed')


class MLKEM512PrivateKey(_BaseAlkindiMLKEMPrivateKey):
    _algorithm = 'ML-KEM-512'
    private_key_length = 1632
    ciphertext_length = 768


class MLKEM512PublicKey(_BaseAlkindiMLKEMPublicKey):
    _algorithm = 'ML-KEM-512'
    public_key_length = 800
    ciphertext_length = 768


class MLKEM768PrivateKey(_BaseAlkindiMLKEMPrivateKey):
    _algorithm = 'ML-KEM-768'
    private_key_length = 2400
    ciphertext_length = 1088


class MLKEM768PublicKey(_BaseAlkindiMLKEMPublicKey):
    _algorithm = 'ML-KEM-768'
    public_key_length = 1184
    ciphertext_length = 1088


class MLKEM1024PrivateKey(_BaseAlkindiMLKEMPrivateKey):
    _algorithm = 'ML-KEM-1024'
    private_key_length = 3168
    ciphertext_length = 1568


class MLKEM1024PublicKey(_BaseAlkindiMLKEMPublicKey):
    _algorithm = 'ML-KEM-1024'
    public_key_length = 1568
    ciphertext_length = 1568