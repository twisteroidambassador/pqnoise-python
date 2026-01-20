"""
This module contains concrete implementations using wolfcrypt.

https://github.com/wolfSSL/wolfcrypt-py/

WIP
"""

from typing import ClassVar, Self

import wolfcrypt.ciphers

from .base import BaseKEMPrivateKey, BaseKEMPublicKey, BaseProvider
from ..types import BytesLike


class _BaseMLKEMPrivateKey(BaseKEMPrivateKey):
    _ml_kem_type: ClassVar[wolfcrypt.ciphers.MlKemType]

    def __init__(self, private_key_obj: wolfcrypt.ciphers.MlKemPrivate | None = None) -> None:
        super().__init__()
        if private_key_obj is None:
            private_key_obj = wolfcrypt.ciphers.MlKemPrivate(self._ml_kem_type)
        self._private_key_obj = private_key_obj
    
    @classmethod
    def generate_key(cls) -> Self:
        private_key_obj = wolfcrypt.ciphers.MlKemPrivate.make_key(cls._ml_kem_type)
        return cls(private_key_obj)
    
    def get_public_key_bytes(self) -> BytesLike:
        return self._private_key_obj.encode_pub_key()
    
    def decapsulate(self, ciphertext: BytesLike) -> BytesLike:
        ciphertext = bytes(ciphertext)
        return self._private_key_obj.decapsulate(ciphertext)


class _BaseMLKEMPublicKey(BaseKEMPublicKey):
    _ml_kem_type: ClassVar[wolfcrypt.ciphers.MlKemType]

    def __init__(self, public_key_obj: wolfcrypt.ciphers.MlKemPublic | None = None) -> None:
        super().__init__()
        if public_key_obj is None:
            public_key_obj = wolfcrypt.ciphers.MlKemPublic(self._ml_kem_type)
        self._public_key_obj = public_key_obj
    
    @classmethod
    def from_bytes(cls, public_key_bytes: BytesLike) -> Self:
        instance = cls()
        instance._public_key_obj.decode_key(bytes(public_key_bytes))
        return instance
    
    def to_bytes(self) -> BytesLike:
        return self._public_key_obj.encode_key()
    
    def encapsulate(self) -> tuple[BytesLike, BytesLike]:
        shared_secret, ciphertext = self._public_key_obj.encapsulate()
        return ciphertext, shared_secret


def _make_classes(ml_kem_type: wolfcrypt.ciphers.MlKemType, name_infix: str) -> tuple[type[_BaseMLKEMPrivateKey], type[_BaseMLKEMPublicKey]]:
    private_class_name = f'MLKEM{name_infix}PrivateKey'
    private_obj = wolfcrypt.ciphers.MlKemPrivate(ml_kem_type)
    private_class = type(
        private_class_name,
        (_BaseMLKEMPrivateKey,),
        {
            'private_key_length': private_obj.priv_key_size,
            'ciphertext_length': private_obj.ct_size,
        }
    )

    public_class_name = f'MLKEM{name_infix}PublicKey'
    public_obj = wolfcrypt.ciphers.MlKemPublic(ml_kem_type)
    public_class = type(
        public_class_name,
        (_BaseMLKEMPublicKey,),
        {
            'public_key_length': public_obj.key_size,
            'ciphertext_length': public_obj.ct_size,
        }
    )

    return private_class, public_class


MLKEM512PrivateKey, MLKEM512PublicKey = _make_classes(wolfcrypt.ciphers.MlKemType.ML_KEM_512, '512')
MLKEM768PrivateKey, MLKEM768PublicKey = _make_classes(wolfcrypt.ciphers.MlKemType.ML_KEM_768, '768')
MLKEM1024PrivateKey, MLKEM1024PublicKey = _make_classes(wolfcrypt.ciphers.MlKemType.ML_KEM_1024, '1024')


