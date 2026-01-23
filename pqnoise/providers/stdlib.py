"""
This module contains concrete implementations using Python's standard library.

Classes in this module only has hashing and HKDF related functions.
They can be combined with AEAD mix-in classes to become a fully concrete provider.
"""
import hashlib
import hmac

from .base import BaseProvider, BaseKEMPrivateKey, BaseKEMPublicKey
from ..types import BytesLike


class StdLibHashProviderMixIn:
    """
    A mix-in class providing hashing and HKDF functions.

    Subclasses should override _hash_algorithm_name and _hash_length,
    either as class or instance variables.
    """
    _hash_algorithm_name: str
    _hash_length: int
    
    @property
    def hash_length(self) -> int:
        return self._hash_length
    
    def hash(self, data: BytesLike) -> BytesLike:
        return hashlib.new(self._hash_algorithm_name, data).digest()
    
    def _hkdf(self, salt: BytesLike, input_key_material: BytesLike, num_output: int):
        prk = hmac.new(salt, input_key_material, self._hash_algorithm_name).digest()
        output_key_material = []
        t = b''
        for i in range(1, num_output+1):
            t = hmac.new(prk, t + i.to_bytes(1, 'big'), self._hash_algorithm_name).digest()
            output_key_material.append(t)
        return output_key_material
    
    def hkdf_double(self, chaining_key: bytes, input_key_material: BytesLike) -> tuple[BytesLike, BytesLike]:
        return tuple(self._hkdf(chaining_key, input_key_material, 2))
    
    def hkdf_triple(self, chaining_key: bytes, input_key_material: BytesLike) -> tuple[BytesLike, BytesLike, BytesLike]:
        return tuple(self._hkdf(chaining_key, input_key_material, 3))


class BaseStdLibHashProvider(StdLibHashProviderMixIn, BaseProvider):
    """
    A base class for provider.

    This class does not include implemenatation of AEAD encryption.
    Remember to add a mix-in class for that.
    """
    def __init__(
            self,
            hash_algorithm_name: str,
            ephemeral_private_key_type: type[BaseKEMPrivateKey],
            ephemeral_public_key_type: type[BaseKEMPublicKey],
            initiator_private_key_type: type[BaseKEMPrivateKey],
            initiator_public_key_type: type[BaseKEMPublicKey],
            responder_private_key_type: type[BaseKEMPrivateKey],
            responder_public_key_type: type[BaseKEMPublicKey],

    ) -> None:
        super().__init__()
        self._hash_algorithm_name = hash_algorithm_name
        self._ephemeral_private_key_type = ephemeral_private_key_type
        self._ephemeral_public_key_type = ephemeral_public_key_type
        self._initiator_private_key_type = initiator_private_key_type
        self._initiator_public_key_type = initiator_public_key_type
        self._responder_private_key_type = responder_private_key_type
        self._responder_public_key_type = responder_public_key_type

        self._hash_length = hashlib.new(hash_algorithm_name).digest_size
    
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
