"""
This module provides the (abstract) base classes for providers.

Providers are used by the various Noise state objects to carry out cryptographical operations.
The required operations are documented in these places:

The Noise Protocol Framework https://noiseprotocol.org/noise.html
This specifies everything except the KEM operations.

Post Quantum Noise https://eprint.iacr.org/2022/539
This specifies the KEM operations.

A concrete implementation should inherit from all classes in this module and override
all abstract methods and unspecified class variables.

When implementing, check the argument type hints,
and make sure to accept bytearrays and memoryviews where required (when BytesLike is specified).

This class does not specify an interface for SEEC as described in Post Quantum Noise,
but it should be possible to implement any relevant logic in the private and public key classes,
since these are the classes that deal with random inputs.
"""


from abc import ABC, abstractmethod
from typing import ClassVar, Self

from ..exceptions import PQNoiseError, CryptographicValueError
from ..types import BytesLike


class BaseKEMPrivateKey(ABC):
    """
    Represents a KEM private key.

    Implementations should inherit from this class and override all methods and class variables.
    
    Again, do remember to override the class variables!
    The state objects access these from the class, not instances.
    
    (Ideally, the class variables should have been abstract class properties, however chaining
    @classmethod and @property has been deprecated in Python 3.11, and writing a custom metaclass
    seems not worth the complexity.)

    This class only specifies operations used in PQNoise protocol handshakes,
    and additional methods may be required for other general usage,
    such as encoding private key to bytes, decoding private key from bytes, loading from file, etc.
    """

    """The length of a KEM private key in bytes."""
    private_key_length: ClassVar[int]  # override this in subclasses!

    """The length of a KEM ciphertext (encapsulating a shared secret) in bytes."""
    ciphertext_length: ClassVar[int]  # override this in subclasses!

    @classmethod
    @abstractmethod
    def generate_key(cls) -> Self:
        """
        Generate a fresh KEM key pair, represented by a private key object.
        
        :return: the private key instance.
        """
        raise NotImplementedError
    
    @abstractmethod
    def get_public_key_bytes(self) -> BytesLike:
        """
        Return the public key corresponding to this private key encoded in bytes.
        
        :return: the encoded public key
        """
        raise NotImplementedError
    
    @abstractmethod
    def decapsulate(self, ciphertext: BytesLike) -> BytesLike:
        """
        Decapsulate ciphertext using the private key to obtain a shared secret.
        
        :param ciphertext: the ciphertext.
        :raises CryptographicValueError: if decapsulation fails.
        :return: the shared secret.
        """
        raise NotImplementedError


class BaseKEMPublicKey(ABC):
    """
    Represents a KEM public key.

    Implementations should inherit from this class and override all methods and class variables.

    Notes on BaseKEMPrivateKey also apply.
    """

    """The length of a KEM public key in bytes."""
    public_key_length: ClassVar[int]  # override this in subclasses!

    """The length of a KEM ciphertext (encapsulating a shared secret) in bytes."""
    ciphertext_length: ClassVar[int]  # override this in subclasses!

    @classmethod
    @abstractmethod
    def from_bytes(cls, public_key_bytes: BytesLike) -> Self:
        """
        Load a public key from a bytes representation.
        
        :param public_key_bytes: the public key. Must have length cls.public_key_length.
        :raises CryptographicValueError: if public_key_bytes does not represent a valid public key.
        :return: the public key instance.
        """
        raise NotImplementedError
    
    @abstractmethod
    def to_bytes(self) -> BytesLike:
        """
        Return the public key encoded in bytes.
        
        :return: the encoded public key.
        """
        raise NotImplementedError
    
    @abstractmethod
    def encapsulate(self) -> tuple[BytesLike, BytesLike]:
        """
        Encapsulate a shared secret.
        
        :raises CryptographicValueError: if public key is invalid, encapsulation failed, etc.
        :return: tuple (ciphertext, shared secret)
        """
        raise NotImplementedError


class BaseProvider(ABC):
    """
    This class provides all cryptographic functions required by Post Quantum Noise protocol.

    Detailed requirements for the functions can be found in:

    The Noise Protocol Framework, Chapter 4 Crypto functions
    https://noiseprotocol.org/noise.html#crypto-functions

    Post Quantum Noise
    https://eprint.iacr.org/2022/539

    Implementations should inherit from this class and override unimplemented methods and unspecified class variables.
    """

    @property
    def max_nonce(self) -> int:
        """
        The maximum value of nonce.
        The nonce used in AEAD encryption must be smaller than this value.
        The rekey operations uses this value.
        """
        return 2 ** 64 - 1

    @property
    def aead_key_length(self) -> int:
        """
        The length of symmetric encryption key for the AEAD encryption / decryption in bytes.
        """
        return 32

    @property
    def aead_tag_lenth(self) -> int:
        """
        The length of the authentication tag in bytes.
        """
        return 16

    @property
    @abstractmethod
    def hash_length(self) -> int:
        """
        The length of hash function output in bytes.
        Noise Protocol specifications requires this to be either 32 or 64.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def ephemeral_private_key_type(self) -> type[BaseKEMPrivateKey]:
        """
        The type of private key used for ephemeral KEM operations.

        Remember to return the type, not an instance.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def ephemeral_public_key_type(self) -> type[BaseKEMPublicKey]:
        """
        The type of public key used for ephemeral KEM operations.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def initiator_static_private_key_type(self) -> type[BaseKEMPrivateKey]:
        """
        The type of private key used for static KEM operations by the initiator.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def initiator_static_public_key_type(self) -> type[BaseKEMPublicKey]:
        """
        The type of public key used for static KEM operations by the initiator.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def responder_static_private_key_type(self) -> type[BaseKEMPrivateKey]:
        """
        The type of private key used for static KEM operations by the responder.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def responder_static_public_key_type(self) -> type[BaseKEMPublicKey]:
        """
        The type of public key used for static KEM operations by the responder.
        """
        raise NotImplementedError
    
    @abstractmethod
    def aead_encrypt(self, key: bytes, nonce: int, associated_data: BytesLike, plaintext: BytesLike) -> BytesLike:
        """
        Encrypt plaintext using an AEAD scheme.
        
        :param key: the encryption key. Must be self.aed_key_length bytes long.
        :param nonce: the nonce. Must satify 0 <= nonce < self.max_nonce.
        :param associated_data: the associated data. Can be empty.
        :param plaintext: the plaintext to be encrypted. Can be empty.
        :return: the encrypted ciphertext + authentication tag. len(return_value) = len(plaintext) + self.aead_tag_length
        """
        raise NotImplementedError
    
    @abstractmethod
    def aead_decrypt(self, key: bytes, nonce: int, associated_data: BytesLike, ciphertext: BytesLike) -> BytesLike:
        """
        Decrypt ciphertext using an AEAD scheme. The inverse operation of self.aead_encrypt.
        
        :param key: the encryption key. Must be self.aed_key_length bytes long.
        :param nonce: the nonce. Must satify 0 <= nonce < self.max_nonce.
        :param associated_data: the associated data. Can be empty.
        :param ciphertext: the ciphertext + authentication tag. Must be at least sele.aead_tag_length long.
        :raises CryptographicValueError: if authentication tag fails to validate or ciphertext too short to contain tag.
        :return: the decrypted plaintext. len(return_value) = len(ciphertext) - self.aead_tag_length
        """
        raise NotImplementedError
    
    def rekey(self, key: bytes) -> bytes:
        """
        Generate a new key from the old key.

        This method implements the default rekey algorithm specified by Noise.
        
        :param key: the old key. Must be self.aead_key_length bytes long.
        :return: the new key, self.aead_key_length bytes long.
        """
        new_key = self.aead_encrypt(key, self.max_nonce, b'', bytes(self.aead_key_length))
        return bytes(new_key[:self.aead_key_length])
    
    @abstractmethod
    def hash(self, data: BytesLike) -> BytesLike:
        """
        Hash arbitrary-length-data.
        
        :param data: data to be hashed.
        :return: the hash digest. Must be self.hash_length bytes long.
        """
        raise NotImplementedError
    
    @abstractmethod
    def hkdf_double(self, chaining_key: bytes, input_key_material: BytesLike) -> tuple[BytesLike, BytesLike]:
        """
        Use HMAC-based Extract-and-Expand Key Derivation Function (HKDF) (RFC 5869) to create more key material.
        Specifically, this function outputs 2 * self.hash_length bytes in total.

        This function must use the same hashing algorithm as used in self.hash.
        
        :param chaining_key: the old chaining key. Must be self.hash_length bytes long.
        :param input_key_material: key material to be mixed in.
        :return: a pair of output key material in bytes, each length self.hash_length
        """
        raise NotImplementedError
    
    @abstractmethod
    def hkdf_triple(self, chaining_key: bytes, input_key_material: BytesLike) -> tuple[BytesLike, BytesLike, BytesLike]:
        """
        Use HMAC-based Extract-and-Expand Key Derivation Function (HKDF) (RFC 5869) to create more key material.
        Specifically, this function outputs 3 * self.hash_length bytes in total.

        This function must use the same hashing algorithm as used in self.hash.
        
        :param chaining_key: the old chaining key. Must be self.hash_length bytes long.
        :param input_key_material: key material to be mixed in.
        :return: a triple of output key material in bytes, each length self.hash_length
        """
        raise NotImplementedError