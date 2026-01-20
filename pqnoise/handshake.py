"""
This module implements tht actual Noise Protocol handshake.

The handshake algorithms are specified in these documents:

The Noise Protocol Framework https://noiseprotocol.org/noise.html
This specifies everything except the KEM operations.

Post Quantum Noise https://eprint.iacr.org/2022/539
This specifies the KEM operations.
"""


import enum
from collections.abc import Sequence
from typing import TypeVar

from .exceptions import PQNoiseError, CryptographicValueError, ConstraintsViolation
from .providers.base import BaseKEMPrivateKey, BaseKEMPublicKey, BaseProvider
from .types import BytesLike


class CipherState:
    """
    The CipherState object.
    
    Pretty much a straight up implementation of https://noiseprotocol.org/noise.html#the-cipherstate-object
    """
    def __init__(self, provider: BaseProvider) -> None:
        self._provider = provider

        self._key: bytes | None = None
        self._nonce: int = 0
    
    @property
    def key(self) -> bytes | None:
        return self._key
    
    @property
    def nonce(self) -> int:
        return self._nonce
    
    @nonce.setter
    def nonce(self, nonce: int) -> None:
        if not 0 <= nonce < self._provider.max_nonce:
            raise CryptographicValueError('Nonce must be in [0, 2**64-1)')
        self._nonce = nonce
    
    def has_key(self) -> bool:
        return self._key is not None
    
    def initialize_key(self, key: BytesLike) -> None:
        self._key = bytes(key)
        self._nonce = 0
    
    def encrypt_with_ad(self, associated_data: BytesLike, plaintext: BytesLike) -> BytesLike:
        if self._key is None:
            return plaintext
        if self._nonce >= self._provider.max_nonce:
            raise ConstraintsViolation('Nonce exceeded max value')
        ciphertext = self._provider.aead_encrypt(self._key, self._nonce, associated_data, plaintext)
        self._nonce += 1
        return ciphertext
    
    def decrypt_with_ad(self, associated_data: BytesLike, ciphertext: BytesLike) -> BytesLike:
        if self._key is None:
            return ciphertext
        if self._nonce >= self._provider.max_nonce:
            raise ConstraintsViolation('Nonce exceeded max value')
        plaintext = self._provider.aead_decrypt(self._key, self._nonce, associated_data, ciphertext)
        self._nonce += 1
        return plaintext
    
    def rekey(self) -> None:
        if self._key is None:
            raise ConstraintsViolation('rekey() called when key is empty')
        self._key = self._provider.rekey(self._key)


class SymmetricState:
    """
    The SymmetricState object.

    Pretty much a straight up implementation of https://noiseprotocol.org/noise.html#the-symmetricstate-object
    """
    def __init__(
            self,
            provider: BaseProvider,
            protocol_name: BytesLike,
    ) -> None:
        self._provider = provider

        self._hash: bytes = bytes(protocol_name).rjust(self._provider.hash_length, b'\0')
        if len(self._hash) > self._provider.hash_length:
            self._hash = bytes(self._provider.hash(self._hash))
        self._chaining_key: bytes = self._hash

        self._cipher_state = CipherState(provider)
    
    @property
    def cipher_state(self) -> CipherState:
        return self._cipher_state
    
    def mix_key(self, input_key_material: BytesLike) -> None:
        new_chaining_key, temp_k = self._provider.hkdf_double(self._chaining_key, input_key_material)
        self._chaining_key = bytes(new_chaining_key)
        self._cipher_state.initialize_key(memoryview(temp_k)[:self._provider.aead_key_length])
    
    def mix_hash(self, data: BytesLike) -> None:
        self._hash = bytes(self._provider.hash(self._hash + data))
        # since self._hash is bytes, memoryviews or bytesarrays can be added after it, which still results in bytes
    
    def mix_key_and_hash(self, input_key_material: BytesLike) -> None:
        new_chaining_key, temp_h, temp_k = self._provider.hkdf_triple(self._chaining_key, input_key_material)
        self._chaining_key = bytes(new_chaining_key)
        self.mix_hash(temp_h)
        self._cipher_state.initialize_key(memoryview(temp_k)[:self._provider.aead_key_length])
    
    @property
    def handshake_hash(self) -> bytes:
        return self._hash
    
    def encrypt_and_hash(self, plaintext: BytesLike) -> BytesLike:
        ciphertext = self._cipher_state.encrypt_with_ad(self._hash, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext
    
    def decrypt_and_hash(self, ciphertext: BytesLike) -> BytesLike:
        plaintext = self._cipher_state.decrypt_with_ad(self._hash, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext
    
    def split(self) -> tuple[CipherState, CipherState]:
        temp_k1, temp_k2 = self._provider.hkdf_double(self._chaining_key, b'')
        c1 = CipherState(self._provider)
        c1.initialize_key(memoryview(temp_k1)[:self._provider.aead_key_length])
        c2 = CipherState(self._provider)
        c2.initialize_key(memoryview(temp_k2)[:self._provider.aead_key_length])
        return c1, c2


class HandshakeRole(enum.StrEnum):
    initiator = 'initiator'
    responder = 'responder'


class KeyType(enum.Enum):
    ephemeral = 'ephemeral'
    static = 'static'


class MessageToken(enum.StrEnum):
    e = 'e'
    s = 's'
    ekem = 'ekem'
    skem = 'skem'
    psk = 'psk'


class HandshakeState:
    """
    The HandshakeState object.

    This is the main way of carrying out Noise Protocol handshakes.

    Reference: https://noiseprotocol.org/noise.html#the-handshakestate-object
    """
    def __init__(
            self,
            provider: BaseProvider,
            role: HandshakeRole,
            initiator_pre_message_pattern: Sequence[MessageToken] | None,
            responder_pre_message_pattern: Sequence[MessageToken] | None,
            message_patterns: Sequence[Sequence[MessageToken]],
            protocol_name: str,
            prologue: BytesLike,
            local_static_private_key: BaseKEMPrivateKey | None = None,
            local_ephemeral_private_key: BaseKEMPrivateKey | None = None,
            remote_static_public_key: BaseKEMPublicKey | None = None,
            remote_ephemeral_public_key: BaseKEMPublicKey | None = None,
            pre_shared_key: BytesLike | None = None,
    ) -> None:
        """
        Initialize the handshake.

        For the two participants of the handshake,
        the {initiator,responder}_pre_message_pattern, message_patterns, protocol_name, prologue arguments must match.

        This corresponds to calling "Initialize" in the Noise Protocol Framework specification.
        
        :param provider: an instance of Protocol, used to carry out cryptographic operations.
        
        :param role: the role to play in this handshake, an instance of enum HandshakeRole.
        
        :param initiator_pre_message_pattern: the initiator's pre-message pattern, if any.
        
        :param responder_pre_message_pattern: the responder's pre-message pattern, if any.

        :param message_patterns: the message patterns for the actual handshake messages (excluding pre-mesages).
        
        :param protocol_name: the handshake protocol's name.
        Post Quantum Noise Protocols don't have standardized names yet,
        so just make sure the participants use the same exact name.

        :param prologue: the prologue data.
        All participants must have the same prologue data.
        
        :param local_static_private_key: the local static key, if any.

        :param local_ephemeral_private_key: the local ephemeral key, if any.
        This is usually not needed unless implementing compound / fallback handshakes.
        
        :param remote_static_public_key: the remote static key, if known from a pre-message.

        :param remote_ephemeral_public_key: the remote ephemeral key, if known.
        
        :param pre_shared_key: the pre-shared key, if used. Should be 32 bytes in length.
        """
        self._provider = provider
        self._role = role
        self._message_patterns = tuple(tuple(m) for m in message_patterns)

        self._s = local_static_private_key
        self._e = local_ephemeral_private_key
        self._rs = remote_static_public_key
        self._re = remote_ephemeral_public_key
        self._psk = pre_shared_key

        self._has_psk_token = any(any(m == MessageToken.psk for m in msg) for msg in self._message_patterns)
        self._next_message_to_process = 0

        self._symmetric_state = SymmetricState(self._provider, protocol_name.encode('ascii'))
        self._symmetric_state.mix_hash(prologue)

        if initiator_pre_message_pattern:
            self._process_pre_message_pattern(HandshakeRole.initiator, initiator_pre_message_pattern)
        if responder_pre_message_pattern:
            self._process_pre_message_pattern(HandshakeRole.responder, responder_pre_message_pattern)
    
    def _get_public_key_bytes(self, role: HandshakeRole, type_: KeyType) -> BytesLike:
        KeyTypes = TypeVar('KeyTypes', BaseKEMPublicKey, BaseKEMPrivateKey)
        
        def check_none_key(key: KeyTypes | None) -> KeyTypes:
            if key is None:
                raise ConstraintsViolation(f'Specified key is empty: {role!s} {type_!s}')
            return key
        
        is_me = self._role == role

        match is_me, type_:
            case True, KeyType.ephemeral:
                return check_none_key(self._e).get_public_key_bytes()
            case True, KeyType.static:
                return check_none_key(self._s).get_public_key_bytes()
            case False, KeyType.ephemeral:
                return check_none_key(self._re).to_bytes()
            case False, KeyType.static:
                return check_none_key(self._rs).to_bytes()
    
    def _process_pre_message_pattern(self, role: HandshakeRole, pattern: Sequence[MessageToken]) -> None:
        for token in pattern:
            match token:
                case MessageToken.e:
                    key_bytes = self._get_public_key_bytes(role, KeyType.ephemeral)
                    self._symmetric_state.mix_hash(key_bytes)
                    if self._has_psk_token:
                        self._symmetric_state.mix_key(key_bytes)
                case MessageToken.s:
                    self._symmetric_state.mix_hash(self._get_public_key_bytes(role, KeyType.static))
                case _:
                    raise ConstraintsViolation(f'Premessage pattern for {role!s} contains disallowed token {token!s}')
    
    def _write_e(self) -> bytes:
        if self._e is not None:
            raise ConstraintsViolation('Local ephemeral private key is not Empty when writing e token')
        self._e = self._provider.ephemeral_private_key_type.generate_key()
        public_key_bytes = self._e.get_public_key_bytes()
        self._symmetric_state.mix_hash(public_key_bytes)
        if self._has_psk_token:
            self._symmetric_state.mix_key(public_key_bytes)
        return public_key_bytes
    
    def _read_e(self, buffer: memoryview) -> memoryview:
        """
        Read an e token from the beginning of buffer, and return the remaining buffer.
        """
        if self._re is not None:
            raise ConstraintsViolation('Remote ephemeral public key is not Empty when reading e token')
        key_type = self._provider.ephemeral_public_key_type
        if len(buffer) < key_type.public_key_length:
            raise CryptographicValueError('Buffer too short to read e token')
        key_bytes = buffer[:key_type.public_key_length]
        buffer = buffer[key_type.public_key_length:]
        self._re = key_type.from_bytes(key_bytes)
        self._symmetric_state.mix_hash(key_bytes)
        if self._has_psk_token:
            self._symmetric_state.mix_key(key_bytes)
        return buffer
    
    def _write_s(self) -> bytes:
        if self._s is None:
            raise ConstraintsViolation('Local static private key is Empty when writing s token')
        return self._symmetric_state.encrypt_and_hash(self._s.get_public_key_bytes())
    
    def _read_s(self, buffer: memoryview) -> memoryview:
        if self._rs is not None:
            raise ConstraintsViolation('Remote static public key is not Empty when reading s token')
        if self._role == HandshakeRole.initiator:
            key_type = self._provider.responder_static_public_key_type
        else:
            key_type = self._provider.initiator_static_public_key_type
        required_length = key_type.public_key_length
        if self._symmetric_state.cipher_state.has_key():
            required_length += self._provider.aead_tag_lenth
        if len(buffer) < required_length:
            raise CryptographicValueError('Buffer too short to read s token')
        key_ciphertext_bytes = buffer[:required_length]
        buffer = buffer[required_length:]
        self._rs = key_type.from_bytes(self._symmetric_state.decrypt_and_hash(key_ciphertext_bytes))
        return buffer
    
    def _write_ekem(self) -> bytes:
        if self._re is None:
            raise ConstraintsViolation('Remote ephemeral public key is Empty when writing ekem token')
        encap_ciphertext, shared_secret = self._re.encapsulate()
        self._symmetric_state.mix_hash(encap_ciphertext)
        self._symmetric_state.mix_key(shared_secret)
        return encap_ciphertext
    
    def _read_ekem(self, buffer: memoryview) -> memoryview:
        if self._e is None:
            raise ConstraintsViolation('Local ephemeral private key is Empty when reading ekem token')
        if len(buffer) < self._e.ciphertext_length:
            raise CryptographicValueError('Buffer too short to read ekem token')
        encap_ciphertext = buffer[:self._e.ciphertext_length]
        buffer = buffer[self._e.ciphertext_length:]
        self._symmetric_state.mix_hash(encap_ciphertext)
        shared_secret = self._e.decapsulate(encap_ciphertext)
        self._symmetric_state.mix_key(shared_secret)
        return buffer
    
    def _write_skem(self) -> bytes:
        if self._rs is None:
            raise ConstraintsViolation('Remote static public key is Empty when writing skem token')
        encap_ciphertext, shared_secret = self._rs.encapsulate()
        encrypted_encap_ciphertext = self._symmetric_state.encrypt_and_hash(encap_ciphertext)
        self._symmetric_state.mix_key(shared_secret)
        return encrypted_encap_ciphertext
    
    def _read_skem(self, buffer: memoryview) -> memoryview:
        if self._s is None:
            raise ConstraintsViolation('Local static private key is Empty when reading ekem token')
        required_length = self._s.ciphertext_length
        if self._symmetric_state.cipher_state.has_key():
            required_length += self._provider.aead_tag_lenth
        if len(buffer) < required_length:
            raise CryptographicValueError('Buffer too short to read skem token')
        encrypted_encap_ciphertext = buffer[:required_length]
        buffer = buffer[required_length:]
        encap_ciphertext = self._symmetric_state.decrypt_and_hash(encrypted_encap_ciphertext)
        shared_secret = self._s.decapsulate(encap_ciphertext)
        self._symmetric_state.mix_key(shared_secret)
        return buffer
    
    def _process_psk(self) -> None:
        if self._psk is None:
            raise ConstraintsViolation('PSK is Empty when processing psk token')
        self._symmetric_state.mix_key_and_hash(self._psk)
    
    def _write_message(self, pattern: Sequence[MessageToken], payload: BytesLike = b'') -> list[bytes]:
        message = []
        for token in pattern:
            match token:
                case MessageToken.e:
                    message.append(self._write_e())
                case MessageToken.s:
                    message.append(self._write_s())
                case MessageToken.ekem:
                    message.append(self._write_ekem())
                case MessageToken.skem:
                    message.append(self._write_skem())
                case MessageToken.psk:
                    self._process_psk()
        message.append(self._symmetric_state.encrypt_and_hash(payload))
        return message
    
    def _read_message(self, pattern: Sequence[MessageToken], data: BytesLike) -> BytesLike:
        buffer = memoryview(data)
        for token in pattern:
            match token:
                case MessageToken.e:
                    buffer = self._read_e(buffer)
                case MessageToken.s:
                    buffer = self._read_s(buffer)
                case MessageToken.ekem:
                    buffer = self._read_ekem(buffer)
                case MessageToken.skem:
                    buffer = self._read_skem(buffer)
                case MessageToken.psk:
                    self._process_psk()
        payload = self._symmetric_state.decrypt_and_hash(buffer)
        return payload
    
    def is_handshake_done(self) -> bool:
        """
        Determines whether the handshake is completed.
        When true, split() can be called.
        
        :return: whether handshake is completed.
        """
        return self._next_message_to_process >= len(self._message_patterns)
    
    def split(self) -> tuple[CipherState, CipherState]:
        """
        Create a pair of CipherState objects that can be used to encrypt transport messages.
        
        :return: a tuple of two CipherState objects
        """
        return self._symmetric_state.split()
    
    def _next_message_is_write(self) -> bool:
        if self._role == HandshakeRole.initiator:
            return self._next_message_to_process % 2 == 0
        else:
            return self._next_message_to_process % 2 == 1
        
    def write_message(self, payload: BytesLike | None = None) -> bytes:
        """
        Write a handshake message according to the message pattern of the next step.
        
        :param payload: an optional payload to send to the other party.
        :raises ConstraintsViolation: if called when the next message is a read, handshake is already complete, or handshake patterns are invalid.
        :raises CryptographicValueError: if the 
        :return: the message contents. Send this to the other participant, who should call read_message() on it.
        """
        if self.is_handshake_done():
            raise ConstraintsViolation('Handshake already completed')
        if not self._next_message_is_write():
            raise ConstraintsViolation('write_message() called when next message is a read')
        pettern = self._message_patterns[self._next_message_to_process]
        if payload is None:
            payload = b''
        message = self._write_message(pettern, payload)
        self._next_message_to_process += 1
        return b''.join(message)
    
    def read_message(self, message: BytesLike) -> bytes:
        """
        Read a handshake message according to the message pattern of the current step.
        
        :param message: the message sent by the other participant.
        :raises ConstraintsViolation: if called when the next message is a write, handshake is already complete, or handshake patterns are invalid.
        :raises CryptographicValueError: if cryptographic procedures fails due to wrong keys, modified ciphertexts, etc.
        :return: the payload sent by the other participant, which may be empty.
        """
        if self.is_handshake_done():
            raise ConstraintsViolation('Handshake already completed')
        if self._next_message_is_write():
            raise ConstraintsViolation('read_message() called when next message is a write')
        pattern = self._message_patterns[self._next_message_to_process]
        mv = memoryview(message)
        payload = self._read_message(pattern, mv)
        self._next_message_to_process += 1
        return payload
    
    @property
    def local_static_key(self) -> BaseKEMPrivateKey | None:
        return self._s
    
    @property
    def local_ephemeral_key(self) -> BaseKEMPrivateKey | None:
        return self._e
    
    @property
    def remote_static_key(self) -> BaseKEMPublicKey | None:
        return self._rs
    
    @property
    def remote_ephemeral_key(self) -> BaseKEMPublicKey | None:
        return self._re

