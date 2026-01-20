from pqnoise.handshake import HandshakeState, HandshakeRole, MessageToken
from pqnoise.providers.alkindi import MLKEM768PrivateKey, MLKEM768PublicKey
from pqnoise.providers.cryptography import ChaPoly_SHA256_Provider


def main():
    """
    A simulation of Post Quantum Noise handshake.
    """

    """
    First, determine the algorithms to be used, and select an appropriate provider.

    For this example, we will use ML-KEM-768 for KEM operations,
    ChaCha20Poly1305 for AEAD encryption,
    and SHA256 for hashing.

    Read the docstrings of these classes and their containing modules for details.
    """

    provider = ChaPoly_SHA256_Provider(
        ephemeral_private_key_type=MLKEM768PrivateKey,
        ephemeral_public_key_type=MLKEM768PublicKey,
        initiator_private_key_type=MLKEM768PrivateKey,
        initiator_public_key_type=MLKEM768PublicKey,
        responder_private_key_type=MLKEM768PrivateKey,
        responder_public_key_type=MLKEM768PublicKey,
    )

    """
    Then, select a handshake pattern.

    We will use the pqXK pattern as described in the Post Quantum Noise paper:

    <- s
    ...
    -> skem, e
    <- ekem
    -> s
    <- skem
    """

    initiator_pre_message_pattern = None
    responder_pre_message_pattern = [MessageToken.s]
    message_patterns = [
        [MessageToken.skem, MessageToken.e],
        [MessageToken.ekem],
        [MessageToken.s],
        [MessageToken.skem],
    ]

    """
    Determine the various protocol parameters, and generate static keys for both parties.
    """

    protocol_name = 'Noise_pqXK_MLKEM768_ChaChaPoly_SHA256'
    prologue = b'pqnoise handshake demonstration'

    initiator_private_key = MLKEM768PrivateKey.generate_key()
    responder_private_key = MLKEM768PrivateKey.generate_key()
    responder_public_key = MLKEM768PublicKey.from_bytes(responder_private_key.get_public_key_bytes())

    """
    Create the handshake state objects for both parties.
    """

    initiator_handshake = HandshakeState(
        provider,
        HandshakeRole.initiator,
        initiator_pre_message_pattern,
        responder_pre_message_pattern,
        message_patterns,
        protocol_name,
        prologue,
        local_static_private_key=initiator_private_key,
        remote_static_public_key=responder_public_key,  # this key is known in the pre-message
    )

    responder_handshake = HandshakeState(
        provider,
        HandshakeRole.responder,
        initiator_pre_message_pattern,
        responder_pre_message_pattern,
        message_patterns,
        protocol_name,
        prologue,
        local_static_private_key=responder_private_key,
    )

    """
    We already know the message pattern contains 4 messages,
    so we can simply do the writes and reads manually 4 times.
    Or, we can write a universal loop like below:
    """

    message_index = 0
    while not initiator_handshake.is_handshake_done():
        assert not responder_handshake.is_handshake_done()
        if message_index % 2 == 0:
            writer, reader = initiator_handshake, responder_handshake
        else:
            writer, reader = responder_handshake, initiator_handshake
        payload = f'message {message_index} payload'.encode('ascii')
        message = writer.write_message(payload)
        payload_received = reader.read_message(message)
        assert payload == payload_received
        message_index += 1
    
    assert initiator_handshake.is_handshake_done()
    assert responder_handshake.is_handshake_done()

    """
    Now that the handshake is done, we can encrypt transport messages:
    """

    initiator_cipherstates = initiator_handshake.split()
    responder_cipherstates = responder_handshake.split()

    plaintext = b'initiator plaintext'
    ciphertext = initiator_cipherstates[0].encrypt_with_ad(b'', plaintext)
    assert responder_cipherstates[0].decrypt_with_ad(b'', ciphertext) == plaintext
    
    plaintext = b'responder plaintext'
    ciphertext = responder_cipherstates[1].encrypt_with_ad(b'', plaintext)
    assert initiator_cipherstates[1].decrypt_with_ad(b'', ciphertext) == plaintext


if __name__ == '__main__':
    main()