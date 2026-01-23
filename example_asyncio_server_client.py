"""
This file demonstrates a PQNoise handshake between TCP server and client.

It also uses different providers for the server and client,
implemented with different backend cryptographic libraries.
"""

import asyncio
import functools
import logging

from pqnoise.handshake import HandshakeState, HandshakeRole, MessageToken
from pqnoise.providers.base import BaseProvider, BaseKEMPrivateKey, BaseKEMPublicKey
from pqnoise.providers import alkindi, cryptography, liboqs, pynacl, stdlib


async def write_message(writer: asyncio.StreamWriter, message: bytes):
    """
    Write a message to TCP stream, prepended with a 2-byte length field (big endian).
    """
    writer.write(len(message).to_bytes(2, 'big'))
    writer.write(message)
    await writer.drain()


async def read_message(reader: asyncio.StreamReader) -> bytes:
    """
    Read a message from a TCP stream, prepended with a 2-byte length field (big endian).
    """
    length = int.from_bytes(await reader.readexactly(2), 'big')
    return await reader.readexactly(length)


async def server_handler(
        provider: BaseProvider,
        server_static_key: BaseKEMPrivateKey,
        handshake_args: dict,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
):
    logger = logging.getLogger('server')
    logger.info('Received connection')
    handshake = HandshakeState(
        provider,
        HandshakeRole.responder,
        **handshake_args,
        local_static_private_key=server_static_key,
    )

    message = await read_message(reader)
    logger.info('Received handshake message 1')
    handshake.read_message(message)
    
    message = handshake.write_message()
    logger.info('Sending handshake message 2')
    await write_message(writer, message)

    message = await read_message(reader)
    logger.info('Received handshake message 3')
    handshake.read_message(message)
    assert handshake.remote_static_key is not None
    logger.info('Received client public key: %s...', handshake.remote_static_key.to_bytes()[:16].hex())

    message = handshake.write_message()
    logger.info('Sending handshake message 4')
    await write_message(writer, message)

    assert handshake.is_handshake_done()
    logger.info('Handshake done, hash: %s', handshake.handshake_hash.hex())

    client_cipher, server_cipher = handshake.split()

    plaintext = b'transport message to client'
    logger.info('Sending transport message %r', plaintext)
    await write_message(writer, server_cipher.encrypt_with_ad(b'', plaintext))

    try:
        while True:
            ciphertext = await read_message(reader)
            plaintext = client_cipher.decrypt_with_ad(b'', ciphertext)
            logger.info('Received transport message: %r', plaintext)
    except asyncio.IncompleteReadError:
        logger.info('Client closed connection')
    finally:
        logger.info('Closing connection')
        writer.close()
        await writer.wait_closed()


async def client_request(
        host: str,
        port: int,
        provider: BaseProvider,
        static_key: BaseKEMPrivateKey,
        handshake_args: dict,
):
    logger = logging.getLogger('client')
    logger.info('Opening connection')
    reader, writer = await asyncio.open_connection(
        host,
        port,
    )
    logger.info('Connected to server')

    try:
        handshake = HandshakeState(
            provider,
            HandshakeRole.initiator,
            **handshake_args,
            local_static_private_key=static_key,
        )

        message = handshake.write_message()
        logger.info('Sending handshake message 1')
        await write_message(writer, message)

        message = await read_message(reader)
        logger.info('Received handshake message 2')
        handshake.read_message(message)
        assert handshake.remote_static_key is not None
        logger.info('Received server public key: %s...', handshake.remote_static_key.to_bytes()[:16].hex())

        message = handshake.write_message()
        logger.info('Sending handshake message 3')
        await write_message(writer, message)

        message = await read_message(reader)
        logger.info('Received handshake message 4')
        handshake.read_message(message)
        
        assert handshake.is_handshake_done()
        logger.info('Handshake done, hash: %s', handshake.handshake_hash.hex())

        client_cipher, server_cipher = handshake.split()

        plaintext = b'transport message to server'
        logger.info('Sending transport message %r', plaintext)
        await write_message(writer, client_cipher.encrypt_with_ad(b'', plaintext))

        ciphertext = await read_message(reader)
        plaintext = server_cipher.decrypt_with_ad(b'', ciphertext)
        logger.info('Received transport message: %r', plaintext)
    finally:
        logger.info('Closing connection')
        writer.close()
        await writer.wait_closed()


async def amain():
    """
    Demonstrate a PQNoise handshake between TCP server and client.
    """

    """
    For this demonstration, we will use different providers for the server and client.

    The server's provider uses AEAD, hashing from pyca/cryptography,
    and ML-KEM from alkindi.

    The client's provider uses AEAD from pynacl,
    hashing from the standard library,
    and ML-KEM from liboqs.
    """

    server_provider = cryptography.ChaPoly_SHA256_Provider(
        ephemeral_private_key_type=alkindi.MLKEM768PrivateKey,
        ephemeral_public_key_type=alkindi.MLKEM768PublicKey,
        initiator_private_key_type=alkindi.MLKEM768PrivateKey,
        initiator_public_key_type=alkindi.MLKEM768PublicKey,
        responder_private_key_type=alkindi.MLKEM768PrivateKey,
        responder_public_key_type=alkindi.MLKEM768PublicKey,
    )

    class ClientProvider(pynacl.ChaCha20Poly1305MixIn, stdlib.BaseStdLibHashProvider):
        def __init__(self) -> None:
            super().__init__(
                'SHA256',
                liboqs.MLKEM768PrivateKey,
                liboqs.MLKEM768PublicKey,
                liboqs.MLKEM768PrivateKey,
                liboqs.MLKEM768PublicKey,
                liboqs.MLKEM768PrivateKey,
                liboqs.MLKEM768PublicKey,
            )
    
    client_provider = ClientProvider()

    """
    We will use a pqXX handshake pattern:

    pqXX:
    -> e
    <- ekem, s
    -> skem, s
    <- skem
    """
    handshake_args = {
        'initiator_pre_message_pattern': None,
        'responder_pre_message_pattern': None,
        'message_patterns': [
            [MessageToken.e],
            [MessageToken.ekem, MessageToken.s],
            [MessageToken.skem, MessageToken.s],
            [MessageToken.skem],
        ],
        'protocol_name': 'Noise_pqXX_MLKEM768_ChaChaPoly_SHA256',
        'prologue': b'pqnoise handshake demonstration over TCP',
    }

    server_static_key = server_provider.responder_static_private_key_type.generate_key()
    logging.info('Server public key: %s...', server_static_key.get_public_key_bytes()[:16].hex())
    client_static_key = client_provider.initiator_static_private_key_type.generate_key()
    logging.info('Client public key: %s...', client_static_key.get_public_key_bytes()[:16].hex())

    server_port = 32767

    server = await asyncio.start_server(
        functools.partial(server_handler, server_provider, server_static_key, handshake_args),
        '127.0.0.1',
        server_port,
    )

    try:
        await client_request(
            '127.0.0.1',
            server_port,
            client_provider,
            client_static_key,
            handshake_args,
        )
    finally:
        server.close()
        await server.wait_closed()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(name)s %(message)s')
    asyncio.run(amain())