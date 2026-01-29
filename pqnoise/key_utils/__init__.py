import hashlib
import hmac

from ..exceptions import CryptographicValueError
from ..types import BytesLike


"""
FIPS 203 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf

The expanded private (decapsulation) key representation is dk = (dk_PKE | ek | H(ek) | z),
where ek is the public (encapsulation) key,
and H is the SHA3-256 function.
The offset of ek in dk is [384k : 768k + 32],
and the offset of H(ek) is [768k + 32 : 768k + 64].

k is one of the ML-KEM parameters,
which is 2 for ML-KEM-512,
3 for ML-KEM-768,
and 4 for ML-KEM-1024.
"""

"""
This dict stores the offsets of public key bytes inside private key bytes.
The dict's key is the length of the private key.
The value is (pub_start, pub_stop).
"""
ML_KEM_PRIVATE_KEY_OFFSETS = {
    1632: (384*2, 768*2+32),
    2400: (384*3, 768*3+32),
    3168: (384*4, 768*4+32),
}


def ml_kem_public_key_bytes_from_private_key_bytes(private_key_bytes: BytesLike, skip_verify: bool = False) -> memoryview:
    """
    Extract the public (encapsulation) key from an expanded private (decapsulation) ML-KEM-{512,768,1024} key.
    
    :param private_key_bytes: private key bytes.
    :param skip_verify: if True, skip verifying the embedded public key hash.
    :raises CryptographicValueError: if the private key does not have a valid length,
    or embedded public key does not match its hash.
    :return: pulic key bytes, in a memoryview object
    """
    try:
        offsets = ML_KEM_PRIVATE_KEY_OFFSETS[len(private_key_bytes)]
    except KeyError:
        raise CryptographicValueError('Private key bytes length incorrect')
    private_key_mv = memoryview(private_key_bytes)
    public_key_bytes = private_key_mv[offsets[0]:offsets[1]]
    if not skip_verify:
        public_key_hash = private_key_mv[offsets[1]:offsets[1]+32]
        public_key_hash_verify = hashlib.sha3_256(public_key_bytes).digest()
        if not hmac.compare_digest(public_key_hash, public_key_hash_verify):
            raise CryptographicValueError('Public key hash verification failed')
    return public_key_bytes