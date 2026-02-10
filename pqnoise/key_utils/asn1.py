"""
This module implements loading and dumping ML-KEM private keys from/to DER encoded ASN.1 data.

Requires pyasn1, and either one of pyasn1-modules or pyasn1-alt-modules.

The ASN.1 encoding schema is defined at
https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/

"""

import enum
from typing import NamedTuple, assert_never

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ, namedtype, tag, constraint

try:
    from pyasn1_alt_modules import rfc5280, rfc5958  # pyright: ignore[reportMissingImports]
except ImportError:
    try:
        from pyasn1_modules import rfc5280, rfc5958  # pyright: ignore[reportMissingImports]
    except ImportError:
        raise ImportError('Both pyasn1_alt_modules and pyasn1_modules cannot be imported')

from ..types import BytesLike


def _fixed_length_octet_string(length: int) -> univ.OctetString:
    return univ.OctetString().subtype(
        subtypeSpec=constraint.ValueSizeConstraint(length, length)
    )


_Seed = _fixed_length_octet_string(64)

_MLKEM512ExpandedKey = _fixed_length_octet_string(1632)
_MLKEM768ExpandedKey = _fixed_length_octet_string(2400)
_MLKEM1024ExpandedKey = _fixed_length_octet_string(3168)


class _MLKEM512Both(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', _Seed),
        namedtype.NamedType('expandedKey', _MLKEM512ExpandedKey),
    )


class _MLKEM768Both(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', _Seed),
        namedtype.NamedType('expandedKey', _MLKEM768ExpandedKey),
    )


class _MLKEM1024Both(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seed', _Seed),
        namedtype.NamedType('expandedKey', _MLKEM1024ExpandedKey),
    )


_ImplicitTaggedSeed = _Seed.subtype(
    implicitTag=tag.Tag(
        tag.tagClassContext,
        tag.tagFormatSimple,
        0,
    ),
)


class _MLKEMPrivateKeyChoice(univ.Choice):
    pass


class _MLKEM512PrivateKey(_MLKEMPrivateKeyChoice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'seed',
            _ImplicitTaggedSeed,
        ),
        namedtype.NamedType(
            'expandedKey',
            _MLKEM512ExpandedKey,
        ),
        namedtype.NamedType(
            'both',
            _MLKEM512Both(),
        ),
    )


class _MLKEM768PrivateKey(_MLKEMPrivateKeyChoice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'seed',
            _ImplicitTaggedSeed,
        ),
        namedtype.NamedType(
            'expandedKey',
            _MLKEM768ExpandedKey,
        ),
        namedtype.NamedType(
            'both',
            _MLKEM768Both(),
        ),
    )


class _MLKEM1024PrivateKey(_MLKEMPrivateKeyChoice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'seed',
            _ImplicitTaggedSeed,
        ),
        namedtype.NamedType(
            'expandedKey',
            _MLKEM1024ExpandedKey,
        ),
        namedtype.NamedType(
            'both',
            _MLKEM1024Both(),
        ),
    )


_nistAlgorithm = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4))
_kems = _nistAlgorithm + (4, )
_id_alg_ml_kem_512 = _kems + (1, )
_id_alg_ml_kem_768 = _kems + (2, )
_id_alg_ml_kem_1024 = _kems + (3, )


class MLKEMName(enum.StrEnum):
    """
    Enum representing names of the ML-KEM variants.
    """
    ml_kem_512 = 'ML-KEM-512'
    ml_kem_768 = 'ML-KEM-768'
    ml_kem_1024 = 'ML-KEM-1024'


class _MLKEMAttributes(NamedTuple):
    name: MLKEMName
    privkey_asn1class: type[_MLKEMPrivateKeyChoice]
    oid: univ.ObjectIdentifier
    pubkey_length: int


_ML_KEM_ATTRIBUTES = [
    _MLKEMAttributes(MLKEMName.ml_kem_512, _MLKEM512PrivateKey, _id_alg_ml_kem_512, 800),
    _MLKEMAttributes(MLKEMName.ml_kem_768, _MLKEM768PrivateKey, _id_alg_ml_kem_768, 1184),
    _MLKEMAttributes(MLKEMName.ml_kem_1024, _MLKEM1024PrivateKey, _id_alg_ml_kem_1024, 1568),
]

_OID_TO_ATTRIBUTES = {a.oid: a for a in _ML_KEM_ATTRIBUTES}
_NAME_TO_ATTRIBUTES = {a.name: a for a in _ML_KEM_ATTRIBUTES}


class LoadedMLKEMPrivateKey(NamedTuple):
    """
    Named tuple representing a ML-KEM private key loaded from DER data.

    seed and expanded_key must not be None at the same time.
    """
    algorithm_name: MLKEMName
    seed: bytes | None
    expanded_key: bytes | None


def load_mlkem_private_key_der(data: BytesLike) -> LoadedMLKEMPrivateKey:
    """
    Load a ML-KEM private key from DER-encoded data.

    As specified, the encoded private key may include seed, expandedKey or both.
    Whatever is stored in the data is returned in the LoadedPrivateKey named tuple,
    and whatever is not stored is set to None.
    
    :param data: the DER-encoded data to load from.
    :raises ValueError: if the DER data is invalid.
    :return: a LoadedPrivateKey named tuple.
    """
    one_asymmetric_key, remaining = der_decode(bytes(data), rfc5958.OneAsymmetricKey())
    if remaining:
        raise ValueError('Trailing data in DER private key')
    oid = one_asymmetric_key['privateKeyAlgorithm']['algorithm']
    try:
        algorithm_attributes = _OID_TO_ATTRIBUTES[oid]
    except KeyError:
        raise ValueError(f'Unsupported algorithm OID {oid}')
    if one_asymmetric_key['privateKeyAlgorithm']['parameters'].isValue:
        raise ValueError('Unexpected algorithm parameters')
    if one_asymmetric_key['version'] != rfc5958.Version('v1'):
        raise ValueError('Unsupported OneAsymmetricKey Version')
    private_key, remaining = der_decode(one_asymmetric_key['privateKey'], algorithm_attributes.privkey_asn1class())
    if remaining:
        raise ValueError('Trailing data in enclosed private key field')
    
    match private_key.getName():
        case 'seed':
            return LoadedMLKEMPrivateKey(algorithm_attributes.name, bytes(private_key['seed']), None)
        case 'expandedKey':
            return LoadedMLKEMPrivateKey(algorithm_attributes.name, None, bytes(private_key['expandedKey']))
        case 'both':
            return LoadedMLKEMPrivateKey(algorithm_attributes.name, bytes(private_key['both']['seed']), bytes(private_key['both']['expandedKey']))
        case _ as unreachable:
            assert_never(unreachable)


def dump_mlkem_private_key_der(
        algorithm_name: MLKEMName,
        seed: BytesLike | None,
        expanded_key: BytesLike | None,
) -> bytes:
    """
    Encode a ML-KEM private key into DER-encoded data.

    seed and expanded_key must not be None at the same time.
    The encoded DER data only includes whatever is provided.
    
    :param algorithm_name: The ML-KEM variant name.
    :param seed: The seed, if available
    :param expanded_key: The expanded private key, if available.
    :raises ValueError: if input is invalid.
    :return: DER-encoded data.
    """
    if seed is None and expanded_key is None:
        raise ValueError('Both seed and expanded_key are absent')
    try:
        algorithm_attributes = _NAME_TO_ATTRIBUTES[algorithm_name]
    except KeyError:
        raise ValueError(f'Unsupported algorithm name {algorithm_name}')
    pkey = algorithm_attributes.privkey_asn1class()
    if seed is not None:
        if expanded_key is not None:
            pkey['both']['seed'] = bytes(seed)
            pkey['both']['expandedKey'] = bytes(expanded_key)
        else:
            pkey['seed'] = bytes(seed)
    else:
        assert expanded_key is not None
        pkey['expandedKey'] = bytes(expanded_key)
    one_asymmetric_key = rfc5958.OneAsymmetricKey()
    one_asymmetric_key['privateKeyAlgorithm']['algorithm'] = algorithm_attributes.oid
    one_asymmetric_key['version'] = 'v1'
    one_asymmetric_key['privateKey'] = der_encode(pkey)

    return der_encode(one_asymmetric_key)


def load_mlkem_public_key_der(data: BytesLike) -> tuple[MLKEMName, bytes]:
    """
    Load a ML-KEM public key from DER-encoded data.
    
    :param data: The DER-encoded data to load from.
    :raises ValueError: if the DER data is invalid.
    :return: A tuple (algorithm name, public key bytes)
    """
    subj_public_key, remaining = der_decode(bytes(data), rfc5280.SubjectPublicKeyInfo())
    if remaining:
        raise ValueError('Trailing data in DER public key')
    oid = subj_public_key['algorithm']['algorithm']
    try:
        algorithm_attributes = _OID_TO_ATTRIBUTES[oid]
    except KeyError:
        raise ValueError(f'Unsupported algorithm OID {oid}')
    if subj_public_key['algorithm']['parameters'].isValue:
        raise ValueError('Unexpected algorithm parameters')
    pubkey_bytes = subj_public_key['subjectPublicKey'].asOctets()
    if len(pubkey_bytes) != algorithm_attributes.pubkey_length:
        raise ValueError('Public key wrong length')
    return algorithm_attributes.name, pubkey_bytes


def dump_mlkem_public_key_der(algorithm_name: MLKEMName, public_key: BytesLike) -> bytes:
    """
    Encode a ML-KEM public key into DER-encoded data.
    
    :param algorithm_name: The ML-KEM variant name.
    :param public_key: The public key bytes.
    :raises ValueError: if input is invalid.
    :return: DER-encoded data.
    """
    try:
        algorithm_attributes = _NAME_TO_ATTRIBUTES[algorithm_name]
    except KeyError:
        raise ValueError(f'Unsupported algorithm name {algorithm_name}')
    if len(public_key) != algorithm_attributes.pubkey_length:
        raise ValueError('Public key wrong length')
    subj_public_key = rfc5280.SubjectPublicKeyInfo()
    subj_public_key['algorithm']['algorithm'] = algorithm_attributes.oid
    subj_public_key['subjectPublicKey'] = univ.BitString.fromOctetString(bytes(public_key))
    return der_encode(subj_public_key)