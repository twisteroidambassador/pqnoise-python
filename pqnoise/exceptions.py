class PQNoiseError(Exception):
    """
    Base exception for this package.
    """


class CryptographicValueError(PQNoiseError, ValueError):
    """
    Exception raised during cryptographic operations due to invalid input.
    This is usually a data problem, such as incorrect keys, altered ciphertext, etc.
    """


class ConstraintsViolation(PQNoiseError):
    """
    A Noise Protocol validity constraint has been violated.
    This is usually a programmer error, such as using an invalid message pattern, calling methods at the wrong time, etc.
    """