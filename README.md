# pqnoise-python

*Work in Progress*

This is a Python implementation of the Post Quantum Noise Protocol Framework,
as described in the paper [Post Quantum Noise](https://eprint.iacr.org/2022/539).

This is a sans-IO implementation:
the HandshakeState object generates and accepts messages as bytes objects,
while the caller is responsible for sending and receiving these messages.

This library requires a modern Python 3 version
(developed with 3.11, may work with lower versions but no guarantees).
A flexible Provider architecture enables using different 3rd-party libraries for the actual cryptographic operations:
currently this library includes providers using
[alkindi](https://github.com/alraddady/alkindi),
[liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
for post-quantum KEM operations,
and
[pyca/cryptography](https://github.com/pyca/cryptography/),
[pynacl](https://github.com/pyca/pynacl),
and the Python standard library
for conventional crypto operations (AEAD encryption, hashing, HKDF),
with more on the way.
It's also very easy to implement your own providers.

## Example

See [example.py](example.py) to see it in action.

## Problems

Here are some problems I have found when writing this implementation:

### Library support for saving and loading ML-KEM keys

Static keys wouldn't be of much use if there isn't a way to persist them.
For ML-KEM, there are two forms for private (decapsulating) keys to be saved in:
seed or expanded.

[It is RECOMMENDED to save the seed only in a PKCS#8 format.](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/)
However, not all libraries support recreating a private key from the seed:
alkindi does not, for example.

Most libraries should support loading a private key from the expanded form,
but even then, many don't expose a method to extract the public key from a private key,
even though the public key is simply concatenated into the expanded private key.

### `psk` token processing

The Post Quantum Noise paper does not discuss pre-shared keys.
Regarding the `psk` token, the original Noise Protocol Specification has both a
[special processing rule](https://noiseprotocol.org/noise.html#handshake-tokens):

> In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results in a call to MixHash(e.public_key). In a PSK handshake, all of these calls are followed by MixKey(e.public_key). In conjunction with the validity rule in the next section, this ensures that PSK-based encryption uses encryption keys that are randomized using ephemeral public keys as nonces.

and a 
[validity rule](https://noiseprotocol.org/noise.html#validity-rule):

> - A party may not send any encrypted data after it processes a "psk" token unless it has previously sent an ephemeral public key (an "e" token), either before or after the "psk" token.
> 
> This rule guarantees that a k derived from a PSK will never be used for encryption unless it has also been randomized by MixKey(e.public_key) using a self-chosen ephemeral public key.

In all the interactive handshake patterns presented in the Post Quantum Noise paper,
the responder never sends an `e` token.
The validity rule then means adding the `psk` token to any of these patterns is not valid.

Even though this library implements the `psk` token according to the original specification,
using it with the post quantum Noise patterns may not be a good idea at the moment.