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
[alkindi](https://github.com/alraddady/alkindi)
for post-quantum KEM operations and
[pyca/cryptography](https://github.com/pyca/cryptography/)
for conventional crypto operations,
with more on the way.
It's also very easy to implement your own providers.

See [example.py](example.py) to see it in action.