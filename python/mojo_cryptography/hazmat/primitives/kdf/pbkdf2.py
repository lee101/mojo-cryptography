from __future__ import annotations

import hmac

from ....exceptions import AlreadyFinalized, InvalidKey
from ...._lib import pbkdf2
from .. import hashes


class PBKDF2HMAC:
    def __init__(
        self,
        algorithm: hashes.HashAlgorithm,
        length: int,
        salt: bytes,
        iterations: int,
        backend=None,
    ):
        if not isinstance(algorithm, (hashes.SHA256, hashes.SHA512)):
            raise TypeError("mojo-cryptography PBKDF2 supports SHA256 and SHA512")
        if length < 0:
            raise ValueError("length must be non-negative")
        if iterations < 1:
            raise ValueError("iterations must be positive")
        if iterations > 2**63 - 1:
            raise OverflowError("iterations does not fit the Mojo C ABI")
        self._algorithm = algorithm
        self._length = length
        self._salt = bytes(salt)
        self._iterations = iterations
        self._used = False

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise AlreadyFinalized("Context was already finalized.")
        self._used = True
        return pbkdf2(
            self._algorithm.digest_size * 8,
            bytes(key_material),
            self._salt,
            self._iterations,
            self._length,
        )

    def verify(self, key_material: bytes, expected_key: bytes) -> None:
        if not hmac.compare_digest(self.derive(key_material), expected_key):
            raise InvalidKey
