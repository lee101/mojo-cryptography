from __future__ import annotations

import hmac

from ....exceptions import AlreadyFinalized, InvalidKey
from ...._lib import hkdf
from .. import hashes


class HKDF:
    def __init__(
        self,
        algorithm: hashes.HashAlgorithm,
        length: int,
        salt: bytes | None,
        info: bytes | None,
        backend=None,
    ):
        if not isinstance(algorithm, (hashes.SHA256, hashes.SHA512)):
            raise TypeError("mojo-cryptography HKDF supports SHA256 and SHA512")
        if length < 0 or length > 255 * algorithm.digest_size:
            raise ValueError("Cannot derive keys larger than 255 times the hash length")
        self._algorithm = algorithm
        self._length = length
        self._salt = b"" if salt is None else bytes(salt)
        self._info = b"" if info is None else bytes(info)
        self._used = False

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise AlreadyFinalized("Context was already finalized.")
        self._used = True
        return hkdf(
            self._algorithm.digest_size * 8,
            self._salt,
            bytes(key_material),
            self._info,
            self._length,
        )

    def verify(self, key_material: bytes, expected_key: bytes) -> None:
        if not hmac.compare_digest(self.derive(key_material), expected_key):
            raise InvalidKey
