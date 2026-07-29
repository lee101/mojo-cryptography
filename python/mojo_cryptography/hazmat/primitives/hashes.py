from __future__ import annotations

import hmac

from ...exceptions import AlreadyFinalized
from ..._lib import digest


class HashAlgorithm:
    name: str
    digest_size: int
    block_size: int


class SHA224(HashAlgorithm):
    name = "sha224"
    digest_size = 28
    block_size = 64


class SHA256(HashAlgorithm):
    name = "sha256"
    digest_size = 32
    block_size = 64


class SHA384(HashAlgorithm):
    name = "sha384"
    digest_size = 48
    block_size = 128


class SHA512(HashAlgorithm):
    name = "sha512"
    digest_size = 64
    block_size = 128


class Hash:
    def __init__(self, algorithm: HashAlgorithm, backend=None):
        if not isinstance(algorithm, (SHA224, SHA256, SHA384, SHA512)):
            raise TypeError("Expected instance of hashes.HashAlgorithm.")
        self._algorithm = algorithm
        self._data = bytearray()
        self._finalized = False

    @property
    def algorithm(self) -> HashAlgorithm:
        return self._algorithm

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._data.extend(data)

    def finalize(self) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._finalized = True
        return digest(self._algorithm.digest_size * 8, self._data)

    def copy(self) -> Hash:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        other = Hash(self._algorithm)
        other._data = self._data.copy()
        return other


def _verify(expected: bytes, actual: bytes) -> bool:
    return hmac.compare_digest(expected, actual)


__all__ = [
    "Hash",
    "HashAlgorithm",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
]
