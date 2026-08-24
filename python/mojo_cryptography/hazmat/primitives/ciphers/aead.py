from __future__ import annotations

import os

from ....exceptions import InvalidTag
from ...._lib import aesgcm, chacha20poly1305

_MAX_SIZE = 2**31 - 1


def _buffer(data):
    if isinstance(data, (bytes, bytearray)):
        return data
    return memoryview(data)


def _buffer_length(data) -> int:
    return data.nbytes if isinstance(data, memoryview) else len(data)


def _check_size(data, name: str) -> None:
    if _buffer_length(data) > _MAX_SIZE:
        raise OverflowError(f"{name} exceeds the maximum supported size")


class AESGCM:
    def __init__(self, key: bytes):
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError("AESGCM key must be 128, 192, or 256 bits.")
        self._key = key

    @classmethod
    def generate_key(cls, bit_length: int) -> bytes:
        if bit_length not in (128, 192, 256):
            raise ValueError("bit_length must be 128, 192, or 256")
        return os.urandom(bit_length // 8)

    def encrypt(
        self, nonce: bytes, data: bytes, associated_data: bytes | None
    ) -> bytes:
        nonce = bytes(nonce)
        if not 8 <= len(nonce) <= 128:
            raise ValueError("Nonce must be between 8 and 128 bytes")
        data = _buffer(data)
        aad = b"" if associated_data is None else _buffer(associated_data)
        _check_size(data, "data")
        _check_size(aad, "associated_data")
        result = aesgcm(False, self._key, nonce, data, aad)
        if result is None:
            raise ValueError("AES-GCM encryption failed")
        return result

    def decrypt(
        self, nonce: bytes, data: bytes, associated_data: bytes | None
    ) -> bytes:
        nonce = bytes(nonce)
        if not 8 <= len(nonce) <= 128:
            raise ValueError("Nonce must be between 8 and 128 bytes")
        data = _buffer(data)
        _check_size(data, "data")
        if _buffer_length(data) < 16:
            raise InvalidTag
        aad = b"" if associated_data is None else _buffer(associated_data)
        _check_size(aad, "associated_data")
        result = aesgcm(True, self._key, nonce, data, aad)
        if result is None:
            raise InvalidTag
        return result


class ChaCha20Poly1305:
    def __init__(self, key: bytes):
        key = bytes(key)
        if len(key) != 32:
            raise ValueError("ChaCha20Poly1305 key must be 32 bytes.")
        self._key = key

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(32)

    def encrypt(
        self,
        nonce: bytes,
        data: bytes,
        associated_data: bytes | None,
        device: str = "cpu",
    ) -> bytes:
        nonce = bytes(nonce)
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        data = _buffer(data)
        aad = b"" if associated_data is None else _buffer(associated_data)
        _check_size(data, "data")
        _check_size(aad, "associated_data")
        if device not in ("cpu", "gpu"):
            raise ValueError("device must be 'cpu' or 'gpu'")
        result = chacha20poly1305(
            False, self._key, nonce, data, aad, device == "gpu"
        )
        if result is None:
            raise ValueError("ChaCha20-Poly1305 encryption failed")
        return result

    def decrypt(
        self,
        nonce: bytes,
        data: bytes,
        associated_data: bytes | None,
        device: str = "cpu",
    ) -> bytes:
        nonce = bytes(nonce)
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        data = _buffer(data)
        _check_size(data, "data")
        if _buffer_length(data) < 16:
            raise InvalidTag
        aad = b"" if associated_data is None else _buffer(associated_data)
        _check_size(aad, "associated_data")
        if device not in ("cpu", "gpu"):
            raise ValueError("device must be 'cpu' or 'gpu'")
        result = chacha20poly1305(
            True, self._key, nonce, data, aad, device == "gpu"
        )
        if result is None:
            raise InvalidTag
        return result


__all__ = ["AESGCM", "ChaCha20Poly1305"]
