from __future__ import annotations

import ctypes
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIB = os.environ.get("MOJO_CRYPTOGRAPHY_LIB") or os.path.join(
    ROOT, "dist", "libmojo-cryptography.so"
)

I = ctypes.c_int64
_SIGNATURES = {
    "mc_gpu_available": ([], I),
    "mc_digest": ([I, I, I, I], I),
    "mc_pbkdf2": ([I, I, I, I, I, I, I, I], I),
    "mc_hkdf": ([I, I, I, I, I, I, I, I, I], I),
    "mc_aesgcm_encrypt": ([I] * 9, I),
    "mc_aesgcm_decrypt": ([I] * 9, I),
    "mc_chacha20poly1305_encrypt": ([I] * 8, I),
    "mc_chacha20poly1305_decrypt": ([I] * 8, I),
}

_loaded: ctypes.CDLL | None = None
_EMPTY = ctypes.create_string_buffer(1)
_PyBytes_AsString = ctypes.pythonapi.PyBytes_AsString
_PyBytes_AsString.argtypes = [ctypes.py_object]
_PyBytes_AsString.restype = ctypes.c_void_p
_PyBytes_FromStringAndSize = ctypes.pythonapi.PyBytes_FromStringAndSize
_PyBytes_FromStringAndSize.argtypes = [ctypes.c_void_p, ctypes.c_ssize_t]
_PyBytes_FromStringAndSize.restype = ctypes.py_object


def build() -> str:
    source = os.path.join(ROOT, "src", "cryptography.mojo")
    needs_build = not os.path.exists(LIB)
    if (
        not os.environ.get("MOJO_CRYPTOGRAPHY_LIB")
        and os.path.exists(LIB)
        and os.path.getmtime(source) > os.path.getmtime(LIB)
    ):
        needs_build = True
    if needs_build:
        proc = subprocess.run(
            ["bash", os.path.join(ROOT, "build", "build.sh")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if proc.returncode or not os.path.exists(LIB):
            raise RuntimeError((proc.stderr or proc.stdout).strip())
    return LIB


def lib() -> ctypes.CDLL:
    global _loaded
    if _loaded is None:
        _loaded = ctypes.CDLL(build())
        for name, (argtypes, restype) in _SIGNATURES.items():
            fn = getattr(_loaded, name)
            fn.argtypes = argtypes
            fn.restype = restype
    return _loaded


def input_buffer(data: object):
    if isinstance(data, bytes):
        return data, _PyBytes_AsString(data), len(data)
    if isinstance(data, bytearray):
        if not data:
            return data, ctypes.addressof(_EMPTY), 0
        view = (ctypes.c_ubyte * len(data)).from_buffer(data)
        return view, ctypes.addressof(view), len(data)
    source = memoryview(data)
    if source.c_contiguous and not source.readonly:
        byte_view = source.cast("B")
        if not byte_view.nbytes:
            return byte_view, ctypes.addressof(_EMPTY), 0
        view = (ctypes.c_ubyte * byte_view.nbytes).from_buffer(byte_view)
        return (byte_view, view), ctypes.addressof(view), byte_view.nbytes
    # C-contiguous readonly and non-contiguous buffers need an owned staging
    # copy. memoryview.tobytes() follows the logical element order, including
    # strides, while bytes(source) is not reliable for every shaped exporter.
    raw = source.tobytes()
    return raw, _PyBytes_AsString(raw), len(raw)


def output_buffer(length: int):
    if length < 0:
        raise ValueError("output length must be non-negative")
    buffer = _PyBytes_FromStringAndSize(None, length)
    return buffer, _PyBytes_AsString(buffer)


def gpu_available() -> bool:
    return bool(lib().mc_gpu_available())


def digest(algorithm: int, data: bytes | bytearray) -> bytes:
    if algorithm not in (224, 256, 384, 512):
        raise ValueError("unsupported digest algorithm")
    source, source_addr, size = input_buffer(data)
    length = algorithm // 8
    result, result_addr = output_buffer(length)
    written = lib().mc_digest(algorithm, source_addr, size, result_addr)
    del source
    if written != length:
        raise ValueError("unsupported digest algorithm")
    return result


def pbkdf2(
    algorithm: int, key: bytes, salt: bytes, iterations: int, length: int
) -> bytes:
    if algorithm not in (256, 512) or iterations < 1 or length < 0:
        raise ValueError("invalid PBKDF2 parameters")
    key_buf, key_addr, key_len = input_buffer(key)
    salt_buf, salt_addr, salt_len = input_buffer(salt)
    result, result_addr = output_buffer(length)
    ok = lib().mc_pbkdf2(
        algorithm,
        key_addr,
        key_len,
        salt_addr,
        salt_len,
        iterations,
        result_addr,
        length,
    )
    del key_buf, salt_buf
    if not ok:
        raise ValueError("invalid PBKDF2 parameters")
    return result


def hkdf(
    algorithm: int, salt: bytes, key: bytes, info: bytes, length: int
) -> bytes:
    if algorithm not in (256, 512) or length < 0:
        raise ValueError("invalid HKDF parameters")
    salt_buf, salt_addr, salt_len = input_buffer(salt)
    key_buf, key_addr, key_len = input_buffer(key)
    info_buf, info_addr, info_len = input_buffer(info)
    result, result_addr = output_buffer(length)
    ok = lib().mc_hkdf(
        algorithm,
        salt_addr,
        salt_len,
        key_addr,
        key_len,
        info_addr,
        info_len,
        result_addr,
        length,
    )
    del salt_buf, key_buf, info_buf
    if not ok:
        raise ValueError("invalid HKDF parameters")
    return result


def aesgcm(
    decrypt: bool,
    key: bytes,
    nonce: bytes,
    data: bytes,
    associated_data: bytes,
) -> bytes | None:
    key_buf, key_addr, key_len = input_buffer(key)
    nonce_buf, nonce_addr, nonce_len = input_buffer(nonce)
    data_buf, data_addr, data_len = input_buffer(data)
    aad_buf, aad_addr, aad_len = input_buffer(associated_data)
    result_len = data_len - 16 if decrypt else data_len + 16
    if result_len < 0:
        return None
    result, result_addr = output_buffer(result_len)
    fn = lib().mc_aesgcm_decrypt if decrypt else lib().mc_aesgcm_encrypt
    ok = fn(
        key_addr,
        key_len,
        nonce_addr,
        nonce_len,
        data_addr,
        data_len,
        aad_addr,
        aad_len,
        result_addr,
    )
    del key_buf, nonce_buf, data_buf, aad_buf
    return result if ok else None


def chacha20poly1305(
    decrypt: bool,
    key: bytes,
    nonce: bytes,
    data: bytes,
    associated_data: bytes,
    use_gpu: bool = False,
) -> bytes | None:
    key_buf, key_addr, _ = input_buffer(key)
    nonce_buf, nonce_addr, _ = input_buffer(nonce)
    data_buf, data_addr, data_len = input_buffer(data)
    aad_buf, aad_addr, aad_len = input_buffer(associated_data)
    result_len = data_len - 16 if decrypt else data_len + 16
    if result_len < 0:
        return None
    result, result_addr = output_buffer(result_len)
    fn = (
        lib().mc_chacha20poly1305_decrypt
        if decrypt
        else lib().mc_chacha20poly1305_encrypt
    )
    ok = fn(
        key_addr,
        nonce_addr,
        data_addr,
        data_len,
        aad_addr,
        aad_len,
        result_addr,
        int(use_gpu),
    )
    del key_buf, nonce_buf, data_buf, aad_buf
    return result if ok else None
