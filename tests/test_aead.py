import pytest
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM as UpstreamAESGCM,
    ChaCha20Poly1305 as UpstreamChaCha20Poly1305,
)

from mojo_cryptography import InvalidTag
from mojo_cryptography._lib import input_buffer
from mojo_cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("nonce_len", [8, 12, 13, 128])
@pytest.mark.parametrize("data_len", [0, 1, 16, 17, 257])
def test_aesgcm_upstream_parity(key_len, nonce_len, data_len):
    key = bytes(range(key_len))
    nonce = bytes(range(nonce_len))
    data = bytes((i * 17 + 3) & 255 for i in range(data_len))
    aad = bytes(range(23))
    encrypted = AESGCM(key).encrypt(nonce, data, aad)
    assert encrypted == UpstreamAESGCM(key).encrypt(nonce, data, aad)
    assert AESGCM(key).decrypt(nonce, encrypted, aad) == data


def test_aesgcm_nist_empty_vector():
    key = b"\0" * 16
    nonce = b"\0" * 12
    assert AESGCM(key).encrypt(nonce, b"", b"").hex() == (
        "58e2fccefa7e3061367f1d57a4e7455a"
    )


def test_aesgcm_nist_one_block_vector():
    key = b"\0" * 16
    nonce = b"\0" * 12
    assert AESGCM(key).encrypt(nonce, b"\0" * 16, b"").hex() == (
        "0388dace60b6a392f328c2b971b2fe78"
        "ab6e47d42cec13bdf53a67b21257bddf"
    )


@pytest.mark.parametrize("cipher_cls", [AESGCM, ChaCha20Poly1305])
def test_aead_rejects_modified_tag_without_plaintext(cipher_cls):
    key = bytes(range(32))
    cipher = cipher_cls(key)
    encrypted = bytearray(cipher.encrypt(b"\1" * 12, b"secret", b"header"))
    encrypted[-1] ^= 1
    with pytest.raises(InvalidTag):
        cipher.decrypt(b"\1" * 12, encrypted, b"header")


@pytest.mark.parametrize("data_len", [0, 1, 15, 16, 17, 63, 64, 65, 1025])
@pytest.mark.parametrize("aad_len", [0, 15, 16, 17])
def test_chacha20poly1305_upstream_parity(data_len, aad_len):
    key = bytes(range(32))
    nonce = bytes(range(12))
    data = bytes((i * 29 + 11) & 255 for i in range(data_len))
    aad = bytes((i * 7) & 255 for i in range(aad_len))
    encrypted = ChaCha20Poly1305(key).encrypt(nonce, data, aad)
    assert encrypted == UpstreamChaCha20Poly1305(key).encrypt(
        nonce, data, aad
    )
    assert ChaCha20Poly1305(key).decrypt(nonce, encrypted, aad) == data


def test_chacha20poly1305_rfc8439_vector():
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only "
        b"one tip for the future, sunscreen would be it."
    )
    expected = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "61161ae10b594f09e26a7e902ecbd060"
        "0691"
    )
    assert ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad) == expected


@pytest.mark.parametrize("data_len", [262_143, 262_144, 262_157])
def test_chacha20poly1305_parallel_threshold(data_len):
    key = bytes(range(32))
    nonce = bytes(range(12))
    data = bytes((i * 13 + 7) & 255 for i in range(data_len))
    aad = b"parallel threshold"
    encrypted = ChaCha20Poly1305(key).encrypt(nonce, data, aad)
    assert encrypted == UpstreamChaCha20Poly1305(key).encrypt(
        nonce, data, aad
    )
    assert ChaCha20Poly1305(key).decrypt(nonce, encrypted, aad) == data


@pytest.mark.parametrize("data_len", [262_143, 262_144, 262_157])
def test_aesgcm_parallel_threshold(data_len):
    key = bytes(range(32))
    nonce = bytes(range(12))
    data = bytes((i * 11 + 5) & 255 for i in range(data_len))
    aad = b"parallel threshold"
    encrypted = AESGCM(key).encrypt(nonce, data, aad)
    assert encrypted == UpstreamAESGCM(key).encrypt(nonce, data, aad)
    assert AESGCM(key).decrypt(nonce, encrypted, aad) == data


def test_chacha20poly1305_gpu_path_or_cpu_fallback():
    key = bytes(range(32))
    nonce = bytes(range(12))
    data = bytes((i * 19 + 3) & 255 for i in range(1_048_589))
    aad = b"optional GPU path"
    cipher = ChaCha20Poly1305(key)
    encrypted = cipher.encrypt(nonce, data, aad, device="gpu")
    assert encrypted == UpstreamChaCha20Poly1305(key).encrypt(
        nonce, data, aad
    )
    assert cipher.decrypt(nonce, encrypted, aad, device="gpu") == data


def test_chacha20poly1305_rejects_unknown_device():
    with pytest.raises(ValueError, match="device"):
        ChaCha20Poly1305(bytes(range(32))).encrypt(
            bytes(range(12)), b"", None, device="accelerator"
        )


def test_numpy_buffers_cross_ffi_zero_copy():
    key = bytes(range(32))
    nonce = bytes(range(12))
    data = np.arange(257, dtype=np.uint16).view(np.uint8)
    aad = np.arange(19, dtype=np.uint8)
    owner, address, size = input_buffer(data)
    assert owner
    assert address == data.ctypes.data
    assert size == data.nbytes
    encrypted = ChaCha20Poly1305(key).encrypt(nonce, data, aad)
    assert encrypted == UpstreamChaCha20Poly1305(key).encrypt(
        nonce, data.tobytes(), aad.tobytes()
    )


def test_noncontiguous_and_readonly_buffers_are_copied_in_logical_order():
    key = bytes(range(32))
    nonce = bytes(range(12))
    array = np.arange(80, dtype=np.uint8).reshape(8, 10)
    data = array[:, ::2]
    readonly = memoryview(bytes(range(19)))
    owner, address, size = input_buffer(data)
    assert isinstance(owner, bytes)
    assert size == data.nbytes
    encrypted = ChaCha20Poly1305(key).encrypt(nonce, data, readonly)
    assert encrypted == UpstreamChaCha20Poly1305(key).encrypt(
        nonce, data.tobytes(), readonly.tobytes()
    )


@pytest.mark.parametrize("cipher_cls", [AESGCM, ChaCha20Poly1305])
def test_short_ciphertext_is_rejected_before_ffi_allocation(cipher_cls):
    cipher = cipher_cls(bytes(range(32)))
    with pytest.raises(InvalidTag):
        cipher.decrypt(bytes(range(12)), b"short", None)


def test_generate_key_lengths():
    assert len(AESGCM.generate_key(128)) == 16
    assert len(AESGCM.generate_key(192)) == 24
    assert len(AESGCM.generate_key(256)) == 32
    assert len(ChaCha20Poly1305.generate_key()) == 32


@pytest.mark.parametrize("nonce_len", [0, 7, 129])
def test_aesgcm_rejects_nonce_outside_documented_range(nonce_len):
    with pytest.raises(ValueError):
        AESGCM(bytes(range(16))).encrypt(b"x" * nonce_len, b"", None)
