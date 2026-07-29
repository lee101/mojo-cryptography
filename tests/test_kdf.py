import hashlib

import pytest
from cryptography.hazmat.primitives import hashes as upstream_hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as UpstreamHKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import (
    PBKDF2HMAC as UpstreamPBKDF2HMAC,
)

from mojo_cryptography import AlreadyFinalized, InvalidKey
from mojo_cryptography.hazmat.primitives import hashes
from mojo_cryptography.hazmat.primitives.kdf.hkdf import HKDF
from mojo_cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@pytest.mark.parametrize(
    "ours,theirs",
    [
        (hashes.SHA256, upstream_hashes.SHA256),
        (hashes.SHA512, upstream_hashes.SHA512),
    ],
)
@pytest.mark.parametrize("iterations,length", [(1, 16), (2, 32), (101, 42)])
def test_pbkdf2_upstream_parity(ours, theirs, iterations, length):
    key = bytes(range(81))
    salt = b"salt-with-a-non-block-size"
    got = PBKDF2HMAC(ours(), length, salt, iterations).derive(key)
    expected = UpstreamPBKDF2HMAC(
        theirs(), length, salt, iterations
    ).derive(key)
    assert got == expected


def test_pbkdf2_published_vector():
    got = PBKDF2HMAC(hashes.SHA256(), 32, b"salt", 1).derive(b"password")
    assert got.hex() == (
        "120fb6cffcf8b32c43e7225256c4f837"
        "a86548c92ccc35480805987cb70be17b"
    )
    assert got == hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1)


@pytest.mark.parametrize(
    "ours,theirs",
    [
        (hashes.SHA256, upstream_hashes.SHA256),
        (hashes.SHA512, upstream_hashes.SHA512),
    ],
)
@pytest.mark.parametrize("salt,info,length", [(None, None, 32), (b"", b"", 42), (b"salt", b"context", 80)])
def test_hkdf_upstream_parity(ours, theirs, salt, info, length):
    material = bytes(range(91))
    got = HKDF(ours(), length, salt, info).derive(material)
    expected = UpstreamHKDF(theirs(), length, salt, info).derive(material)
    assert got == expected


def test_hkdf_rfc5869_case_1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    got = HKDF(hashes.SHA256(), 42, salt, info).derive(ikm)
    assert got.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: HKDF(hashes.SHA256(), 32, b"salt", b"info"),
        lambda: PBKDF2HMAC(hashes.SHA256(), 32, b"salt", 10),
    ],
)
def test_kdf_context_is_one_shot(factory):
    context = factory()
    context.derive(b"key")
    with pytest.raises(AlreadyFinalized):
        context.derive(b"key")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: HKDF(hashes.SHA256(), 32, b"salt", b"info"),
        lambda: PBKDF2HMAC(hashes.SHA256(), 32, b"salt", 10),
    ],
)
def test_kdf_verify_rejects_wrong_key(factory):
    with pytest.raises(InvalidKey):
        factory().verify(b"key", b"\0" * 32)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: HKDF(hashes.SHA256(), -1, b"salt", b"info"),
        lambda: PBKDF2HMAC(hashes.SHA256(), -1, b"salt", 1),
        lambda: PBKDF2HMAC(hashes.SHA256(), 1, b"salt", 0),
    ],
)
def test_kdf_rejects_invalid_lengths_and_iterations(factory):
    with pytest.raises(ValueError):
        factory()


def test_pbkdf2_rejects_iterations_that_would_narrow_at_ffi():
    with pytest.raises(OverflowError):
        PBKDF2HMAC(hashes.SHA256(), 1, b"salt", 2**63)
