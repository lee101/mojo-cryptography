import hashlib

import pytest

from mojo_cryptography import AlreadyFinalized
from mojo_cryptography.hazmat.primitives import hashes


ALGORITHMS = [
    (hashes.SHA224, hashlib.sha224),
    (hashes.SHA256, hashlib.sha256),
    (hashes.SHA384, hashlib.sha384),
    (hashes.SHA512, hashlib.sha512),
]


@pytest.mark.parametrize("algorithm,reference", ALGORITHMS)
@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"abc",
        bytes(range(63)),
        bytes(range(64)),
        bytes(range(65)),
        bytes(range(128)) * 9,
    ],
)
def test_digest_parity(algorithm, reference, data):
    context = hashes.Hash(algorithm())
    context.update(data[: len(data) // 2])
    context.update(data[len(data) // 2 :])
    assert context.finalize() == reference(data).digest()


def test_sha256_published_vector():
    context = hashes.Hash(hashes.SHA256())
    context.update(b"abc")
    assert context.finalize().hex() == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


@pytest.mark.parametrize("data_len", [3, 4, 5, 131])
def test_digest_simd_tail(data_len):
    data = bytes((i * 31 + 9) & 255 for i in range(data_len))
    for algorithm, reference in ALGORITHMS:
        context = hashes.Hash(algorithm())
        context.update(data)
        assert context.finalize() == reference(data).digest()


def test_hash_copy_and_properties():
    context = hashes.Hash(hashes.SHA512())
    context.update(b"prefix")
    copied = context.copy()
    context.update(b"-one")
    copied.update(b"-two")
    assert context.algorithm.name == "sha512"
    assert context.finalize() == hashlib.sha512(b"prefix-one").digest()
    assert copied.finalize() == hashlib.sha512(b"prefix-two").digest()


def test_hash_finalization_is_one_shot():
    context = hashes.Hash(hashes.SHA256())
    context.finalize()
    with pytest.raises(AlreadyFinalized):
        context.finalize()
    with pytest.raises(AlreadyFinalized):
        context.update(b"x")
    with pytest.raises(AlreadyFinalized):
        context.copy()
