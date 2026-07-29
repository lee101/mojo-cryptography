# mojo-cryptography

A focused port of Python's
[`cryptography`](https://cryptography.io/) package to Mojo. The cryptographic
operations themselves run in a single Mojo shared library; Python provides
upstream-shaped classes and argument validation.

This is a real, standalone implementation, not a wrapper around OpenSSL or
upstream `cryptography`. It is useful when studying, testing, or embedding
cryptographic primitives implemented in Mojo. It has not received a
third-party security audit, so do not treat it as a replacement for an audited
production cryptography provider.

## Covered subset

The Python imports and method signatures mirror the corresponding upstream
classes after replacing `cryptography` with `mojo_cryptography`:

| Area | Covered API |
| --- | --- |
| AEAD | `AESGCM` with 128/192/256-bit keys and 8–128-byte nonces |
| AEAD | `ChaCha20Poly1305` with RFC 8439 96-bit nonces |
| Digests | `Hash`, `SHA224`, `SHA256`, `SHA384`, `SHA512` |
| KDF | `HKDF` with SHA-256 or SHA-512 |
| KDF | `PBKDF2HMAC` with SHA-256 or SHA-512 |

AEAD output uses the same `ciphertext || 16-byte tag` representation as
upstream. Decryption authenticates before writing plaintext, and tag checks
accumulate differences without an early exit.

Not covered are the streaming `Cipher` API; AES-CCM, AES-SIV and AES-GCM-SIV;
SHA-1, SHA-3, BLAKE and extendable-output hashes; scrypt, Argon2 and the other
KDF families; asymmetric cryptography; X.509; serialization; and OpenSSL
provider integration. Digest `Hash.update()` is API-compatible but currently
buffers chunks until `finalize()` rather than preserving a Mojo-side streaming
state.

## Install

The pinned Mojo nightly and all Python dependencies come from Pixi:

```bash
pixi install
pixi run build
```

The build task produces `dist/libmojo-cryptography.so`. Tests and benchmarks
always run inside the same environment:

```bash
pixi run test
pixi run bench
```

## Usage

This example is exercised by the same API paths used in the test suite:

```python
from mojo_cryptography.hazmat.primitives import hashes
from mojo_cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mojo_cryptography.hazmat.primitives.kdf.hkdf import HKDF

master_key = bytes(range(32))
key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"application salt",
    info=b"message key",
).derive(master_key)

nonce = bytes(range(12))
cipher = AESGCM(key)
encrypted = cipher.encrypt(nonce, b"Mojo cryptography", b"header")
assert cipher.decrypt(nonce, encrypted, b"header") == b"Mojo cryptography"

digest = hashes.Hash(hashes.SHA256())
digest.update(encrypted)
print(digest.finalize().hex())
```

Save it as `example.py` and run `pixi run python example.py`.

## Benchmarks

Measured with `pixi run bench` on an Intel Xeon E5-2697 v4 at 2.30 GHz,
Linux x86-64. Times are the best of three runs. The ratio is upstream time
divided by Mojo time, so values below 1 mean Mojo is slower.

| operation | Mojo | upstream cryptography | upstream / Mojo |
| --- | ---: | ---: | ---: |
| SHA-256, 4 MiB | 66.01 ms | 17.29 ms | 0.26x slower |
| SHA-512, 4 MiB | 75.86 ms | 8.00 ms | 0.11x slower |
| PBKDF2-HMAC-SHA256, 10k iterations | 29.74 ms | 10.07 ms | 0.34x slower |
| HKDF-SHA256, 4096-byte output | 0.49 ms | 0.28 ms | 0.57x slower |
| AES-256-GCM encrypt, 4 MiB | 20.79 ms | 2.49 ms | 0.12x slower |
| ChaCha20-Poly1305 encrypt, 4 MiB | 22.68 ms | 7.56 ms | 0.33x slower |

Upstream still wins every measured case through mature OpenSSL assembly.
This port now uses SIMD endian loads and byte XORs, caches prepared HMAC states,
uses AES-NI for AES rounds and PCLMULQDQ for GHASH, and parallelizes independent
ChaCha20 blocks above a 256 KiB threshold. Inputs backed by Python `bytes` or a
writable contiguous buffer such as a NumPy array cross the FFI boundary without
a staging copy.

No GPU path is implemented or benchmarked.

## How it works

`src/cryptography.mojo` is one compilation unit containing SHA-2 compression,
HMAC-based KDFs, AES key expansion and counter mode, GHASH, ChaCha20, and
Poly1305. The x86-64 AES and GHASH paths use AES-NI and PCLMULQDQ intrinsics;
ChaCha20 uses thresholded CPU parallelism. `build/build.sh` compiles it once with
`mojo build --emit shared-lib`.

The Python layer uses `ctypes`. Input bytes remain in their Python-owned
contiguous buffers and cross the C ABI as integer addresses plus lengths; Mojo reconstructs
`UnsafePointer[UInt8, AnyOrigin[mut=True]]` values inside non-parametric
exports. Output `bytes` are allocated once by Python and filled in place, so
ownership never crosses the FFI boundary and the Mojo library performs no heap
allocation. Multi-byte digest and GHASH words use big-endian layout; ChaCha20
and Poly1305 words use the little-endian layout specified by RFC 8439.

Correctness is checked against upstream `cryptography`, Python `hashlib`, NIST
AES-GCM vectors, RFC 5869 HKDF vectors, and RFC 8439
ChaCha20-Poly1305 vectors.

MIT licensed.
