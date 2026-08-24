from __future__ import annotations

import math
import os
import platform
import subprocess
import sys
import time

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "python"
    ),
)

from cryptography.hazmat.primitives import hashes as reference_hashes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM as ReferenceAESGCM,
    ChaCha20Poly1305 as ReferenceChaCha20Poly1305,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as ReferenceHKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import (
    PBKDF2HMAC as ReferencePBKDF2,
)

from mojo_cryptography.hazmat.primitives import hashes
from mojo_cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)
from mojo_cryptography.hazmat.primitives.kdf.hkdf import HKDF
from mojo_cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from mojo_cryptography._lib import gpu_available


def best_time(function, repeat: int = 3) -> float:
    best = math.inf
    for _ in range(repeat):
        start = time.perf_counter()
        function()
        best = min(best, time.perf_counter() - start)
    return best


def hash_once(algorithm, data: bytes) -> bytes:
    context = hashes.Hash(algorithm)
    context.update(data)
    return context.finalize()


def reference_hash_once(algorithm, data: bytes) -> bytes:
    context = reference_hashes.Hash(algorithm)
    context.update(data)
    return context.finalize()


def cpu_name() -> str:
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown CPU"


def gpu_memory_free_mib() -> int:
    try:
        output = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=memory.free",
                "--format=csv,noheader,nounits",
            ],
            text=True,
            timeout=5,
        )
        return max(int(line.strip()) for line in output.splitlines())
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0


def main() -> None:
    data = bytes(range(256)) * 16_384
    aad = bytes(range(32))
    key = bytes(range(32))
    nonce = bytes(range(12))

    aes_ours = AESGCM(key)
    aes_reference = ReferenceAESGCM(key)
    chacha_ours = ChaCha20Poly1305(key)
    chacha_reference = ReferenceChaCha20Poly1305(key)

    cases = [
        (
            "SHA-256, 4 MiB",
            lambda: hash_once(hashes.SHA256(), data),
            lambda: reference_hash_once(reference_hashes.SHA256(), data),
        ),
        (
            "SHA-512, 4 MiB",
            lambda: hash_once(hashes.SHA512(), data),
            lambda: reference_hash_once(reference_hashes.SHA512(), data),
        ),
        (
            "PBKDF2-HMAC-SHA256, 10k iterations",
            lambda: PBKDF2HMAC(
                hashes.SHA256(), 32, b"benchmark salt", 10_000
            ).derive(b"benchmark password"),
            lambda: ReferencePBKDF2(
                reference_hashes.SHA256(), 32, b"benchmark salt", 10_000
            ).derive(b"benchmark password"),
        ),
        (
            "HKDF-SHA256, 4096-byte output",
            lambda: HKDF(
                hashes.SHA256(), 4096, b"benchmark salt", b"context"
            ).derive(key),
            lambda: ReferenceHKDF(
                reference_hashes.SHA256(), 4096, b"benchmark salt", b"context"
            ).derive(key),
        ),
        (
            "AES-256-GCM encrypt, 4 MiB",
            lambda: aes_ours.encrypt(nonce, data, aad),
            lambda: aes_reference.encrypt(nonce, data, aad),
        ),
        (
            "ChaCha20-Poly1305 encrypt, 4 MiB",
            lambda: chacha_ours.encrypt(nonce, data, aad),
            lambda: chacha_reference.encrypt(nonce, data, aad),
        ),
    ]

    free_gpu_mib = gpu_memory_free_mib()
    if free_gpu_mib >= 4_000 and gpu_available():
        cases.append(
            (
                "ChaCha20-Poly1305 GPU encrypt, 4 MiB",
                lambda: chacha_ours.encrypt(
                    nonce, data, aad, device="gpu"
                ),
                lambda: chacha_reference.encrypt(nonce, data, aad),
            )
        )
    elif free_gpu_mib < 4_000:
        print(
            "GPU benchmark skipped: less than 4000 MiB device memory is free."
        )
    else:
        print("GPU benchmark skipped: no usable accelerator context.")

    print(f"Machine: {cpu_name()} ({platform.system()} {platform.machine()})")
    print()
    print("| operation | Mojo | upstream cryptography | upstream / Mojo |")
    print("| --- | ---: | ---: | ---: |")
    for name, ours, reference in cases:
        assert ours() == reference()
        ours_time = best_time(ours)
        reference_time = best_time(reference)
        ratio = reference_time / ours_time
        label = "faster" if ratio > 1 else "slower"
        ratio_text = f"{ratio:.3f}x" if ratio < 0.1 else f"{ratio:.2f}x"
        print(
            f"| {name} | {ours_time * 1000:.2f} ms | "
            f"{reference_time * 1000:.2f} ms | {ratio_text} {label} |"
        )


if __name__ == "__main__":
    main()
