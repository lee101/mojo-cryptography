"""Cryptographic kernels exported through a small C ABI."""

from std.algorithm import parallelize
from std.bit import bit_reverse, byte_swap
from std.sys.info import simd_width_of
from std.sys.intrinsics import llvm_intrinsic

comptime BPtr = UnsafePointer[UInt8, AnyOrigin[mut=True]]
comptime U32Ptr = UnsafePointer[UInt32, AnyOrigin[mut=True]]
comptime U64Ptr = UnsafePointer[UInt64, AnyOrigin[mut=True]]


@always_inline
def rotr32(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (UInt32(32) - n))


@always_inline
def rotr64(x: UInt64, n: UInt64) -> UInt64:
    return (x >> n) | (x << (UInt64(64) - n))


@always_inline
def load_be32(data: UnsafePointer[UInt8, _], i: Int) -> UInt32:
    return (
        (UInt32(data[i]) << 24)
        | (UInt32(data[i + 1]) << 16)
        | (UInt32(data[i + 2]) << 8)
        | UInt32(data[i + 3])
    )


@always_inline
def load_be64(data: UnsafePointer[UInt8, _], i: Int) -> UInt64:
    return (
        (UInt64(data[i]) << 56)
        | (UInt64(data[i + 1]) << 48)
        | (UInt64(data[i + 2]) << 40)
        | (UInt64(data[i + 3]) << 32)
        | (UInt64(data[i + 4]) << 24)
        | (UInt64(data[i + 5]) << 16)
        | (UInt64(data[i + 6]) << 8)
        | UInt64(data[i + 7])
    )


@always_inline
def store_be32[dst_origin: MutOrigin](
    dst: UnsafePointer[UInt8, dst_origin], i: Int, x: UInt32
):
    dst[i] = UInt8(x >> 24)
    dst[i + 1] = UInt8(x >> 16)
    dst[i + 2] = UInt8(x >> 8)
    dst[i + 3] = UInt8(x)


@always_inline
def store_be64[dst_origin: MutOrigin](
    dst: UnsafePointer[UInt8, dst_origin], i: Int, x: UInt64
):
    dst[i] = UInt8(x >> 56)
    dst[i + 1] = UInt8(x >> 48)
    dst[i + 2] = UInt8(x >> 40)
    dst[i + 3] = UInt8(x >> 32)
    dst[i + 4] = UInt8(x >> 24)
    dst[i + 5] = UInt8(x >> 16)
    dst[i + 6] = UInt8(x >> 8)
    dst[i + 7] = UInt8(x)


@always_inline
def copy_bytes[dst_origin: MutOrigin](
    dst: UnsafePointer[UInt8, dst_origin],
    source: UnsafePointer[UInt8, _],
    n: Int,
):
    comptime W = simd_width_of[DType.float64]()
    var i = 0
    while i + W <= n:
        dst.store(i, source.load[width=W](i))
        i += W
    while i < n:
        dst[i] = source[i]
        i += 1


@always_inline
def xor_bytes[dst_origin: MutOrigin](
    dst: UnsafePointer[UInt8, dst_origin],
    left: UnsafePointer[UInt8, _],
    right: UnsafePointer[UInt8, _],
    n: Int,
):
    comptime W = simd_width_of[DType.float64]()
    var i = 0
    while i + W <= n:
        dst.store(
            i,
            left.load[width=W](i) ^ right.load[width=W](i),
        )
        i += W
    while i < n:
        dst[i] = left[i] ^ right[i]
        i += 1


def sha256_k(i: Int) -> UInt32:
    var k: InlineArray[UInt32, 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ]
    return k[i]


def sha256_compress[state_origin: MutOrigin](
    data: UnsafePointer[UInt8, _],
    offset: Int,
    state: UnsafePointer[UInt32, state_origin],
):
    comptime W = simd_width_of[DType.float64]()
    var w = InlineArray[UInt32, 64](fill=0)
    var source_words = (data + offset).bitcast[UInt32]()
    var i = 0
    while i + W <= 16:
        w.unsafe_ptr().store(
            i,
            byte_swap(
                source_words.load[width=W, alignment=1](i)
            ),
        )
        i += W
    while i < 16:
        w[i] = load_be32(data, offset + i * 4)
        i += 1
    for i in range(16, 64):
        var a = w[i - 15]
        var b = w[i - 2]
        var s0 = rotr32(a, 7) ^ rotr32(a, 18) ^ (a >> 3)
        var s1 = rotr32(b, 17) ^ rotr32(b, 19) ^ (b >> 10)
        w[i] = w[i - 16] + s0 + w[i - 7] + s1
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    for i in range(64):
        var s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
        var ch = (e & f) ^ ((~e) & g)
        var t1 = h + s1 + ch + sha256_k(i) + w[i]
        var s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var t2 = s0 + maj
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h


def sha256_init[state_origin: MutOrigin](
    state: UnsafePointer[UInt32, state_origin], variant: Int
):
    if variant == 224:
        state[0] = 0xC1059ED8
        state[1] = 0x367CD507
        state[2] = 0x3070DD17
        state[3] = 0xF70E5939
        state[4] = 0xFFC00B31
        state[5] = 0x68581511
        state[6] = 0x64F98FA7
        state[7] = 0xBEFA4FA4
    else:
        state[0] = 0x6A09E667
        state[1] = 0xBB67AE85
        state[2] = 0x3C6EF372
        state[3] = 0xA54FF53A
        state[4] = 0x510E527F
        state[5] = 0x9B05688C
        state[6] = 0x1F83D9AB
        state[7] = 0x5BE0CD19


def sha256_finish[state_origin: MutOrigin, dst_origin: MutOrigin](
    data: UnsafePointer[UInt8, _],
    n: Int,
    state: UnsafePointer[UInt32, state_origin],
    prefix: Int,
    dst: UnsafePointer[UInt8, dst_origin],
    words: Int,
):
    var i = 0
    while i + 64 <= n:
        sha256_compress(data, i, state)
        i += 64
    var tail = InlineArray[UInt8, 128](fill=0)
    var rem = n - i
    for j in range(rem):
        tail[j] = data[i + j]
    tail[rem] = 0x80
    var total = prefix + n
    var final_size = 64 if rem < 56 else 128
    var bits = UInt64(total) * 8
    for j in range(8):
        tail[final_size - 1 - j] = UInt8(bits >> UInt64(j * 8))
    sha256_compress(tail.unsafe_ptr(), 0, state)
    if final_size == 128:
        sha256_compress(tail.unsafe_ptr(), 64, state)
    for j in range(words):
        store_be32(dst, j * 4, state[j])


def sha256_hash[dst_origin: MutOrigin](
    data: UnsafePointer[UInt8, _],
    n: Int,
    dst: UnsafePointer[UInt8, dst_origin],
    variant: Int,
):
    var state = InlineArray[UInt32, 8](fill=0)
    sha256_init(state.unsafe_ptr(), variant)
    sha256_finish(data, n, state.unsafe_ptr(), 0, dst, 7 if variant == 224 else 8)


def sha512_k(i: Int) -> UInt64:
    var k: InlineArray[UInt64, 80] = [
        0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,
        0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,
        0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,
        0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
        0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
        0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,
        0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,
        0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
        0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,
        0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,
        0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,
        0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
        0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,
        0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
        0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC,
        0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,
        0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
        0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,
        0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
        0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
        0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
    ]
    return k[i]


def sha512_compress[state_origin: MutOrigin](
    data: UnsafePointer[UInt8, _],
    offset: Int,
    state: UnsafePointer[UInt64, state_origin],
):
    comptime W = simd_width_of[DType.float64]()
    var w = InlineArray[UInt64, 80](fill=0)
    var source_words = (data + offset).bitcast[UInt64]()
    var i = 0
    while i + W <= 16:
        w.unsafe_ptr().store(
            i,
            byte_swap(
                source_words.load[width=W, alignment=1](i)
            ),
        )
        i += W
    while i < 16:
        w[i] = load_be64(data, offset + i * 8)
        i += 1
    for i in range(16, 80):
        var a = w[i - 15]
        var b = w[i - 2]
        var s0 = rotr64(a, 1) ^ rotr64(a, 8) ^ (a >> 7)
        var s1 = rotr64(b, 19) ^ rotr64(b, 61) ^ (b >> 6)
        w[i] = w[i - 16] + s0 + w[i - 7] + s1
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    for i in range(80):
        var s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
        var ch = (e & f) ^ ((~e) & g)
        var t1 = h + s1 + ch + sha512_k(i) + w[i]
        var s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var t2 = s0 + maj
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h


def sha512_init[state_origin: MutOrigin](
    state: UnsafePointer[UInt64, state_origin], variant: Int
):
    if variant == 384:
        state[0] = 0xCBBB9D5DC1059ED8
        state[1] = 0x629A292A367CD507
        state[2] = 0x9159015A3070DD17
        state[3] = 0x152FECD8F70E5939
        state[4] = 0x67332667FFC00B31
        state[5] = 0x8EB44A8768581511
        state[6] = 0xDB0C2E0D64F98FA7
        state[7] = 0x47B5481DBEFA4FA4
    else:
        state[0] = 0x6A09E667F3BCC908
        state[1] = 0xBB67AE8584CAA73B
        state[2] = 0x3C6EF372FE94F82B
        state[3] = 0xA54FF53A5F1D36F1
        state[4] = 0x510E527FADE682D1
        state[5] = 0x9B05688C2B3E6C1F
        state[6] = 0x1F83D9ABFB41BD6B
        state[7] = 0x5BE0CD19137E2179


def sha512_finish[state_origin: MutOrigin, dst_origin: MutOrigin](
    data: UnsafePointer[UInt8, _],
    n: Int,
    state: UnsafePointer[UInt64, state_origin],
    prefix: Int,
    dst: UnsafePointer[UInt8, dst_origin],
    words: Int,
):
    var i = 0
    while i + 128 <= n:
        sha512_compress(data, i, state)
        i += 128
    var tail = InlineArray[UInt8, 256](fill=0)
    var rem = n - i
    for j in range(rem):
        tail[j] = data[i + j]
    tail[rem] = 0x80
    var total = prefix + n
    var final_size = 128 if rem < 112 else 256
    var bits = UInt64(total) * 8
    for j in range(8):
        tail[final_size - 1 - j] = UInt8(bits >> UInt64(j * 8))
    sha512_compress(tail.unsafe_ptr(), 0, state)
    if final_size == 256:
        sha512_compress(tail.unsafe_ptr(), 128, state)
    for j in range(words):
        store_be64(dst, j * 8, state[j])


def sha512_hash[dst_origin: MutOrigin](
    data: UnsafePointer[UInt8, _],
    n: Int,
    dst: UnsafePointer[UInt8, dst_origin],
    variant: Int,
):
    var state = InlineArray[UInt64, 8](fill=0)
    sha512_init(state.unsafe_ptr(), variant)
    sha512_finish(data, n, state.unsafe_ptr(), 0, dst, 6 if variant == 384 else 8)


@always_inline
def segment_byte(
    a: UnsafePointer[UInt8, _],
    na: Int,
    b: UnsafePointer[UInt8, _],
    nb: Int,
    c: UnsafePointer[UInt8, _],
    nc: Int,
    i: Int,
) -> UInt8:
    if i < na:
        return a[i]
    if i < na + nb:
        return b[i - na]
    return c[i - na - nb]


def sha256_segments[state_origin: MutOrigin, dst_origin: MutOrigin](
    state: UnsafePointer[UInt32, state_origin],
    prefix: Int,
    a: UnsafePointer[UInt8, _],
    na: Int,
    b: UnsafePointer[UInt8, _],
    nb: Int,
    c: UnsafePointer[UInt8, _],
    nc: Int,
    dst: UnsafePointer[UInt8, dst_origin],
):
    var total = na + nb + nc
    var padded = ((total + 9 + 63) // 64) * 64
    var block = InlineArray[UInt8, 64](fill=0)
    var offset = 0
    while offset < padded:
        for j in range(64):
            var pos = offset + j
            if pos < total:
                block[j] = segment_byte(a, na, b, nb, c, nc, pos)
            elif pos == total:
                block[j] = 0x80
            elif pos >= padded - 8:
                var shift = UInt64((padded - 1 - pos) * 8)
                block[j] = UInt8((UInt64(prefix + total) * 8) >> shift)
            else:
                block[j] = 0
        sha256_compress(block.unsafe_ptr(), 0, state)
        offset += 64
    for j in range(8):
        store_be32(dst, j * 4, state[j])


def sha512_segments[state_origin: MutOrigin, dst_origin: MutOrigin](
    state: UnsafePointer[UInt64, state_origin],
    prefix: Int,
    a: UnsafePointer[UInt8, _],
    na: Int,
    b: UnsafePointer[UInt8, _],
    nb: Int,
    c: UnsafePointer[UInt8, _],
    nc: Int,
    dst: UnsafePointer[UInt8, dst_origin],
):
    var total = na + nb + nc
    var padded = ((total + 17 + 127) // 128) * 128
    var block = InlineArray[UInt8, 128](fill=0)
    var offset = 0
    while offset < padded:
        for j in range(128):
            var pos = offset + j
            if pos < total:
                block[j] = segment_byte(a, na, b, nb, c, nc, pos)
            elif pos == total:
                block[j] = 0x80
            elif pos >= padded - 8:
                var shift = UInt64((padded - 1 - pos) * 8)
                block[j] = UInt8((UInt64(prefix + total) * 8) >> shift)
            else:
                block[j] = 0
        sha512_compress(block.unsafe_ptr(), 0, state)
        offset += 128
    for j in range(8):
        store_be64(dst, j * 8, state[j])


def hmac_sha256_states[
    inner_origin: MutOrigin,
    outer_origin: MutOrigin,
](
    key: UnsafePointer[UInt8, _],
    key_len: Int,
    inner_state: UnsafePointer[UInt32, inner_origin],
    outer_state: UnsafePointer[UInt32, outer_origin],
):
    comptime W = simd_width_of[DType.float64]()
    var pad = InlineArray[UInt8, 64](fill=0)
    if key_len > 64:
        sha256_hash(key, key_len, pad.unsafe_ptr(), 256)
    else:
        copy_bytes(pad.unsafe_ptr(), key, key_len)
    var i = 0
    while i + W <= 64:
        pad.unsafe_ptr().store(
            i,
            pad.unsafe_ptr().load[width=W](i)
                ^ SIMD[DType.uint8, W](0x36),
        )
        i += W
    while i < 64:
        pad[i] ^= 0x36
        i += 1
    sha256_init(inner_state, 256)
    sha256_compress(pad.unsafe_ptr(), 0, inner_state)
    i = 0
    while i + W <= 64:
        pad.unsafe_ptr().store(
            i,
            pad.unsafe_ptr().load[width=W](i)
                ^ SIMD[DType.uint8, W](0x36 ^ 0x5C),
        )
        i += W
    while i < 64:
        pad[i] ^= 0x36 ^ 0x5C
        i += 1
    sha256_init(outer_state, 256)
    sha256_compress(pad.unsafe_ptr(), 0, outer_state)


def hmac_sha256_prepared[dst_origin: MutOrigin](
    inner_base: UnsafePointer[UInt32, _],
    outer_base: UnsafePointer[UInt32, _],
    a: UnsafePointer[UInt8, _],
    na: Int,
    b: UnsafePointer[UInt8, _],
    nb: Int,
    c: UnsafePointer[UInt8, _],
    nc: Int,
    dst: UnsafePointer[UInt8, dst_origin],
):
    comptime W = simd_width_of[DType.float64]()
    var inner_state = InlineArray[UInt32, 8](fill=0)
    var i = 0
    while i + W <= 8:
        inner_state.unsafe_ptr().store(
            i, inner_base.load[width=W](i)
        )
        i += W
    while i < 8:
        inner_state[i] = inner_base[i]
        i += 1
    var inner = InlineArray[UInt8, 32](fill=0)
    sha256_segments(
        inner_state.unsafe_ptr(), 64, a, na, b, nb, c, nc, inner.unsafe_ptr()
    )
    var outer_state = InlineArray[UInt32, 8](fill=0)
    var empty1 = InlineArray[UInt8, 1](fill=0)
    var empty2 = InlineArray[UInt8, 1](fill=0)
    i = 0
    while i + W <= 8:
        outer_state.unsafe_ptr().store(
            i, outer_base.load[width=W](i)
        )
        i += W
    while i < 8:
        outer_state[i] = outer_base[i]
        i += 1
    sha256_segments(
        outer_state.unsafe_ptr(), 64,
        inner.unsafe_ptr(), 32,
        empty1.unsafe_ptr(), 0, empty2.unsafe_ptr(), 0, dst,
    )


def hmac_sha256[dst_origin: MutOrigin](
    key: UnsafePointer[UInt8, _],
    key_len: Int,
    a: UnsafePointer[UInt8, _],
    na: Int,
    b: UnsafePointer[UInt8, _],
    nb: Int,
    c: UnsafePointer[UInt8, _],
    nc: Int,
    dst: UnsafePointer[UInt8, dst_origin],
):
    var inner_state = InlineArray[UInt32, 8](fill=0)
    var outer_state = InlineArray[UInt32, 8](fill=0)
    hmac_sha256_states(
        key,
        key_len,
        inner_state.unsafe_ptr(),
        outer_state.unsafe_ptr(),
    )
    hmac_sha256_prepared(
        inner_state.unsafe_ptr(),
        outer_state.unsafe_ptr(),
        a,
        na,
        b,
        nb,
        c,
        nc,
        dst,
    )


def hmac_sha512_states[
    inner_origin: MutOrigin,
    outer_origin: MutOrigin,
](
    key: UnsafePointer[UInt8, _],
    key_len: Int,
    inner_state: UnsafePointer[UInt64, inner_origin],
    outer_state: UnsafePointer[UInt64, outer_origin],
):
    comptime W = simd_width_of[DType.float64]()
    var pad = InlineArray[UInt8, 128](fill=0)
    if key_len > 128:
        sha512_hash(key, key_len, pad.unsafe_ptr(), 512)
    else:
        copy_bytes(pad.unsafe_ptr(), key, key_len)
    var i = 0
    while i + W <= 128:
        pad.unsafe_ptr().store(
            i,
            pad.unsafe_ptr().load[width=W](i)
                ^ SIMD[DType.uint8, W](0x36),
        )
        i += W
    while i < 128:
        pad[i] ^= 0x36
        i += 1
    sha512_init(inner_state, 512)
    sha512_compress(pad.unsafe_ptr(), 0, inner_state)
    i = 0
    while i + W <= 128:
        pad.unsafe_ptr().store(
            i,
            pad.unsafe_ptr().load[width=W](i)
                ^ SIMD[DType.uint8, W](0x36 ^ 0x5C),
        )
        i += W
    while i < 128:
        pad[i] ^= 0x36 ^ 0x5C
        i += 1
    sha512_init(outer_state, 512)
    sha512_compress(pad.unsafe_ptr(), 0, outer_state)


def hmac_sha512_prepared[dst_origin: MutOrigin](
    inner_base: UnsafePointer[UInt64, _],
    outer_base: UnsafePointer[UInt64, _],
    a: UnsafePointer[UInt8, _],
    na: Int,
    b: UnsafePointer[UInt8, _],
    nb: Int,
    c: UnsafePointer[UInt8, _],
    nc: Int,
    dst: UnsafePointer[UInt8, dst_origin],
):
    comptime W = simd_width_of[DType.float64]()
    var inner_state = InlineArray[UInt64, 8](fill=0)
    var i = 0
    while i + W <= 8:
        inner_state.unsafe_ptr().store(
            i, inner_base.load[width=W](i)
        )
        i += W
    while i < 8:
        inner_state[i] = inner_base[i]
        i += 1
    var inner = InlineArray[UInt8, 64](fill=0)
    sha512_segments(
        inner_state.unsafe_ptr(), 128, a, na, b, nb, c, nc, inner.unsafe_ptr()
    )
    var outer_state = InlineArray[UInt64, 8](fill=0)
    var empty1 = InlineArray[UInt8, 1](fill=0)
    var empty2 = InlineArray[UInt8, 1](fill=0)
    i = 0
    while i + W <= 8:
        outer_state.unsafe_ptr().store(
            i, outer_base.load[width=W](i)
        )
        i += W
    while i < 8:
        outer_state[i] = outer_base[i]
        i += 1
    sha512_segments(
        outer_state.unsafe_ptr(), 128,
        inner.unsafe_ptr(), 64,
        empty1.unsafe_ptr(), 0, empty2.unsafe_ptr(), 0, dst,
    )


def hmac_sha512[dst_origin: MutOrigin](
    key: UnsafePointer[UInt8, _],
    key_len: Int,
    a: UnsafePointer[UInt8, _],
    na: Int,
    b: UnsafePointer[UInt8, _],
    nb: Int,
    c: UnsafePointer[UInt8, _],
    nc: Int,
    dst: UnsafePointer[UInt8, dst_origin],
):
    var inner_state = InlineArray[UInt64, 8](fill=0)
    var outer_state = InlineArray[UInt64, 8](fill=0)
    hmac_sha512_states(
        key,
        key_len,
        inner_state.unsafe_ptr(),
        outer_state.unsafe_ptr(),
    )
    hmac_sha512_prepared(
        inner_state.unsafe_ptr(),
        outer_state.unsafe_ptr(),
        a,
        na,
        b,
        nb,
        c,
        nc,
        dst,
    )


@export("mc_pbkdf2")
def mc_pbkdf2(
    algorithm: Int,
    key_addr: Int,
    key_len: Int,
    salt_addr: Int,
    salt_len: Int,
    iterations: Int,
    dst_addr: Int,
    dst_len: Int,
) abi("C") -> Int:
    if (
        (algorithm != 256 and algorithm != 512)
        or key_addr == 0 or salt_addr == 0 or dst_addr == 0
        or key_len < 0 or salt_len < 0 or dst_len < 0
        or iterations < 1
    ):
        return 0
    var key = BPtr(unsafe_from_address=key_addr)
    var salt = BPtr(unsafe_from_address=salt_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)
    var counter = InlineArray[UInt8, 4](fill=0)
    var u = InlineArray[UInt8, 64](fill=0)
    var next_u = InlineArray[UInt8, 64](fill=0)
    var t = InlineArray[UInt8, 64](fill=0)
    var empty1 = InlineArray[UInt8, 1](fill=0)
    var empty2 = InlineArray[UInt8, 1](fill=0)
    var digest_len = 32 if algorithm == 256 else 64
    var inner256 = InlineArray[UInt32, 8](fill=0)
    var outer256 = InlineArray[UInt32, 8](fill=0)
    var inner512 = InlineArray[UInt64, 8](fill=0)
    var outer512 = InlineArray[UInt64, 8](fill=0)
    if algorithm == 256:
        hmac_sha256_states(
            key, key_len, inner256.unsafe_ptr(), outer256.unsafe_ptr()
        )
    else:
        hmac_sha512_states(
            key, key_len, inner512.unsafe_ptr(), outer512.unsafe_ptr()
        )
    var block_index = 1
    var written = 0
    while written < dst_len:
        counter[0] = UInt8(UInt32(block_index) >> 24)
        counter[1] = UInt8(UInt32(block_index) >> 16)
        counter[2] = UInt8(UInt32(block_index) >> 8)
        counter[3] = UInt8(UInt32(block_index))
        if algorithm == 256:
            hmac_sha256_prepared(
                inner256.unsafe_ptr(), outer256.unsafe_ptr(),
                salt, salt_len, counter.unsafe_ptr(), 4,
                empty1.unsafe_ptr(), 0, u.unsafe_ptr(),
            )
        else:
            hmac_sha512_prepared(
                inner512.unsafe_ptr(), outer512.unsafe_ptr(),
                salt, salt_len, counter.unsafe_ptr(), 4,
                empty1.unsafe_ptr(), 0, u.unsafe_ptr(),
            )
        for j in range(digest_len):
            t[j] = u[j]
        for _ in range(1, iterations):
            if algorithm == 256:
                hmac_sha256_prepared(
                    inner256.unsafe_ptr(), outer256.unsafe_ptr(),
                    u.unsafe_ptr(), digest_len,
                    empty1.unsafe_ptr(), 0, empty2.unsafe_ptr(), 0,
                    next_u.unsafe_ptr(),
                )
            else:
                hmac_sha512_prepared(
                    inner512.unsafe_ptr(), outer512.unsafe_ptr(),
                    u.unsafe_ptr(), digest_len,
                    empty1.unsafe_ptr(), 0, empty2.unsafe_ptr(), 0,
                    next_u.unsafe_ptr(),
                )
            comptime W = simd_width_of[DType.float64]()
            var j = 0
            while j + W <= digest_len:
                var next_values = next_u.unsafe_ptr().load[width=W](j)
                u.unsafe_ptr().store(j, next_values)
                t.unsafe_ptr().store(
                    j, t.unsafe_ptr().load[width=W](j) ^ next_values
                )
                j += W
            while j < digest_len:
                u[j] = next_u[j]
                t[j] ^= u[j]
                j += 1
        var take = digest_len
        if take > dst_len - written:
            take = dst_len - written
        for j in range(take):
            dst[written + j] = t[j]
        written += take
        block_index += 1
    return 1


@export("mc_hkdf")
def mc_hkdf(
    algorithm: Int,
    salt_addr: Int,
    salt_len: Int,
    key_addr: Int,
    key_len: Int,
    info_addr: Int,
    info_len: Int,
    dst_addr: Int,
    dst_len: Int,
) abi("C") -> Int:
    if (
        (algorithm != 256 and algorithm != 512)
        or salt_addr == 0 or key_addr == 0 or info_addr == 0 or dst_addr == 0
        or salt_len < 0 or key_len < 0 or info_len < 0 or dst_len < 0
    ):
        return 0
    var salt = BPtr(unsafe_from_address=salt_addr)
    var key = BPtr(unsafe_from_address=key_addr)
    var info = BPtr(unsafe_from_address=info_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)
    var prk = InlineArray[UInt8, 64](fill=0)
    var previous = InlineArray[UInt8, 64](fill=0)
    var next_block = InlineArray[UInt8, 64](fill=0)
    var counter = InlineArray[UInt8, 1](fill=0)
    var empty1 = InlineArray[UInt8, 1](fill=0)
    var empty2 = InlineArray[UInt8, 1](fill=0)
    var digest_len = 32 if algorithm == 256 else 64
    if dst_len > digest_len * 255:
        return 0
    if algorithm == 256:
        hmac_sha256(
            salt, salt_len, key, key_len,
            empty1.unsafe_ptr(), 0, empty2.unsafe_ptr(), 0, prk.unsafe_ptr()
        )
    else:
        hmac_sha512(
            salt, salt_len, key, key_len,
            empty1.unsafe_ptr(), 0, empty2.unsafe_ptr(), 0, prk.unsafe_ptr()
        )
    var inner256 = InlineArray[UInt32, 8](fill=0)
    var outer256 = InlineArray[UInt32, 8](fill=0)
    var inner512 = InlineArray[UInt64, 8](fill=0)
    var outer512 = InlineArray[UInt64, 8](fill=0)
    if algorithm == 256:
        hmac_sha256_states(
            prk.unsafe_ptr(),
            digest_len,
            inner256.unsafe_ptr(),
            outer256.unsafe_ptr(),
        )
    else:
        hmac_sha512_states(
            prk.unsafe_ptr(),
            digest_len,
            inner512.unsafe_ptr(),
            outer512.unsafe_ptr(),
        )
    var written = 0
    var block_index = 1
    while written < dst_len:
        counter[0] = UInt8(block_index)
        var previous_len = 0 if block_index == 1 else digest_len
        if algorithm == 256:
            hmac_sha256_prepared(
                inner256.unsafe_ptr(), outer256.unsafe_ptr(),
                previous.unsafe_ptr(), previous_len, info, info_len,
                counter.unsafe_ptr(), 1, next_block.unsafe_ptr(),
            )
        else:
            hmac_sha512_prepared(
                inner512.unsafe_ptr(), outer512.unsafe_ptr(),
                previous.unsafe_ptr(), previous_len, info, info_len,
                counter.unsafe_ptr(), 1, next_block.unsafe_ptr(),
            )
        for j in range(digest_len):
            previous[j] = next_block[j]
        var take = digest_len
        if take > dst_len - written:
            take = dst_len - written
        for j in range(take):
            dst[written + j] = previous[j]
        written += take
        block_index += 1
    return 1


# AES-GCM ---------------------------------------------------------------------

@always_inline
def aes_sbox(index: UInt8) -> UInt8:
    var table: InlineArray[UInt8, 256] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]
    return table[Int(index)]


@always_inline
def aes_xtime(x: UInt8) -> UInt8:
    return (x << 1) ^ (UInt8(0x1B) if (x & 0x80) != 0 else UInt8(0))


def aes_expand_key(
    key: UnsafePointer[UInt8, _], key_len: Int, expanded: BPtr
) -> Int:
    var rounds = key_len // 4 + 6
    var total = 16 * (rounds + 1)
    for i in range(key_len):
        expanded[i] = key[i]
    var generated = key_len
    var rcon = UInt8(1)
    var temp = InlineArray[UInt8, 4](fill=0)
    while generated < total:
        for j in range(4):
            temp[j] = expanded[generated - 4 + j]
        if generated % key_len == 0:
            var first = temp[0]
            temp[0] = aes_sbox(temp[1]) ^ rcon
            temp[1] = aes_sbox(temp[2])
            temp[2] = aes_sbox(temp[3])
            temp[3] = aes_sbox(first)
            rcon = aes_xtime(rcon)
        elif key_len == 32 and generated % key_len == 16:
            for j in range(4):
                temp[j] = aes_sbox(temp[j])
        for j in range(4):
            expanded[generated] = expanded[generated - key_len] ^ temp[j]
            generated += 1
    return rounds


@always_inline
def aes_add_key(state: BPtr, expanded: BPtr, offset: Int):
    for i in range(16):
        state[i] ^= expanded[offset + i]


@always_inline
def aes_shift_rows(state: BPtr):
    var t = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = state[13]
    state[13] = t
    t = state[2]
    var u = state[6]
    state[2] = state[10]
    state[6] = state[14]
    state[10] = t
    state[14] = u
    t = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = state[3]
    state[3] = t


@always_inline
def aes_mix_columns(state: BPtr):
    for column in range(4):
        var i = column * 4
        var a = state[i]
        var b = state[i + 1]
        var c = state[i + 2]
        var d = state[i + 3]
        var all = a ^ b ^ c ^ d
        state[i] = a ^ all ^ aes_xtime(a ^ b)
        state[i + 1] = b ^ all ^ aes_xtime(b ^ c)
        state[i + 2] = c ^ all ^ aes_xtime(c ^ d)
        state[i + 3] = d ^ all ^ aes_xtime(d ^ a)


def aes_encrypt_block_scalar(
    source: UnsafePointer[UInt8, _],
    destination: BPtr,
    expanded: BPtr,
    rounds: Int,
):
    var state = InlineArray[UInt8, 16](fill=0)
    var state_ptr = BPtr(unsafe_from_address=Int(state.unsafe_ptr()))
    for i in range(16):
        state[i] = source[i]
    aes_add_key(state_ptr, expanded, 0)
    for round_index in range(1, rounds):
        for i in range(16):
            state[i] = aes_sbox(state[i])
        aes_shift_rows(state_ptr)
        aes_mix_columns(state_ptr)
        aes_add_key(state_ptr, expanded, round_index * 16)
    for i in range(16):
        state[i] = aes_sbox(state[i])
    aes_shift_rows(state_ptr)
    aes_add_key(state_ptr, expanded, rounds * 16)
    for i in range(16):
        destination[i] = state[i]


@always_inline
def aes_encrypt_block(
    source: UnsafePointer[UInt8, _],
    destination: BPtr,
    expanded: BPtr,
    rounds: Int,
):
    comptime Block = SIMD[DType.uint64, 2]
    var source_words = source.bitcast[UInt64]()
    var destination_words = destination.bitcast[UInt64]()
    var key_words = expanded.bitcast[UInt64]()
    var state = (
        source_words.load[width=2, alignment=1]()
        ^ key_words.load[width=2, alignment=1]()
    )
    for round_index in range(1, rounds):
        state = llvm_intrinsic[
            "llvm.x86.aesni.aesenc", Block, Block, Block
        ](
            state,
            key_words.load[width=2, alignment=1](round_index * 2),
        )
    state = llvm_intrinsic[
        "llvm.x86.aesni.aesenclast", Block, Block, Block
    ](
        state,
        key_words.load[width=2, alignment=1](rounds * 2),
    )
    destination_words.store[alignment=1](state)


@always_inline
def ghash_multiply(
    state: U64Ptr,
    h_hi: UInt64,
    h_lo: UInt64,
):
    comptime Block = SIMD[DType.uint64, 2]
    var left = Block(
        bit_reverse(state[0]),
        bit_reverse(state[1]),
    )
    var right = Block(
        bit_reverse(h_hi),
        bit_reverse(h_lo),
    )
    var p0 = llvm_intrinsic[
        "llvm.x86.pclmulqdq", Block, Block, Block, UInt8
    ](left, right, 0x00)
    var p1 = llvm_intrinsic[
        "llvm.x86.pclmulqdq", Block, Block, Block, UInt8
    ](left, right, 0x11)
    var mixed_left = Block(left[0] ^ left[1], 0)
    var mixed_right = Block(right[0] ^ right[1], 0)
    var middle = llvm_intrinsic[
        "llvm.x86.pclmulqdq", Block, Block, Block, UInt8
    ](mixed_left, mixed_right, 0x00) ^ p0 ^ p1
    var r0 = UInt64(p0[0])
    var r1 = UInt64(p0[1] ^ middle[0])
    var r2 = UInt64(p1[0] ^ middle[1])
    var r3 = UInt64(p1[1])
    r0 ^= r2 ^ (r2 << 1) ^ (r2 << 2) ^ (r2 << 7)
    r1 ^= (
        r3
        ^ (r3 << 1)
        ^ (r3 << 2)
        ^ (r3 << 7)
        ^ (r2 >> 63)
        ^ (r2 >> 62)
        ^ (r2 >> 57)
    )
    var overflow = (r3 >> 63) ^ (r3 >> 62) ^ (r3 >> 57)
    r0 ^= (
        overflow
        ^ (overflow << 1)
        ^ (overflow << 2)
        ^ (overflow << 7)
    )
    state[0] = bit_reverse(r0)
    state[1] = bit_reverse(r1)


def ghash_block(
    state: U64Ptr,
    h_hi: UInt64,
    h_lo: UInt64,
    data: UnsafePointer[UInt8, _],
    n: Int,
):
    if n == 16:
        state[0] ^= load_be64(data, 0)
        state[1] ^= load_be64(data, 8)
    else:
        var block = InlineArray[UInt8, 16](fill=0)
        copy_bytes(block.unsafe_ptr(), data, n)
        state[0] ^= load_be64(block.unsafe_ptr(), 0)
        state[1] ^= load_be64(block.unsafe_ptr(), 8)
    ghash_multiply(state, h_hi, h_lo)


def ghash_update(
    state: U64Ptr,
    h_hi: UInt64,
    h_lo: UInt64,
    data: UnsafePointer[UInt8, _],
    n: Int,
):
    var offset = 0
    while offset < n:
        var count = 16
        if count > n - offset:
            count = n - offset
        ghash_block(state, h_hi, h_lo, data + offset, count)
        offset += count


def ghash_all(
    h: UnsafePointer[UInt8, _],
    aad: UnsafePointer[UInt8, _],
    aad_len: Int,
    data: UnsafePointer[UInt8, _],
    data_len: Int,
    destination: BPtr,
):
    var state = InlineArray[UInt64, 2](fill=0)
    var state_ptr = U64Ptr(unsafe_from_address=Int(state.unsafe_ptr()))
    var h_hi = load_be64(h, 0)
    var h_lo = load_be64(h, 8)
    ghash_update(state_ptr, h_hi, h_lo, aad, aad_len)
    ghash_update(state_ptr, h_hi, h_lo, data, data_len)
    var lengths = InlineArray[UInt8, 16](fill=0)
    store_be64(lengths.unsafe_ptr(), 0, UInt64(aad_len) * 8)
    store_be64(lengths.unsafe_ptr(), 8, UInt64(data_len) * 8)
    ghash_block(
        state_ptr,
        h_hi,
        h_lo,
        lengths.unsafe_ptr(),
        16,
    )
    store_be64(destination, 0, state[0])
    store_be64(destination, 8, state[1])


def increment32(counter: BPtr):
    for i in range(4):
        var pos = 15 - i
        counter[pos] += 1
        if counter[pos] != 0:
            break


def aes_gcm_prepare(
    key: UnsafePointer[UInt8, _],
    key_len: Int,
    nonce: UnsafePointer[UInt8, _],
    nonce_len: Int,
    expanded: BPtr,
    h: BPtr,
    j0: BPtr,
) -> Int:
    var rounds = aes_expand_key(key, key_len, expanded)
    var zero = InlineArray[UInt8, 16](fill=0)
    aes_encrypt_block(zero.unsafe_ptr(), h, expanded, rounds)
    if nonce_len == 12:
        for i in range(12):
            j0[i] = nonce[i]
        j0[12] = 0
        j0[13] = 0
        j0[14] = 0
        j0[15] = 1
    else:
        ghash_all(h, zero.unsafe_ptr(), 0, nonce, nonce_len, j0)
    return rounds


def aes_gcm_xor(
    source: UnsafePointer[UInt8, _],
    destination: BPtr,
    n: Int,
    expanded: BPtr,
    rounds: Int,
    j0: UnsafePointer[UInt8, _],
):
    var counter = InlineArray[UInt8, 16](fill=0)
    var stream = InlineArray[UInt8, 16](fill=0)
    var counter_ptr = BPtr(unsafe_from_address=Int(counter.unsafe_ptr()))
    var stream_ptr = BPtr(unsafe_from_address=Int(stream.unsafe_ptr()))
    copy_bytes(counter.unsafe_ptr(), j0, 16)
    var offset = 0
    while offset < n:
        increment32(counter_ptr)
        aes_encrypt_block(counter.unsafe_ptr(), stream_ptr, expanded, rounds)
        var count = 16
        if count > n - offset:
            count = n - offset
        xor_bytes(destination + offset, source + offset, stream.unsafe_ptr(), count)
        offset += count


@export("mc_aesgcm_encrypt")
def mc_aesgcm_encrypt(
    key_addr: Int,
    key_len: Int,
    nonce_addr: Int,
    nonce_len: Int,
    data_addr: Int,
    data_len: Int,
    aad_addr: Int,
    aad_len: Int,
    dst_addr: Int,
) abi("C") -> Int:
    if (
        key_addr == 0 or nonce_addr == 0 or data_addr == 0
        or aad_addr == 0 or dst_addr == 0
        or (key_len != 16 and key_len != 24 and key_len != 32)
        or nonce_len < 1 or data_len < 0 or aad_len < 0
    ):
        return 0
    var key = BPtr(unsafe_from_address=key_addr)
    var nonce = BPtr(unsafe_from_address=nonce_addr)
    var data = BPtr(unsafe_from_address=data_addr)
    var aad = BPtr(unsafe_from_address=aad_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)
    var expanded = InlineArray[UInt8, 240](fill=0)
    var h = InlineArray[UInt8, 16](fill=0)
    var j0 = InlineArray[UInt8, 16](fill=0)
    var tag_mask = InlineArray[UInt8, 16](fill=0)
    var expanded_ptr = BPtr(unsafe_from_address=Int(expanded.unsafe_ptr()))
    var h_ptr = BPtr(unsafe_from_address=Int(h.unsafe_ptr()))
    var j0_ptr = BPtr(unsafe_from_address=Int(j0.unsafe_ptr()))
    var rounds = aes_gcm_prepare(
        key, key_len, nonce, nonce_len, expanded_ptr, h_ptr, j0_ptr
    )
    aes_gcm_xor(data, dst, data_len, expanded_ptr, rounds, j0.unsafe_ptr())
    ghash_all(h.unsafe_ptr(), aad, aad_len, dst, data_len, dst + data_len)
    aes_encrypt_block(
        j0.unsafe_ptr(),
        BPtr(unsafe_from_address=Int(tag_mask.unsafe_ptr())),
        expanded_ptr,
        rounds,
    )
    for i in range(16):
        dst[data_len + i] ^= tag_mask[i]
    return 1


@export("mc_aesgcm_decrypt")
def mc_aesgcm_decrypt(
    key_addr: Int,
    key_len: Int,
    nonce_addr: Int,
    nonce_len: Int,
    data_addr: Int,
    data_len: Int,
    aad_addr: Int,
    aad_len: Int,
    dst_addr: Int,
) abi("C") -> Int:
    if (
        key_addr == 0 or nonce_addr == 0 or data_addr == 0
        or aad_addr == 0 or dst_addr == 0
        or (key_len != 16 and key_len != 24 and key_len != 32)
        or nonce_len < 1 or aad_len < 0
        or data_len < 16
    ):
        return 0
    var key = BPtr(unsafe_from_address=key_addr)
    var nonce = BPtr(unsafe_from_address=nonce_addr)
    var data = BPtr(unsafe_from_address=data_addr)
    var aad = BPtr(unsafe_from_address=aad_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)
    var expanded = InlineArray[UInt8, 240](fill=0)
    var h = InlineArray[UInt8, 16](fill=0)
    var j0 = InlineArray[UInt8, 16](fill=0)
    var expected = InlineArray[UInt8, 16](fill=0)
    var mask = InlineArray[UInt8, 16](fill=0)
    var expanded_ptr = BPtr(unsafe_from_address=Int(expanded.unsafe_ptr()))
    var rounds = aes_gcm_prepare(
        key, key_len, nonce, nonce_len, expanded_ptr,
        BPtr(unsafe_from_address=Int(h.unsafe_ptr())),
        BPtr(unsafe_from_address=Int(j0.unsafe_ptr())),
    )
    var plain_len = data_len - 16
    ghash_all(
        h.unsafe_ptr(), aad, aad_len, data, plain_len,
        BPtr(unsafe_from_address=Int(expected.unsafe_ptr())),
    )
    aes_encrypt_block(
        j0.unsafe_ptr(),
        BPtr(unsafe_from_address=Int(mask.unsafe_ptr())),
        expanded_ptr,
        rounds,
    )
    var difference = UInt8(0)
    for i in range(16):
        expected[i] ^= mask[i]
        difference |= expected[i] ^ data[plain_len + i]
    if difference != 0:
        return 0
    aes_gcm_xor(data, dst, plain_len, expanded_ptr, rounds, j0.unsafe_ptr())
    return 1


# ChaCha20-Poly1305 -----------------------------------------------------------

@always_inline
def load_le32(data: UnsafePointer[UInt8, _], i: Int) -> UInt32:
    return (
        UInt32(data[i])
        | (UInt32(data[i + 1]) << 8)
        | (UInt32(data[i + 2]) << 16)
        | (UInt32(data[i + 3]) << 24)
    )


@always_inline
def store_le32[dst_origin: MutOrigin](
    dst: UnsafePointer[UInt8, dst_origin], i: Int, x: UInt32
):
    dst[i] = UInt8(x)
    dst[i + 1] = UInt8(x >> 8)
    dst[i + 2] = UInt8(x >> 16)
    dst[i + 3] = UInt8(x >> 24)


@always_inline
def store_le64[dst_origin: MutOrigin](
    dst: UnsafePointer[UInt8, dst_origin], i: Int, x: UInt64
):
    for j in range(8):
        dst[i + j] = UInt8(x >> UInt64(j * 8))


@always_inline
def rotl32(x: UInt32, n: UInt32) -> UInt32:
    return (x << n) | (x >> (UInt32(32) - n))


@always_inline
def chacha_quarter(state: U32Ptr, a: Int, b: Int, c: Int, d: Int):
    state[a] += state[b]
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] += state[d]
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] += state[b]
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] += state[d]
    state[b] = rotl32(state[b] ^ state[c], 7)


def chacha_block(
    key: UnsafePointer[UInt8, _],
    nonce: UnsafePointer[UInt8, _],
    counter: UInt32,
    destination: BPtr,
):
    var initial = InlineArray[UInt32, 16](fill=0)
    initial[0] = 0x61707865
    initial[1] = 0x3320646E
    initial[2] = 0x79622D32
    initial[3] = 0x6B206574
    for i in range(8):
        initial[4 + i] = load_le32(key, i * 4)
    initial[12] = counter
    initial[13] = load_le32(nonce, 0)
    initial[14] = load_le32(nonce, 4)
    initial[15] = load_le32(nonce, 8)
    var working = InlineArray[UInt32, 16](fill=0)
    for i in range(16):
        working[i] = initial[i]
    var words = U32Ptr(unsafe_from_address=Int(working.unsafe_ptr()))
    for _ in range(10):
        chacha_quarter(words, 0, 4, 8, 12)
        chacha_quarter(words, 1, 5, 9, 13)
        chacha_quarter(words, 2, 6, 10, 14)
        chacha_quarter(words, 3, 7, 11, 15)
        chacha_quarter(words, 0, 5, 10, 15)
        chacha_quarter(words, 1, 6, 11, 12)
        chacha_quarter(words, 2, 7, 8, 13)
        chacha_quarter(words, 3, 4, 9, 14)
    for i in range(16):
        store_le32(destination, i * 4, working[i] + initial[i])


def chacha_xor_blocks(
    key: UnsafePointer[UInt8, _],
    nonce: UnsafePointer[UInt8, _],
    source: UnsafePointer[UInt8, _],
    destination: BPtr,
    first_block: Int,
    block_count: Int,
):
    var stream = InlineArray[UInt8, 64](fill=0)
    var stream_ptr = BPtr(unsafe_from_address=Int(stream.unsafe_ptr()))
    var block = first_block
    while block < first_block + block_count:
        chacha_block(key, nonce, UInt32(block + 1), stream_ptr)
        var offset = block * 64
        xor_bytes(
            destination + offset,
            source + offset,
            stream.unsafe_ptr(),
            64,
        )
        block += 1


def chacha_xor(
    key: UnsafePointer[UInt8, _],
    nonce: UnsafePointer[UInt8, _],
    source: UnsafePointer[UInt8, _],
    destination: BPtr,
    n: Int,
):
    comptime PARALLEL_THRESHOLD = 262_144
    comptime BLOCKS_PER_TASK = 1_024
    var full_blocks = n // 64
    if n >= PARALLEL_THRESHOLD:
        var task_count = (
            full_blocks + BLOCKS_PER_TASK - 1
        ) // BLOCKS_PER_TASK
        var key_address = Int(key)
        var nonce_address = Int(nonce)
        var source_address = Int(source)
        var destination_address = Int(destination)

        @parameter
        def work(task: Int):
            var first_block = task * BLOCKS_PER_TASK
            var count = BLOCKS_PER_TASK
            if count > full_blocks - first_block:
                count = full_blocks - first_block
            chacha_xor_blocks(
                BPtr(unsafe_from_address=key_address),
                BPtr(unsafe_from_address=nonce_address),
                BPtr(unsafe_from_address=source_address),
                BPtr(unsafe_from_address=destination_address),
                first_block,
                count,
            )

        parallelize[work](task_count, 16)
    else:
        chacha_xor_blocks(
            key, nonce, source, destination, 0, full_blocks
        )
    var offset = full_blocks * 64
    if offset < n:
        var stream = InlineArray[UInt8, 64](fill=0)
        chacha_block(
            key,
            nonce,
            UInt32(full_blocks + 1),
            BPtr(unsafe_from_address=Int(stream.unsafe_ptr())),
        )
        xor_bytes(
            destination + offset,
            source + offset,
            stream.unsafe_ptr(),
            n - offset,
        )


def poly1305_block(
    h: U64Ptr, r: U64Ptr, data: UnsafePointer[UInt8, _]
):
    var t0 = UInt64(load_le32(data, 0))
    var t1 = UInt64(load_le32(data, 4))
    var t2 = UInt64(load_le32(data, 8))
    var t3 = UInt64(load_le32(data, 12))
    h[0] += t0 & 0x3FFFFFF
    h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3FFFFFF
    h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3FFFFFF
    h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3FFFFFF
    h[4] += (t3 >> 8) | 0x1000000
    var d0 = h[0] * r[0] + h[1] * r[9] + h[2] * r[8] + h[3] * r[7] + h[4] * r[6]
    var d1 = h[0] * r[1] + h[1] * r[0] + h[2] * r[9] + h[3] * r[8] + h[4] * r[7]
    var d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * r[9] + h[4] * r[8]
    var d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * r[9]
    var d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0]
    var carry = d0 >> 26
    h[0] = d0 & 0x3FFFFFF
    d1 += carry
    carry = d1 >> 26
    h[1] = d1 & 0x3FFFFFF
    d2 += carry
    carry = d2 >> 26
    h[2] = d2 & 0x3FFFFFF
    d3 += carry
    carry = d3 >> 26
    h[3] = d3 & 0x3FFFFFF
    d4 += carry
    carry = d4 >> 26
    h[4] = d4 & 0x3FFFFFF
    h[0] += carry * 5
    carry = h[0] >> 26
    h[0] &= 0x3FFFFFF
    h[1] += carry


def poly1305_update(
    h: U64Ptr, r: U64Ptr, data: UnsafePointer[UInt8, _], n: Int
):
    var offset = 0
    while offset + 16 <= n:
        poly1305_block(h, r, data + offset)
        offset += 16
    if offset < n:
        var padded = InlineArray[UInt8, 16](fill=0)
        for i in range(n - offset):
            padded[i] = data[offset + i]
        poly1305_block(h, r, padded.unsafe_ptr())


def poly1305_auth(
    one_time_key: UnsafePointer[UInt8, _],
    aad: UnsafePointer[UInt8, _],
    aad_len: Int,
    data: UnsafePointer[UInt8, _],
    data_len: Int,
    destination: BPtr,
):
    var r = InlineArray[UInt64, 10](fill=0)
    var h = InlineArray[UInt64, 5](fill=0)
    var r_ptr = U64Ptr(unsafe_from_address=Int(r.unsafe_ptr()))
    var h_ptr = U64Ptr(unsafe_from_address=Int(h.unsafe_ptr()))
    var t0 = UInt64(load_le32(one_time_key, 0))
    var t1 = UInt64(load_le32(one_time_key, 4))
    var t2 = UInt64(load_le32(one_time_key, 8))
    var t3 = UInt64(load_le32(one_time_key, 12))
    r[0] = t0 & 0x3FFFFFF
    r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3FFFF03
    r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3FFC0FF
    r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3F03FFF
    r[4] = (t3 >> 8) & 0x00FFFFF
    r[5] = r[0] * 5
    r[6] = r[1] * 5
    r[7] = r[2] * 5
    r[8] = r[3] * 5
    r[9] = r[4] * 5
    poly1305_update(h_ptr, r_ptr, aad, aad_len)
    poly1305_update(h_ptr, r_ptr, data, data_len)
    var lengths = InlineArray[UInt8, 16](fill=0)
    store_le64(lengths.unsafe_ptr(), 0, UInt64(aad_len))
    store_le64(lengths.unsafe_ptr(), 8, UInt64(data_len))
    poly1305_block(h_ptr, r_ptr, lengths.unsafe_ptr())
    var carry = h[1] >> 26
    h[1] &= 0x3FFFFFF
    h[2] += carry
    carry = h[2] >> 26
    h[2] &= 0x3FFFFFF
    h[3] += carry
    carry = h[3] >> 26
    h[3] &= 0x3FFFFFF
    h[4] += carry
    carry = h[4] >> 26
    h[4] &= 0x3FFFFFF
    h[0] += carry * 5
    carry = h[0] >> 26
    h[0] &= 0x3FFFFFF
    h[1] += carry
    var g0 = h[0] + 5
    carry = g0 >> 26
    g0 &= 0x3FFFFFF
    var g1 = h[1] + carry
    carry = g1 >> 26
    g1 &= 0x3FFFFFF
    var g2 = h[2] + carry
    carry = g2 >> 26
    g2 &= 0x3FFFFFF
    var g3 = h[3] + carry
    carry = g3 >> 26
    g3 &= 0x3FFFFFF
    var g4 = h[4] + carry - 0x4000000
    var mask = (g4 >> 63) - 1
    var inverse = ~mask
    h[0] = (h[0] & inverse) | (g0 & mask)
    h[1] = (h[1] & inverse) | (g1 & mask)
    h[2] = (h[2] & inverse) | (g2 & mask)
    h[3] = (h[3] & inverse) | (g3 & mask)
    h[4] = (h[4] & inverse) | (g4 & mask)
    var f0 = ((h[0] | (h[1] << 26)) & 0xFFFFFFFF) + UInt64(load_le32(one_time_key, 16))
    var f1 = (((h[1] >> 6) | (h[2] << 20)) & 0xFFFFFFFF) + UInt64(load_le32(one_time_key, 20)) + (f0 >> 32)
    var f2 = (((h[2] >> 12) | (h[3] << 14)) & 0xFFFFFFFF) + UInt64(load_le32(one_time_key, 24)) + (f1 >> 32)
    var f3 = (((h[3] >> 18) | (h[4] << 8)) & 0xFFFFFFFF) + UInt64(load_le32(one_time_key, 28)) + (f2 >> 32)
    store_le32(destination, 0, UInt32(f0))
    store_le32(destination, 4, UInt32(f1))
    store_le32(destination, 8, UInt32(f2))
    store_le32(destination, 12, UInt32(f3))


@export("mc_chacha20poly1305_encrypt")
def mc_chacha20poly1305_encrypt(
    key_addr: Int,
    nonce_addr: Int,
    data_addr: Int,
    data_len: Int,
    aad_addr: Int,
    aad_len: Int,
    dst_addr: Int,
) abi("C") -> Int:
    if (
        key_addr == 0 or nonce_addr == 0 or data_addr == 0
        or aad_addr == 0 or dst_addr == 0
        or data_len < 0 or aad_len < 0
    ):
        return 0
    var key = BPtr(unsafe_from_address=key_addr)
    var nonce = BPtr(unsafe_from_address=nonce_addr)
    var data = BPtr(unsafe_from_address=data_addr)
    var aad = BPtr(unsafe_from_address=aad_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)
    var first_block = InlineArray[UInt8, 64](fill=0)
    chacha_block(
        key, nonce, 0, BPtr(unsafe_from_address=Int(first_block.unsafe_ptr()))
    )
    chacha_xor(key, nonce, data, dst, data_len)
    poly1305_auth(
        first_block.unsafe_ptr(), aad, aad_len, dst, data_len, dst + data_len
    )
    return 1


@export("mc_chacha20poly1305_decrypt")
def mc_chacha20poly1305_decrypt(
    key_addr: Int,
    nonce_addr: Int,
    data_addr: Int,
    data_len: Int,
    aad_addr: Int,
    aad_len: Int,
    dst_addr: Int,
) abi("C") -> Int:
    if (
        key_addr == 0 or nonce_addr == 0 or data_addr == 0
        or aad_addr == 0 or dst_addr == 0
        or aad_len < 0 or data_len < 16
    ):
        return 0
    var key = BPtr(unsafe_from_address=key_addr)
    var nonce = BPtr(unsafe_from_address=nonce_addr)
    var data = BPtr(unsafe_from_address=data_addr)
    var aad = BPtr(unsafe_from_address=aad_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)
    var first_block = InlineArray[UInt8, 64](fill=0)
    var expected = InlineArray[UInt8, 16](fill=0)
    chacha_block(
        key, nonce, 0, BPtr(unsafe_from_address=Int(first_block.unsafe_ptr()))
    )
    var plain_len = data_len - 16
    poly1305_auth(
        first_block.unsafe_ptr(), aad, aad_len, data, plain_len,
        BPtr(unsafe_from_address=Int(expected.unsafe_ptr())),
    )
    var difference = UInt8(0)
    for i in range(16):
        difference |= expected[i] ^ data[plain_len + i]
    if difference != 0:
        return 0
    chacha_xor(key, nonce, data, dst, plain_len)
    return 1


@export("mc_digest")
def mc_digest(algorithm: Int, data_addr: Int, n: Int, dst_addr: Int) abi("C") -> Int:
    if data_addr == 0 or dst_addr == 0 or n < 0:
        return 0
    var data = BPtr(unsafe_from_address=data_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)
    if algorithm == 224 or algorithm == 256:
        sha256_hash(data, n, dst, algorithm)
        return 28 if algorithm == 224 else 32
    if algorithm == 384 or algorithm == 512:
        sha512_hash(data, n, dst, algorithm)
        return 48 if algorithm == 384 else 64
    return 0
