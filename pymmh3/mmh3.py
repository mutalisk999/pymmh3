# /usr/bin/env python

import struct

# RangeList = lambda x, y: list(range(x, y + 1))

# unsigned type
UINT8 = lambda a: a & 0xff
UINT16 = lambda a: a & 0xffff
UINT32 = lambda a: a & 0xffffffff
UINT64 = lambda a: a & 0xffffffffffffffff

# operator
UINT32_ADD = lambda a, b: UINT32(UINT32(a) + UINT32(b))
UINT32_MUL = lambda a, b: UINT32(UINT32(a) * UINT32(b))
UINT32_XOR = lambda a, b: UINT32(UINT32(a) ^ UINT32(b))
UINT32_LSFT = lambda a, b: UINT32(UINT32(a) << UINT8(b))
UINT32_RSFT = lambda a, b: UINT32(UINT32(a) >> UINT8(b))

UINT64_ADD = lambda a, b: UINT64(UINT64(a) + UINT64(b))
UINT64_MUL = lambda a, b: UINT64(UINT64(a) * UINT64(b))
UINT64_XOR = lambda a, b: UINT64(UINT64(a) ^ UINT64(b))
UINT64_LSFT = lambda a, b: UINT64(UINT64(a) << UINT8(b))
UINT64_RSFT = lambda a, b: UINT64(UINT64(a) >> UINT8(b))

# rotl
ROTL32 = lambda x, r: UINT32(UINT32_LSFT(x, r) | UINT32_RSFT(x, 32 - r))
ROTL64 = lambda x, r: UINT64(UINT64_LSFT(x, r) | UINT64_RSFT(x, 64 - r))

GetBlock32 = lambda p, i: struct.unpack("I", p[i * 4:(i + 1) * 4])[0]
GetBlock64 = lambda p, i: struct.unpack("Q", p[i * 8:(i + 1) * 8])[0]


def _fmix32(h):
    h = UINT32(h)
    h = UINT32_XOR(h, UINT32_RSFT(h, 16))
    h = UINT32_MUL(h, 0x85ebca6b)
    h = UINT32_XOR(h, UINT32_RSFT(h, 13))
    h = UINT32_MUL(h, 0xc2b2ae35)
    h = UINT32_XOR(h, UINT32_RSFT(h, 16))
    return h


def _fmix64(k):
    k = UINT64(k)
    k = UINT64_XOR(k, UINT64_RSFT(k, 33))
    k = UINT64_MUL(k, 0xff51afd7ed558ccd)
    k = UINT64_XOR(k, UINT64_RSFT(k, 33))
    k = UINT64_MUL(k, 0xc4ceb9fe1a85ec53)
    k = UINT64_XOR(k, UINT64_RSFT(k, 33))
    return k


def _mmh3_x86_32 (key, seed):
    if isinstance(key, str):
        key = key.encode("utf8")

    data = key
    nblocks = len(data) // 4

    h1 = UINT32(seed)
    c1 = UINT32(0xcc9e2d51)
    c2 = UINT32(0x1b873593)

    # body
    for i in range(-nblocks, 0):
        ii = nblocks + i
        k1 = GetBlock32(data, ii)

        k1 = UINT32_MUL(k1, c1)
        k1 = ROTL32(k1, 15)
        k1 = UINT32_MUL(k1, c2)

        h1 = UINT32_XOR(h1, k1)
        h1 = ROTL32(h1, 13)
        h1 = UINT32_ADD(UINT32_MUL(h1, 5), 0xe6546b64)

    # tail
    tail = data[nblocks * 4:]

    k1 = UINT32(0)

    v = len(data) & 3
    if v >= 3:
        k1 = UINT32_XOR(k1, UINT32_LSFT(tail[2], 16))

    if v >= 2:
        k1 = UINT32_XOR(k1, UINT32_LSFT(tail[1], 8))

    if v >= 1:
        k1 = UINT32_XOR(k1, tail[0])

    k1 = UINT32_MUL(k1, c1)
    k1 = ROTL32(k1, 15)
    k1 = UINT32_MUL(k1, c2)
    h1 = UINT32_XOR(h1, k1)

    # finalization
    h1 = UINT32_XOR(h1, len(data))
    h1 = _fmix32(h1)

    return h1


def _mmh3_x86_128 (key, seed):
    if isinstance(key, str):
        key = key.encode("utf8")

    data = key
    nblocks = len(data) // 16

    h1 = UINT32(seed)
    h2 = UINT32(seed)
    h3 = UINT32(seed)
    h4 = UINT32(seed)

    c1 = UINT32(0x239b961b)
    c2 = UINT32(0xab0e9789)
    c3 = UINT32(0x38b34ae5)
    c4 = UINT32(0xa1e38b93)

    # body
    for i in range(-nblocks, 0):
        ii = nblocks + i
        k1 = GetBlock32(data, ii * 4 + 0)
        k2 = GetBlock32(data, ii * 4 + 1)
        k3 = GetBlock32(data, ii * 4 + 2)
        k4 = GetBlock32(data, ii * 4 + 3)

        k1 = UINT32_MUL(k1, c1)
        k1 = ROTL32(k1, 15)
        k1 = UINT32_MUL(k1, c2)
        h1 = UINT32_XOR(h1, k1)

        h1 = ROTL32(h1, 19)
        h1 = UINT32_ADD(h1, h2)
        h1 = UINT32_ADD(UINT32_MUL(h1, 5), 0x561ccd1b)

        k2 = UINT32_MUL(k2, c2)
        k2 = ROTL32(k2, 16)
        k2 = UINT32_MUL(k2, c3)
        h2 = UINT32_XOR(h2, k2)

        h2 = ROTL32(h2, 17)
        h2 = UINT32_ADD(h2, h3)
        h2 = UINT32_ADD(UINT32_MUL(h2, 5), 0x0bcaa747)

        k3 = UINT32_MUL(k3, c3)
        k3 = ROTL32(k3, 17)
        k3 = UINT32_MUL(k3, c4)
        h3 = UINT32_XOR(h3, k3)

        h3 = ROTL32(h3, 15)
        h3 = UINT32_ADD(h3, h4)
        h3 = UINT32_ADD(UINT32_MUL(h3, 5), 0x96cd1c35)

        k4 = UINT32_MUL(k4, c4)
        k4 = ROTL32(k4, 18)
        k4 = UINT32_MUL(k4, c1)
        h4 = UINT32_XOR(h4, k4)

        h4 = ROTL32(h4, 13)
        h4 = UINT32_ADD(h4, h1)
        h4 = UINT32_ADD(UINT32_MUL(h4, 5), 0x32ac3b17)

    # tail
    tail = data[nblocks * 16:]

    k1 = UINT32(0)
    k2 = UINT32(0)
    k3 = UINT32(0)
    k4 = UINT32(0)

    v = len(data) & 15
    if v >= 15:
        k4 = UINT32_XOR(k4, UINT32_LSFT(tail[14], 16))

    if v >= 14:
        k4 = UINT32_XOR(k4, UINT32_LSFT(tail[13], 8))

    if v >= 13:
        k4 = UINT32_XOR(k4, UINT32_LSFT(tail[12], 0))
        k4 = UINT32_MUL(k4, c4)
        k4 = ROTL32(k4, 18)
        k4 = UINT32_MUL(k4, c1)
        h4 = UINT32_XOR(h4, k4)

    if v >= 12:
        k3 = UINT32_XOR(k3, UINT32_LSFT(tail[11], 24))

    if v >= 11:
        k3 = UINT32_XOR(k3, UINT32_LSFT(tail[10], 16))

    if v >= 10:
        k3 = UINT32_XOR(k3, UINT32_LSFT(tail[9], 8))

    if v >= 9:
        k3 = UINT32_XOR(k3, UINT32_LSFT(tail[8], 0))
        k3 = UINT32_MUL(k3, c3)
        k3 = ROTL32(k3, 17)
        k3 = UINT32_MUL(k3, c4)
        h3 = UINT32_XOR(h3, k3)

    if v >= 8:
        k2 = UINT32_XOR(k2, UINT32_LSFT(tail[7], 24))

    if v >= 7:
        k2 = UINT32_XOR(k2, UINT32_LSFT(tail[6], 16))

    if v >= 6:
        k2 = UINT32_XOR(k2, UINT32_LSFT(tail[5], 8))

    if v >= 5:
        k2 = UINT32_XOR(k2, UINT32_LSFT(tail[4], 0))
        k2 = UINT32_MUL(k2, c2)
        k2 = ROTL32(k2, 16)
        k2 = UINT32_MUL(k2, c3)
        h2 = UINT32_XOR(h2, k2)

    if v >= 4:
        k1 = UINT32_XOR(k1, UINT32_LSFT(tail[3], 24))

    if v >= 3:
        k1 = UINT32_XOR(k1, UINT32_LSFT(tail[2], 16))

    if v >= 2:
        k1 = UINT32_XOR(k1, UINT32_LSFT(tail[1], 8))

    if v >= 1:
        k1 = UINT32_XOR(k1, UINT32_LSFT(tail[0], 0))
        k1 = UINT32_MUL(k1, c1)
        k1 = ROTL32(k1, 15)
        k1 = UINT32_MUL(k1, c2)
        h1 = UINT32_XOR(h1, k1)

    # finalization
    h1 = UINT32_XOR(h1, len(data))
    h2 = UINT32_XOR(h2, len(data))
    h3 = UINT32_XOR(h3, len(data))
    h4 = UINT32_XOR(h4, len(data))

    h1 = UINT32_ADD(h1, h2)
    h1 = UINT32_ADD(h1, h3)
    h1 = UINT32_ADD(h1, h4)

    h2 = UINT32_ADD(h2, h1)
    h3 = UINT32_ADD(h3, h1)
    h4 = UINT32_ADD(h4, h1)

    h1 = _fmix32(h1)
    h2 = _fmix32(h2)
    h3 = _fmix32(h3)
    h4 = _fmix32(h4)

    h1 = UINT32_ADD(h1, h2)
    h1 = UINT32_ADD(h1, h3)
    h1 = UINT32_ADD(h1, h4)

    h2 = UINT32_ADD(h2, h1)
    h3 = UINT32_ADD(h3, h1)
    h4 = UINT32_ADD(h4, h1)

    s = struct.pack("IIII", h1, h2, h3, h4)
    t = struct.unpack("QQ", s)

    return t[0], t[1]


def _mmh3_x64_128 (key, seed):
    if isinstance(key, str):
        key = key.encode("utf8")

    data = key
    nblocks = len(data) // 16

    h1 = UINT64(seed)
    h2 = UINT64(seed)

    c1 = UINT64(0x87c37b91114253d5)
    c2 = UINT64(0x4cf5ad432745937f)

    # body
    for i in range(0, nblocks):
        k1 = GetBlock64(key, i * 2 + 0)
        k2 = GetBlock64(key, i * 2 + 1)

        k1 = UINT64_MUL(k1, c1)
        k1 = ROTL64(k1, 31)
        k1 = UINT64_MUL(k1, c2)
        h1 = UINT64_XOR(h1, k1)

        h1 = ROTL64(h1, 27)
        h1 = UINT64_ADD(h1, h2)
        h1 = UINT64_ADD(UINT64_MUL(h1, 5), 0x52dce729)

        k2 = UINT64_MUL(k2, c2)
        k2 = ROTL64(k2, 33)
        k2 = UINT64_MUL(k2, c1)
        h2 = UINT64_XOR(h2, k2)

        h2 = ROTL64(h2, 31)
        h2 = UINT64_ADD(h2, h1)
        h2 = UINT64_ADD(UINT64_MUL(h2, 5), 0x38495ab5)

    # tail
    tail = data[nblocks * 16:]

    k1 = UINT64(0)
    k2 = UINT64(0)

    v = len(data) & 15
    if v >= 15:
        k2 = UINT64_XOR(k2, UINT64_LSFT(tail[14], 48))

    if v >= 14:
        k2 = UINT64_XOR(k2, UINT64_LSFT(tail[13], 40))

    if v >= 13:
        k2 = UINT64_XOR(k2, UINT64_LSFT(tail[12], 32))

    if v >= 12:
        k2 = UINT64_XOR(k2, UINT64_LSFT(tail[11], 24))

    if v >= 11:
        k2 = UINT64_XOR(k2, UINT64_LSFT(tail[10], 16))

    if v >= 10:
        k2 = UINT64_XOR(k2, UINT64_LSFT(tail[9], 8))

    if v >= 9:
        k2 = UINT64_XOR(k2, UINT64_LSFT(tail[8], 0))
        k2 = UINT64_MUL(k2, c2)
        k2 = ROTL64(k2, 33)
        k2 = UINT64_MUL(k2, c1)
        h2 = UINT64_XOR(h2, k2)

    if v >= 8:
        k1 = UINT64_XOR(k1, UINT64_LSFT(tail[7], 56))

    if v >= 7:
        k1 = UINT64_XOR(k1, UINT64_LSFT(tail[6], 48))

    if v >= 6:
        k1 = UINT64_XOR(k1, UINT64_LSFT(tail[5], 40))

    if v >= 5:
        k1 = UINT64_XOR(k1, UINT64_LSFT(tail[4], 32))

    if v >= 4:
        k1 = UINT64_XOR(k1, UINT64_LSFT(tail[3], 24))

    if v >= 3:
        k1 = UINT64_XOR(k1, UINT64_LSFT(tail[2], 16))

    if v >= 2:
        k1 = UINT64_XOR(k1, UINT64_LSFT(tail[1], 8))

    if v >= 1:
        k1 = UINT64_XOR(k1, UINT64_LSFT(tail[0], 0))
        k1 = UINT64_MUL(k1, c1)
        k1 = ROTL64(k1, 31)
        k1 = UINT64_MUL(k1, c2)
        h1 = UINT64_XOR(h1, k1)

    # finalization
    h1 = UINT64_XOR(h1, len(data))
    h2 = UINT64_XOR(h2, len(data))

    h1 = UINT64_ADD(h1, h2)
    h2 = UINT64_ADD(h2, h1)

    h1 = _fmix64(h1)
    h2 = _fmix64(h2)

    h1 = UINT64_ADD(h1, h2)
    h2 = UINT64_ADD(h2, h1)

    return h1, h2


def hash(key, seed=0x0):
    return _mmh3_x86_32(key, seed)


def hash64(key, seed=0x0, x64arch=True):
    if x64arch:
        return _mmh3_x64_128(key, seed)
    else:
        return _mmh3_x86_128(key, seed)


def hash128(key, seed=0x0, x64arch=True):
    if x64arch:
        t = _mmh3_x64_128(key, seed)
        return t[0] | (t[1] << 64)
    else:
        t = _mmh3_x86_128(key, seed)
        return t[0] | (t[1] << 64)
