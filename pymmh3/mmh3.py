# /usr/bin/env python

import struct

# unsigned type
UINT8   = lambda a:  a & 0xff
UINT16  = lambda a:  a & 0xffff
UINT32  = lambda a:  a & 0xffffffff
UINT64  = lambda a:  a & 0xffffffffffffffff

# operator
UINT32_ADD  = lambda a, b: UINT32(UINT32(a) + UINT32(b))
UINT32_MUL  = lambda a, b: UINT32(UINT32(a) * UINT32(b))
UINT32_XOR  = lambda a, b: UINT32(UINT32(a) ^ UINT32(b))
UINT32_LSFT = lambda a, b: UINT32(UINT32(a) << UINT8(b))
UINT32_RSFT = lambda a, b: UINT32(UINT32(a) >> UINT8(b))

UINT64_ADD  = lambda a, b: UINT64(UINT64(a) + UINT64(b))
UINT64_MUL  = lambda a, b: UINT64(UINT64(a) * UINT64(b))
UINT64_XOR  = lambda a, b: UINT64(UINT64(a) ^ UINT64(b))
UINT64_LSFT = lambda a, b: UINT64(UINT64(a) << UINT8(b))
UINT64_RSFT = lambda a, b: UINT64(UINT64(a) >> UINT8(b))

# rotl
ROTL32 = lambda x, r: UINT32(UINT32_LSFT(x, r) | UINT32_RSFT(x, 32-r))
ROTL64 = lambda x, r: UINT64(UINT64_LSFT(x, r) | UINT64_RSFT(x, 64-r))

GetBlock32 = lambda p, i: struct.unpack("I", p[i * 4:(i + 1) * 4])[0]
GetBlock64 = lambda p, i: struct.unpack("Q", p[i * 8:(i + 1) * 8])[0]


def fmix32(h):
    h = UINT32(h)
    h = UINT32_XOR(h, UINT32_RSFT(h, 16))
    h = UINT32_MUL(h, 0x85ebca6b)
    h = UINT32_XOR(h, UINT32_RSFT(h, 13))
    h = UINT32_MUL(h, 0xc2b2ae35)
    h = UINT32_XOR(h, UINT32_RSFT(h, 16))
    return h


def fmix64(k):
    k = UINT64(k)
    k = UINT64_XOR(k, UINT64_RSFT(k, 33))
    k = UINT32_MUL(k, 0xff51afd7ed558ccd)
    k = UINT64_XOR(k, UINT64_RSFT(k, 33))
    k = UINT32_MUL(k, 0xc4ceb9fe1a85ec53)
    k = UINT64_XOR(k, UINT64_RSFT(k, 33))
    return k


def MurmurHash3_x86_32(key, seed):
    if isinstance(key, str):
        key = key.encode("ascii")

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
    tail = data[nblocks * 4:(nblocks + 1) * 4]

    k1 = UINT32(0)

    v = len(data) & 3
    if v == 3:
        k1 = UINT32_XOR(k1, UINT32_LSFT(tail[2], 16))

    if v == 2 or v == 3:
        k1 = UINT32_XOR(k1, UINT32_LSFT(tail[1], 8))

    if v == 1 or v == 2 or v == 3:
        k1 = UINT32_XOR(k1, tail[0])

    k1 = UINT32_MUL(k1, c1)
    k1 = ROTL32(k1, 15)
    k1 = UINT32_MUL(k1, c2)
    h1 = UINT32_XOR(h1, k1)

    # finalization
    h1 = UINT32_XOR(h1, len(data))
    h1 = fmix32(h1)

    return h1


