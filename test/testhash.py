#!/usr/bin/env python

#
# test case from https://github.com/hajimes/mmh3/blob/master/test_mmh3.py
#

from pymmh3 import mmh3


def testhash():
    assert mmh3.hash(b"", seed=0) == 0
    assert mmh3.hash(b"", seed=1) == 0x514E28B7
    assert mmh3.hash(b"", seed=0xFFFFFFFF) == 0x81F16F39
    assert mmh3.hash(b"\x21\x43\x65\x87", 0) == 0xF55B516B
    assert mmh3.hash(b"\x21\x43\x65\x87", 0x5082EDEE) == 0x2362F9DE

    assert mmh3.hash(b"\x21\x43\x65", 0) == 0x7E4A8634
    assert mmh3.hash(b"\x21\x43", 0) == 0xA0F7B07A
    assert mmh3.hash(b"\x21", 0) == 0x72661CF4
    assert mmh3.hash(b"\xff\xff\xff\xff", 0) == 0x76293B50
    assert mmh3.hash(b"\x00\x00\x00\x00", 0) == 0x2362F9DE
    assert mmh3.hash(b"\x00\x00\x00", 0) == 0x85F0B427
    assert mmh3.hash(b"\x00\x00", 0) == 0x30F4C306
    assert mmh3.hash(b"\x00", 0) == 0x514E28B7

    assert mmh3.hash("aaaa", 0x9747B28C) == 0x5A97808A
    assert mmh3.hash("aaa", 0x9747B28C) == 0x283E0130
    assert mmh3.hash("aa", 0x9747B28C) == 0x5D211726
    assert mmh3.hash("a", 0x9747B28C) == 0x7FA09EA6
    assert mmh3.hash("abcd", 0x9747B28C) == 0xF0478627
    assert mmh3.hash("abc", 0x9747B28C) == 0xC84A62DD
    assert mmh3.hash("ab", 0x9747B28C) == 0x74875592
    assert mmh3.hash("a", 0x9747B28C) == 0x7FA09EA6
    assert mmh3.hash("Hello, world!", 0x9747B28C) == 0x24884CBA
    assert mmh3.hash(u"ππππππππ".encode("utf-8"), 0x9747B28C) == 0xD58063C1
    assert mmh3.hash("a" * 256, 0x9747B28C) == 0x37405BDC
    assert mmh3.hash("abc", 0) == 0xB3DD93FA
    assert mmh3.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 0) == 0xEE925B90
    assert mmh3.hash("The quick brown fox jumps over the lazy dog", 0x9747B28C) == 0x2FA826CD
    assert mmh3.hash("The quick brown fox jumps over the lazy dog", 0x9747B28C) == 0x2FA826CD


def testhash64():
    assert mmh3.hash64("foo") == (16316970633193145697, 9128664383759220103,)


def testhash128():
    assert mmh3.hash128("foo") == 168394135621993849475852668931176482145
    assert mmh3.hash128("foo", 42) == 215966891540331383248189432718888555506


if __name__ == "__main__":
    testhash()
    testhash64()
    testhash128()

