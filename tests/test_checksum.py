# -*- coding: utf-8 -*-
"""校验：CRC 算法向量、校验字段行为、失败策略。"""

from __future__ import annotations

import struct
import unittest

from kkprotocol import Field, FrameRuleError, crc16_modbus, crc16_x25, sum8, xor8
from kkprotocol.example_device import DeviceFrameCodec, build_device_frame

from tests.helpers import build_mini, make_codec, mini_codec


class TestCrcUtilities(unittest.TestCase):
    def test_standard_vectors(self):
        self.assertEqual(crc16_modbus(b"123456789"), 0x4B37)
        self.assertEqual(crc16_x25(b"123456789"), 0x906E)

    def test_simple_checksums(self):
        self.assertEqual(sum8(b"\x01\x02\x03"), 6)
        self.assertEqual(xor8(b"\x01\x02\x03"), 0)
        self.assertEqual(sum8(b""), 0)
        self.assertEqual(xor8(b""), 0)

    def test_sum8_wraps(self):
        self.assertEqual(sum8(b"\xff\xff"), 0xFE)


class TestChecksumField(unittest.TestCase):
    def test_bad_crc_resync_then_recover(self):
        codec = DeviceFrameCodec()
        good = build_device_frame(cmd=7)
        frames = codec.feed(build_device_frame(cmd=6, bad_crc=True) + good)
        self.assertEqual([f.value("cmd") for f in frames], [7])
        self.assertEqual(codec.stats.crc_errors, 1)

    def test_bad_crc_skip_frame_policy(self):
        codec = DeviceFrameCodec()
        codec.on_crc_error = "skip_frame"
        good = build_device_frame(cmd=7)
        frames = codec.feed(build_device_frame(cmd=6, bad_crc=True) + good)
        self.assertEqual([f.value("cmd") for f in frames], [7])
        self.assertEqual(codec.pending_bytes, b"")

    def test_crc_imp_returning_bytes(self):
        rules = [
            Field.u8("n"),
            Field.raw("data", "{n.val}"),
            Field.checksum("crc", 2, group="{n}{data}", fmt=""),
        ]

        def crc_bytes(payload: bytes) -> bytes:
            return struct.pack("!H", crc16_modbus(payload))

        codec = make_codec(rules, crc=crc_bytes)
        payload = b"xyz"
        body = bytes([len(payload)]) + payload
        frames = codec.feed(body + crc_bytes(body))
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"xyz")
        self.assertEqual(codec.feed(body + b"\x00\x00"), [])

    def test_crc_flag_without_group_covers_previous_fields(self):
        rules = [
            Field.u8("a"),
            Field.u8("b"),
            Field.checksum("chk", 1, fmt="B"),
        ]
        codec = make_codec(rules, crc=sum8)
        self.assertEqual(len(codec.feed(bytes([1, 2, 3]))), 1)
        self.assertEqual(codec.feed(bytes([1, 2, 9])), [])

    def test_checksum_field_not_last(self):
        rules = [
            Field.u8("n"),
            Field.checksum("chk", 1, group="{n}", fmt="B"),
            Field.raw("data", "{n.val}"),
        ]
        codec = make_codec(rules, crc=sum8)
        frames = codec.feed(bytes([3, 3]) + b"abc")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"abc")

    def test_crc_imp_bad_return_type(self):
        rules = [Field.u8("a"), Field.checksum("chk", 1, fmt="B")]
        codec = make_codec(rules, crc=lambda data: "oops")
        with self.assertRaises(FrameRuleError):
            codec.feed(bytes([1, 1]))

    def test_checksum_over_empty_group(self):
        # group 引用了一个零长度字段，校验值为 sum8(b"")
        rules = [
            Field.u8("n"),
            Field.raw("empty", "{n.val}-1"),
            Field.checksum("chk", 1, group="{empty}", fmt="B"),
        ]
        codec = make_codec(rules, crc=sum8)
        self.assertEqual(len(codec.feed(bytes([1, 0]))), 1)


class TestChecksumVariants(unittest.TestCase):
    def test_mini_protocol_good_and_bad(self):
        codec = mini_codec()
        self.assertEqual(len(codec.feed(build_mini())), 1)
        self.assertEqual(codec.feed(build_mini(bad_sum=True)), [])
        self.assertEqual(codec.stats.crc_errors, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
