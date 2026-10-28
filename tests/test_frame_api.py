# -*- coding: utf-8 -*-
"""Frame 的整帧字节接口：``to_bytes()`` / ``to_hex()`` / ``bytes(frame)``。"""

from __future__ import annotations

import unittest

from kkprotocol import DelimiterFraming, FieldValue, Frame, build_ppp_frame, PppFrameCodec

from tests.helpers import build_mini, mini_codec


class TestLengthFramingBytes(unittest.TestCase):
    def setUp(self):
        self.raw = build_mini(b"abc")
        self.frame = mini_codec().feed(self.raw)[0]

    def test_to_bytes_returns_whole_frame(self):
        self.assertEqual(self.frame.to_bytes(), self.raw)
        self.assertEqual(bytes(self.frame), self.raw)
        self.assertEqual(self.frame.to_bytes(wire=False), self.frame.raw)

    def test_to_hex_default_format(self):
        self.assertEqual(self.frame.to_hex(), self.raw.hex(" ").upper())
        self.assertTrue(self.frame.to_hex().startswith("AA 01 03"))

    def test_to_hex_without_separator(self):
        self.assertEqual(self.frame.to_hex(sep=""), self.raw.hex().upper())

    def test_to_hex_lowercase(self):
        self.assertEqual(self.frame.to_hex(upper=False), self.raw.hex(" "))
        self.assertEqual(self.frame.to_hex(upper=False), self.frame.to_hex().lower())


class TestDelimiterFramingBytes(unittest.TestCase):
    """分隔符定界：wire 含首尾标志与转义字节，raw 是反转义后的净帧。"""

    def setUp(self):
        self.wire = build_ppp_frame(payload=b"hi\x7e")
        self.frame = PppFrameCodec().feed(self.wire)[0]

    def test_to_bytes_keeps_delimiters(self):
        self.assertEqual(self.frame.to_bytes(), self.wire)
        self.assertTrue(self.frame.to_bytes().startswith(b"\x7e"))
        self.assertTrue(self.frame.to_bytes().endswith(b"\x7e"))

    def test_wire_false_returns_unescaped_payload(self):
        self.assertEqual(self.frame.to_bytes(wire=False), self.frame.raw)
        self.assertNotEqual(self.frame.to_bytes(), self.frame.raw)

    def test_to_hex_can_select_wire_or_raw(self):
        self.assertEqual(self.frame.to_hex(), self.wire.hex(" ").upper())
        self.assertEqual(self.frame.to_hex(wire=False), self.frame.raw.hex(" ").upper())
        self.assertTrue(self.frame.to_hex().startswith("7E"))


class TestManualFrame(unittest.TestCase):
    def test_wire_none_falls_back_to_raw(self):
        frame = Frame(raw=b"\x01\x02", fields={"a": FieldValue("a", b"\x01\x02", b"\x01\x02")})
        self.assertIsNone(frame.wire)
        self.assertEqual(frame.to_bytes(), b"\x01\x02")
        self.assertEqual(frame.to_bytes(wire=True), b"\x01\x02")
        self.assertEqual(frame.to_hex(), "01 02")
        self.assertEqual(bytes(frame), b"\x01\x02")


if __name__ == "__main__":
    unittest.main(verbosity=2)
