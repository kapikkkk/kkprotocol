# -*- coding: utf-8 -*-
"""转义工具：往返一致、线上无裸定界符、SLIP 映射、配置冲突检测。"""

from __future__ import annotations

import random
import unittest

from kkprotocol import (
    DelimiterFraming,
    FrameRuleError,
    escape_bytes,
    find_end_delimiter,
    unescape_bytes,
    wrap_frame,
)


def ppp_spec() -> DelimiterFraming:
    return DelimiterFraming(end=0x7E, start=0x7E, escape=0x7D, escape_xor=0x20)


class TestEscapeRoundTrip(unittest.TestCase):
    def test_roundtrip_random_payloads(self):
        spec = ppp_spec()
        random.seed(20261027)
        for _ in range(50):
            payload = bytes(random.getrandbits(8) for _ in range(random.randint(0, 64)))
            self.assertEqual(unescape_bytes(escape_bytes(payload, spec), spec), payload)

    def test_escaped_stream_has_no_bare_delimiters(self):
        spec = ppp_spec()
        payload = bytes(range(256)) * 2
        escaped = escape_bytes(payload, spec)
        index = 0
        while index < len(escaped):
            byte = escaped[index]
            if byte in spec.targets:
                # 只允许作为转义字节出现，且后面跟一个非定界字节
                self.assertEqual(byte, spec.escape)
                self.assertNotIn(escaped[index + 1], spec.targets)
                index += 2
            else:
                index += 1

    def test_escape_byte_itself_is_escaped(self):
        spec = ppp_spec()
        self.assertEqual(escape_bytes(b"\x7d", spec), b"\x7d\x5d")
        self.assertEqual(escape_bytes(b"\x7e", spec), b"\x7d\x5e")

    def test_no_escape_configured_is_passthrough(self):
        spec = DelimiterFraming(end=0x0A)
        self.assertEqual(escape_bytes(b"a\nb", spec), b"a\nb")
        self.assertEqual(unescape_bytes(b"a\nb", spec), b"a\nb")

    def test_dangling_escape_raises(self):
        with self.assertRaises(ValueError):
            unescape_bytes(b"abc\x7d", ppp_spec())


class TestMapStyleEscape(unittest.TestCase):
    def test_slip_style(self):
        spec = DelimiterFraming(
            end=0xC0,
            escape=0xDB,
            escape_xor=0x20,
            escape_map={0xC0: 0xDC, 0xDB: 0xDD},
        )
        payload = b"\xc0\xdb\x01\xc0"
        escaped = escape_bytes(payload, spec)
        self.assertEqual(escaped, b"\xdb\xdc\xdb\xdd\x01\xdb\xdc")
        self.assertEqual(unescape_bytes(escaped, spec), payload)

    def test_duplicate_second_byte_rejected(self):
        with self.assertRaises(FrameRuleError):
            DelimiterFraming(
                end=0xC0,
                escape=0xDB,
                escape_map={0xC0: 0xDC, 0x01: 0xDC},
            )


class TestDelimiterConfig(unittest.TestCase):
    def test_byte_range_validation(self):
        with self.assertRaises(FrameRuleError):
            DelimiterFraming(end=300)
        with self.assertRaises(FrameRuleError):
            DelimiterFraming(end=0x7E, escape=0x7E)
        with self.assertRaises(FrameRuleError):
            DelimiterFraming(end=0x7E, escape=0x7D, escape_xor=-1)

    def test_conflicting_escape_requires_map(self):
        # 0x7E ^ 0x01 = 0x7F ... 选一个会撞到定界符的异或值
        with self.assertRaises(FrameRuleError):
            DelimiterFraming(end=0x01, escape=0x02, escape_xor=0x03)

    def test_spec_targets_and_second_byte(self):
        spec = ppp_spec()
        self.assertEqual(spec.targets, frozenset({0x7E, 0x7D}))
        self.assertEqual(spec.second_byte(0x7E), 0x5E)
        self.assertEqual(spec.second_byte(0x7D), 0x5D)

    def test_start_equals_end_allowed(self):
        spec = DelimiterFraming(end=0x7E, start=0x7E)
        self.assertEqual(spec.start, spec.end)


class TestScanAndWrap(unittest.TestCase):
    def test_find_end_skips_escaped_delimiter(self):
        spec = ppp_spec()
        buf = b"\x7d\x5e" + b"abc" + b"\x7e"
        self.assertEqual(find_end_delimiter(buf, 0, spec), 5)

    def test_find_end_returns_none_when_unclosed(self):
        self.assertIsNone(find_end_delimiter(b"\x7d\x5e abc", 0, ppp_spec()))

    def test_find_end_without_escape(self):
        spec = DelimiterFraming(end=0x0A)
        self.assertEqual(find_end_delimiter(b"abc\ndef", 0, spec), 3)
        self.assertIsNone(find_end_delimiter(b"abcdef", 0, spec))

    def test_wrap_frame_with_start(self):
        spec = ppp_spec()
        self.assertEqual(wrap_frame(b"\x7e", spec), b"\x7e\x7d\x5e\x7e")

    def test_wrap_frame_without_start(self):
        spec = DelimiterFraming(end=0x0A)
        self.assertEqual(wrap_frame(b"ok", spec), b"ok\n")

    def test_wrap_and_scan_roundtrip(self):
        spec = ppp_spec()
        payload = b"\x7e\x7d mixed \x00 bytes"
        wire = wrap_frame(payload, spec)
        self.assertEqual(find_end_delimiter(wire, 1, spec), len(wire) - 1)
        self.assertEqual(unescape_bytes(wire[1:-1], spec), payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
