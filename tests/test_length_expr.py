# -*- coding: utf-8 -*-
"""长度机制：表达式、常量折叠、回调、剩余长度、Field 与 dict 两种写法。"""

from __future__ import annotations

import unittest

from kkprotocol import Field, FieldValue, FrameRuleError, LengthExpr

from tests.helpers import make_codec


class TestLengthExpression(unittest.TestCase):
    def test_multi_ref_expression(self):
        rules = [
            Field.u8("total"),
            Field.u8("a"),
            Field.u16("b"),
            Field.raw("rest", "{total.val}-{a.len}-{b.len}-1"),
        ]
        codec = make_codec(rules)
        frames = codec.feed(bytes([7, 0x11, 0x00, 0x22]) + b"qqq")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("rest"), b"qqq")

    def test_constant_folding(self):
        expr = LengthExpr("{x.val}-1-1-2-4-2")
        self.assertEqual(expr.evaluate({"x": FieldValue("x", b"\x10", 16)}), 6)

    def test_len_attribute_is_actual_byte_count(self):
        # a 的规则长度是表达式，{a.len} 取的是实际解析出的字节数
        rules = [
            Field.u8("n"),
            Field.raw("a", "{n.val}"),
            Field.raw("b", "{a.len}"),
        ]
        codec = make_codec(rules)
        frames = codec.feed(bytes([2]) + b"ab" + b"cd")
        self.assertEqual(frames[0].value("a"), b"ab")
        self.assertEqual(frames[0].value("b"), b"cd")

    def test_bytes_alias_of_len(self):
        rules = [Field.u8("n"), Field.raw("a", "{n.val}"), Field.raw("b", "{a.bytes}")]
        frames = make_codec(rules).feed(bytes([1]) + b"xy")
        self.assertEqual(frames[0].value("b"), b"y")

    def test_callable_length(self):
        def twice(fields):
            return fields["n"].val * 2

        rules = [Field.u8("n"), Field.raw("data", twice)]
        frames = make_codec(rules).feed(bytes([2]) + b"abcd")
        self.assertEqual(frames[0].value("data"), b"abcd")

    def test_callable_length_raising_is_invalid(self):
        def boom(fields):
            raise RuntimeError("bad")

        rules = [Field.u8("n"), Field.raw("data", boom)]
        codec = make_codec(rules)
        self.assertEqual(codec.feed(bytes([2]) + b"abcd"), [])
        self.assertGreater(codec.stats.resyncs, 0)

    def test_callable_returning_non_int_is_invalid(self):
        rules = [Field.u8("n"), Field.raw("data", lambda fields: "x")]
        codec = make_codec(rules)
        self.assertEqual(codec.feed(bytes([2]) + b"abcd"), [])
        self.assertGreater(codec.stats.resyncs, 0)

    def test_negative_computed_length_is_invalid(self):
        rules = [Field.u8("n"), Field.raw("data", "{n.val}-5")]
        codec = make_codec(rules)
        self.assertEqual(codec.feed(bytes([1]) + b"abcd"), [])
        self.assertGreater(codec.stats.resyncs, 0)

    def test_zero_length_expression_yields_empty(self):
        rules = [Field.u8("n"), Field.raw("data", "{n.val}-1"), Field.u8("tail")]
        frames = make_codec(rules).feed(bytes([1, 0x99]))
        self.assertEqual(frames[0].value("data"), b"")
        self.assertEqual(frames[0].value("tail"), 0x99)


class TestRuleStyles(unittest.TestCase):
    def test_field_class_style(self):
        rules = [
            Field(key="start", length=1, fmt="B", fixed=0xAA, desc="帧头"),
            Field(key="n", length=1, fmt="B"),
            Field(key="data", length="{n.val}", fmt=""),
        ]
        frames = make_codec(rules).feed(b"\xAA\x03xyz")
        self.assertEqual(frames[0].value("data"), b"xyz")

    def test_dict_style_still_supported(self):
        rules = [
            {"key": "start", "len": 1, "fmt": "B", "fixed": 0xAA},
            {"key": "n", "len": 1, "fmt": "B"},
            {"key": "data", "len": "{n.val}", "fmt": ""},
        ]
        frames = make_codec(rules).feed(b"\xAA\x02xy")
        self.assertEqual(frames[0].value("data"), b"xy")

    def test_field_factories(self):
        self.assertEqual(Field.u8("a").fmt, "B")
        self.assertEqual(Field.u16("a").fmt, "!H")
        self.assertEqual(Field.u16("a", little_endian=True).fmt, "<H")
        self.assertEqual(Field.u32("a").length, 4)
        self.assertEqual(Field.u64("a").length, 8)
        self.assertEqual(Field.raw("a", 4).fmt, "")
        self.assertTrue(Field.checksum("c", group="{a}").crc)
        self.assertIsNone(Field.rest("a").length)

    def test_signed_constant_length(self):
        rules = [Field.raw("a", "4")]
        frames = make_codec(rules).feed(b"abcd")
        self.assertEqual(frames[0].value("a"), b"abcd")

    def test_rest_field_requires_delimiter_framing(self):
        codec = make_codec([Field.u8("stx"), Field.rest("body")])
        with self.assertRaises(FrameRuleError):
            codec.compile()


if __name__ == "__main__":
    unittest.main(verbosity=2)
