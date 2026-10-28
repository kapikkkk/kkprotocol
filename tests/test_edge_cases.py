# -*- coding: utf-8 -*-
"""边界分支：表达式求值、同步锚点、零长度+fmt、设备号跨类型比较等。"""

from __future__ import annotations

import unittest

from kkprotocol import (
    AUTO_FRAMING,
    DelimiterFraming,
    Field,
    FieldValue,
    FrameRuleError,
    LengthExpr,
    crc16_modbus,
    sum8,
)
from kkprotocol.example_device import DeviceFrameCodec, build_device_frame

from tests.helpers import make_codec


class TestLengthExpressionEdges(unittest.TestCase):
    def test_unary_minus_on_reference(self):
        rules = [Field.u8("n"), Field.raw("body", "-{n.val}+4")]
        frames = make_codec(rules).feed(bytes([1]) + b"abc")
        self.assertEqual(frames[0].value("body"), b"abc")

    def test_constant_folding_with_leading_minus(self):
        expr = LengthExpr("-1+{n.val}")
        self.assertEqual(expr.evaluate({"n": FieldValue("n", b"\x05", 5)}), 4)

    def test_runtime_division_by_zero(self):
        rules = [
            Field.u8("stx", fixed=0xAA),
            Field.u8("n"),
            Field.u8("d"),
            Field.raw("body", "{n.val}//{d.val}"),
        ]
        codec = make_codec(rules)
        self.assertEqual(codec.feed(bytes([0xAA, 8, 0]) + b"abcd"), [])
        self.assertGreater(codec.stats.resyncs, 0)

    def test_unary_plus_on_reference(self):
        rules = [Field.u8("n"), Field.raw("body", "+{n.val}")]
        frames = make_codec(rules).feed(bytes([2]) + b"ab")
        self.assertEqual(frames[0].value("body"), b"ab")

    def test_float_constant_rejected(self):
        with self.assertRaises(FrameRuleError):
            LengthExpr("{n.val}+1.5")

    def test_invert_operator_rejected(self):
        with self.assertRaises(FrameRuleError):
            LengthExpr("~{n.val}")

    def test_comparison_rejected(self):
        with self.assertRaises(FrameRuleError):
            LengthExpr("{n.val}>1")

    def test_reference_to_non_numeric_val(self):
        rules = [
            Field.u8("n"),
            Field.raw("raw", "{n.val}"),
            Field.raw("body", "{raw.val}"),
        ]
        codec = make_codec(rules)
        self.assertEqual(codec.feed(bytes([2]) + b"abcd"), [])
        self.assertGreater(codec.stats.resyncs, 0)


class TestFieldValueApi(unittest.TestCase):
    def test_len_and_int_conversion(self):
        frame = DeviceFrameCodec().feed(build_device_frame())[0]
        self.assertEqual(len(frame["cmd"]), 1)
        self.assertEqual(frame["cmd"].length, 1)
        self.assertEqual(int(frame["cmd"]), 0x03)
        with self.assertRaises(TypeError):
            int(frame["data"])

    def test_raw_of(self):
        frame = DeviceFrameCodec().feed(build_device_frame(payload=b"zz"))[0]
        self.assertEqual(frame.raw_of("data"), b"zz")

    def test_repr_is_readable(self):
        frame = DeviceFrameCodec().feed(build_device_frame())[0]
        self.assertIn("Frame", repr(frame))
        self.assertIn("cmd", repr(frame["cmd"]))


class TestAbstractContract(unittest.TestCase):
    def test_rules_is_abstract(self):
        from kkprotocol import AbstractFrameCodec

        with self.assertRaises(NotImplementedError):
            AbstractFrameCodec.rules(object())

    def test_crc_imp_is_abstract(self):
        from kkprotocol import AbstractFrameCodec

        with self.assertRaises(NotImplementedError):
            AbstractFrameCodec.crc_imp(object(), b"")


class TestSyncAnchor(unittest.TestCase):
    def test_int_sync(self):
        codec = make_codec([Field.u8("a", fixed=0xAA), Field.u8("b")], sync=0xAA)
        self.assertEqual(len(codec.feed(b"\x00\xAA\x07")), 1)

    def test_bytes_fixed_field(self):
        rules = [Field.raw("mark", 2, fixed=b"OK"), Field.u8("v")]
        codec = make_codec(rules)
        self.assertEqual(codec.feed(b"xxOK\x01")[0].value("v"), 1)
        self.assertEqual(codec.feed(b"xxNO\x01"), [])

    def test_sync_from_one_byte_bytes_fixed(self):
        codec = make_codec([Field.raw("h", 1, fixed=b"\xAA"), Field.u8("v")])
        self.assertEqual(len(codec.feed(b"\x00\xAA\x07")), 1)

    def test_auto_derived_sync_from_single_byte_header(self):
        codec = DeviceFrameCodec()
        codec.compile()
        self.assertEqual(codec._sync, b"\x55")


class TestDelimiterEdges(unittest.TestCase):
    def test_header_scan_overflow(self):
        rules = [Field.rest("body")]
        codec = make_codec(
            rules, framing=DelimiterFraming(end=0x04, start=0x02), max_frame_size=8
        )
        self.assertEqual(codec.feed(b"\x01" * 20), [])
        self.assertGreater(codec.stats.resyncs, 0)
        self.assertEqual(codec.pending_bytes, b"")

    def test_declared_length_exceeds_delimited_content(self):
        rules = [Field.u8("stx", fixed=0x02), Field.u8("n"), Field.raw("body", "{n.val}")]
        codec = make_codec(rules, framing=DelimiterFraming(end=0x04))
        self.assertEqual(codec.feed(b"\x02\x09ab\x04"), [])
        self.assertGreaterEqual(codec.stats.length_mismatches, 1)

    def test_rules_not_consuming_whole_delimited_content(self):
        rules = [Field.u8("stx", fixed=0x02), Field.u8("n"), Field.raw("body", "{n.val}")]
        codec = make_codec(rules, framing=DelimiterFraming(end=0x04))
        self.assertEqual(codec.feed(b"\x02\x02abX\x04"), [])
        self.assertGreaterEqual(codec.stats.length_mismatches, 1)

    def test_auto_both_invalid_triggers_resync(self):
        rules = [Field.u8("stx", fixed=0x02), Field.rest("body")]
        codec = make_codec(
            rules, framing=AUTO_FRAMING, delimiter=DelimiterFraming(end=0x0A)
        )
        self.assertEqual(codec.feed(b"\xff\xff\n"), [])
        self.assertGreaterEqual(codec.stats.resyncs, 1)


class TestRuntimeFieldEdges(unittest.TestCase):
    def test_zero_length_with_fmt_at_runtime(self):
        rules = [Field.u8("n"), Field(key="x", length="{n.val}-1", fmt="B")]
        codec = make_codec(rules)
        self.assertEqual(codec.feed(bytes([1, 0x00])), [])
        self.assertGreater(codec.stats.resyncs, 0)

    def test_expression_length_conflicts_with_fmt_size(self):
        rules = [Field.u8("n"), Field(key="x", length="{n.val}", fmt="!H")]
        codec = make_codec(rules)
        self.assertEqual(codec.feed(bytes([3]) + b"abc"), [])
        self.assertGreater(codec.stats.resyncs, 0)

    def test_callable_raising_rule_error_propagates(self):
        def boom(fields):
            raise FrameRuleError("配置错误")

        codec = make_codec([Field.u8("n"), Field.raw("body", boom)])
        with self.assertRaises(FrameRuleError):
            codec.feed(bytes([1]) + b"ab")

    def test_checksum_field_without_fmt_compares_as_int(self):
        rules = [
            Field.u8("n"),
            Field(key="chk", length=2, fmt="", group="{n}"),
        ]
        codec = make_codec(rules, crc=crc16_modbus)
        good = bytes([1]) + crc16_modbus(b"\x01").to_bytes(2, "big")
        self.assertEqual(len(codec.feed(good)), 1)
        self.assertEqual(codec.feed(bytes([1, 0, 0])), [])


class TestDeviceCrossType(unittest.TestCase):
    def test_int_bound_device_vs_bytes_field(self):
        rules = [
            Field.u8("header", fixed=0x5A),
            Field.raw("dev", 4),
            Field.u8("n"),
            Field.raw("body", "{n.val}"),
            Field.checksum("sum", 1, group="{dev}{n}{body}", fmt="B"),
        ]
        codec = make_codec(rules, crc=sum8, device_field="dev", auto_learn_device=False)

        def build(dev: bytes, body: bytes = b"z") -> bytes:
            head = bytes([0x5A]) + dev + bytes([len(body)]) + body
            return head + bytes([sum8(head[1:])])

        codec.bind_device(1)  # int 表示，字段是 4 字节
        frames = codec.feed(build(b"\x00\x00\x00\x01"))
        self.assertFalse(frames[0].device_mismatch)

    def test_unknown_type_device_never_matches(self):
        rules = [
            Field.u8("header", fixed=0x5A),
            Field.raw("dev", 4),
            Field.checksum("sum", 1, group="{dev}", fmt="B"),
        ]
        codec = make_codec(rules, crc=sum8, device_field="dev", auto_learn_device=False)
        codec.bind_device("not-bytes")
        head = bytes([0x5A]) + b"\x00\x00\x00\x01"
        frames = codec.feed(head + bytes([sum8(head[1:])]))
        self.assertTrue(frames[0].device_mismatch)


if __name__ == "__main__":
    unittest.main(verbosity=2)
