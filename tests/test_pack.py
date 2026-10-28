# -*- coding: utf-8 -*-
"""``Data`` / ``pack``：把一串有类型的值拼成载荷字节。"""

import struct
import unittest

from kkprotocol import (
    ChecksumRule,
    Field,
    FrameSpec,
    LengthRule,
    Protocol,
    Data,
    crc16_modbus,
    pack,
)


def aurora(**kwargs):
    params = dict(
        fields=[
            Field.u8("header", fixed=0xAA),
            Field.u8("len"),
            Field.u8("type"),
            Field.u8("cmd"),
            Field.u16("seq"),
            Field.raw("dev", 4),
            Field.raw("data", "{len.val}-10"),
            Field.checksum("crc", 2, group="{len}{type}{cmd}{seq}{dev}{data}"),
        ],
        payload="data",
        length=LengthRule("len"),
        checksum=ChecksumRule("crc", crc16_modbus),
        device="dev",
    )
    params.update(kwargs)
    return FrameSpec(**params)


class TestValueEncoding(unittest.TestCase):
    def test_unsigned_ints(self):
        self.assertEqual(bytes(Data.u8(0x12)), b"\x12")
        self.assertEqual(bytes(Data.u16(0x1234)), struct.pack("!H", 0x1234))
        self.assertEqual(bytes(Data.u32(0x12345678)), struct.pack("!I", 0x12345678))
        self.assertEqual(bytes(Data.u64(1)), struct.pack("!Q", 1))

    def test_signed_ints(self):
        self.assertEqual(bytes(Data.i8(-1)), b"\xff")
        self.assertEqual(bytes(Data.i16(-2)), struct.pack("!h", -2))
        self.assertEqual(bytes(Data.i32(-3)), struct.pack("!i", -3))
        self.assertEqual(bytes(Data.i64(-4)), struct.pack("!q", -4))

    def test_little_endian(self):
        self.assertEqual(bytes(Data.u16(0x1234, little_endian=True)), b"\x34\x12")
        self.assertEqual(bytes(Data.u32(1, little_endian=True)), b"\x01\x00\x00\x00")

    def test_floats(self):
        self.assertEqual(bytes(Data.f32(1.5)), struct.pack("!f", 1.5))
        self.assertEqual(bytes(Data.f64(1.5)), struct.pack("!d", 1.5))
        self.assertEqual(bytes(Data.f32(1.0, little_endian=True)), struct.pack("<f", 1.0))

    def test_out_of_range(self):
        with self.assertRaises(ValueError) as ctx:
            Data.u8(300)
        self.assertIn("Data.u8", str(ctx.exception))

    def test_bool(self):
        self.assertEqual(bytes(Data.bool(True)), b"\x01")
        self.assertEqual(bytes(Data.bool(False)), b"\x00")
        self.assertEqual(bytes(Data.bool(1)), b"\x01")
        self.assertEqual(bytes(Data.bool("")), b"\x00")

    def test_raw_and_zeros(self):
        self.assertEqual(bytes(Data.raw(b"\x01\x02")), b"\x01\x02")
        self.assertEqual(bytes(Data.zeros(3)), b"\x00\x00\x00")
        self.assertEqual(bytes(Data.zeros(0)), b"")

    def test_zeros_negative(self):
        with self.assertRaises(ValueError):
            Data.zeros(-1)


class TestValueString(unittest.TestCase):
    def test_variable_length(self):
        self.assertEqual(bytes(Data.str("test")), b"test")
        self.assertEqual(bytes(Data.str("中文")), "中文".encode("utf-8"))

    def test_fixed_length_pads(self):
        self.assertEqual(bytes(Data.str("test", count=8)), b"test\x00\x00\x00\x00")

    def test_fixed_length_truncates(self):
        self.assertEqual(bytes(Data.str("abcdef", count=3)), b"abc")

    def test_exact_count_no_padding(self):
        self.assertEqual(bytes(Data.str("abcd", count=4)), b"abcd")

    def test_fill_variants(self):
        self.assertEqual(bytes(Data.str("a", count=3, fill=b"\xff")), b"a\xff\xff")
        self.assertEqual(bytes(Data.str("a", count=3, fill=0x20)), b"a  ")
        self.assertEqual(bytes(Data.str("a", count=3, fill="\0")), b"a\x00\x00")
        self.assertEqual(bytes(Data.str("a", count=3, fill=" ")), b"a  ")

    def test_fill_must_be_one_byte(self):
        with self.assertRaises(ValueError):
            Data.str("a", count=3, fill=b"\x00\x00")

    def test_encoding(self):
        self.assertEqual(bytes(Data.str("é", encoding="latin-1")), b"\xe9")

    def test_char_alias(self):
        self.assertEqual(bytes(Data.char("test", count=6)), b"test\x00\x00")

    def test_negative_count(self):
        with self.assertRaises(ValueError):
            Data.str("a", count=-1)


class TestPack(unittest.TestCase):
    def test_positional(self):
        body = pack(Data.u8(0), Data.u8(0), Data.bool(True), Data.str("test", count=8))
        self.assertEqual(body, b"\x00\x00\x01test\x00\x00\x00\x00")
        self.assertIsInstance(body, bytes)

    def test_single_list(self):
        self.assertEqual(pack([Data.u8(1), Data.u8(2)]), b"\x01\x02")
        self.assertEqual(pack((Data.u8(1),)), b"\x01")

    def test_mixed_bytes(self):
        self.assertEqual(pack(Data.u8(1), b"\x02\x03", Data.u8(4)), b"\x01\x02\x03\x04")

    def test_empty(self):
        self.assertEqual(pack(), b"")

    def test_rejects_unknown_type(self):
        with self.assertRaises(TypeError) as ctx:
            pack(123)
        self.assertIn("bytes", str(ctx.exception))

    def test_bytes_plus(self):
        self.assertEqual(b"\x00" + pack(Data.u8(1)), b"\x00\x01")


class TestEncodedObject(unittest.TestCase):
    def test_bytes_and_len(self):
        one = Data.u16(0x0102)
        self.assertEqual(bytes(one), b"\x01\x02")
        self.assertEqual(len(one), 2)

    def test_equality(self):
        self.assertEqual(Data.u8(1), Data.u8(1))
        self.assertEqual(Data.u8(1), b"\x01")
        self.assertNotEqual(Data.u8(1), Data.u8(2))

    def test_repr(self):
        self.assertEqual(repr(Data.u8(0xAB)), "Data(ab)")

    def test_add(self):
        self.assertEqual(bytes(Data.u8(1) + b"\x02"), b"\x01\x02")
        self.assertEqual(bytes(b"\x00" + Data.u8(1)), b"\x00\x01")


class TestBuildRawPayload(unittest.TestCase):
    def setUp(self):
        self.proto = Protocol(aurora(), device_id=b"\x00\x00\x00\x07")

    def test_pack_result(self):
        body = pack(Data.u8(0), Data.u8(0), Data.bool(True), Data.str("test", count=24))
        wire = self.proto.build_raw(0x03, body, type=1, seq=1)
        self.assertEqual(wire[:2], b"\xaa\x25")       # len = 10 + 27
        self.assertEqual(wire[10:37], body)

    def test_list_payload(self):
        wire = self.proto.build_raw(
            0x03, [Data.u8(0), Data.u8(0), Data.bool(True), Data.str("test", count=24)], type=1, seq=1
        )
        self.assertEqual(wire[10:37], b"\x00\x00\x01test" + b"\x00" * 20)

    def test_same_as_manual_bytes(self):
        as_list = self.proto.build_raw(0x03, [Data.u8(1), Data.u16(0x0203)], type=1, seq=1)
        as_bytes = self.proto.build_raw(0x03, b"\x01\x02\x03", type=1, seq=1)
        self.assertEqual(as_list, as_bytes)

    def test_single_value_payload(self):
        wire = self.proto.build_raw(0x03, Data.u32(0x01020304), type=1, seq=1)
        self.assertEqual(wire[10:14], b"\x01\x02\x03\x04")

    def test_roundtrip_parse(self):
        body = pack(Data.u8(0), Data.u8(0), Data.bool(True), Data.str("test", count=24))
        frame = self.proto.feed(self.proto.build_raw(0x03, body, type=1, seq=1))[0]
        self.assertEqual(frame.value("data"), body)
        self.assertEqual(frame.value("len"), 10 + len(body))

    def test_equivalent_to_pdu_fields(self):
        # 同样的载荷，一条走 Pdu 字段、一条走 Data/pack
        from kkprotocol import Pdu

        spec = aurora(pdus={0x03: Pdu("Write", [Field.u8("a"), Field.u16("b")])})
        proto = Protocol(spec, device_id=b"\x00\x00\x00\x07")
        via_fields = proto.build("Write", type=1, seq=1, a=1, b=0x0203)
        via_pack = proto.build_raw(0x03, [Data.u8(1), Data.u16(0x0203)], type=1, seq=1)
        self.assertEqual(via_fields, via_pack)


if __name__ == "__main__":
    unittest.main()
