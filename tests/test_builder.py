# -*- coding: utf-8 -*-
"""组帧：不动点回填、两种长度口径、校验计算、参数校验与收发自检。"""

import struct
import unittest

from kkprotocol import (
    AutoField,
    ChecksumRule,
    DelimiterFraming,
    Field,
    FrameBuildError,
    FrameBuilder,
    FrameRuleError,
    FrameSpec,
    LengthRule,
    Pdu,
    Protocol,
    SeqPolicy,
    crc16_modbus,
    sum8,
    xor8,
)
DEVID_LEN = 19
PROTO_FLAG = 0x02
DEVID = b"SN00000000000000001"


def dev_crc(data: bytes) -> bytes:
    """字节异或后按大端打成 2 字节（示例帧的校验口径）。"""
    return xor8(data).to_bytes(2, "big")


def dev_fields():
    """55 AA | LEN(2) | 0x02 | CMD | SEQ(2) | DEVID(19) | DATA(n) | CRC(2)。"""
    return [
        Field.u8("head_hi", fixed=0x55),
        Field.u8("head_lo", fixed=0xAA),
        Field.u16("len"),
        Field.u8("proto", fixed=PROTO_FLAG),
        Field.u8("cmd"),
        Field.u16("seq"),
        Field.raw("devid", DEVID_LEN),
        Field.raw("data", "{len.val}-25"),
        Field.checksum("crc", 2, group="{len}{proto}{cmd}{seq}{devid}{data}"),
    ]


def dev_spec(**kwargs):
    params = dict(
        fields=dev_fields(),
        payload="data",
        device="devid",
        length=LengthRule("len"),
        checksum=ChecksumRule("crc", dev_crc),
        pdus={0x00: Pdu("Login", 0x00, resp=0x80)},
    )
    params.update(kwargs)
    return FrameSpec(**params)


def basic_fields():
    """AA | LEN(2) | CMD | DATA(len-3) | SUM(2)，LEN 覆盖 CMD+DATA+SUM。"""
    return [
        Field.u8("head", fixed=0xAA),
        Field.u16("len"),
        Field.u8("cmd"),
        Field.raw("data", "{len.val}-3"),
        Field.checksum("crc", 2, group="{len}{cmd}{data}"),
    ]


def basic_spec(**kwargs):
    params = dict(
        fields=basic_fields(),
        payload="data",
        length=LengthRule("len"),
        checksum=ChecksumRule("crc", sum8),
        pdus={1: Pdu("Ping", 1)},
    )
    params.update(kwargs)
    return FrameSpec(**params)


def ack_fields():
    """AA | LEN(1) | CMD | SEQ(2) | DEV(4) | DATA(len-8) | SUM(1)。"""
    return [
        Field.u8("head", fixed=0xAA),
        Field.u8("len"),
        Field.u8("cmd"),
        Field.u16("seq"),
        Field.raw("dev", 4),
        Field.raw("data", "{len.val}-8"),
        Field.checksum("sum", 1, group="{len}{cmd}{seq}{dev}{data}"),
    ]


def ack_spec(**kwargs):
    params = dict(
        fields=ack_fields(),
        payload="data",
        device="dev",
        length=LengthRule("len"),
        checksum=ChecksumRule("sum", sum8),
        seq=SeqPolicy("seq", enabled=True),
        pdus={1: Pdu("Ping", 1, resp=0x81)},
    )
    params.update(kwargs)
    return FrameSpec(**params)


def manual_frame(cmd: int, data: bytes, devid: bytes, seq: int = 0) -> bytes:
    """按 ``dev_fields`` 的布局手工拼一帧，用来对照声明式组帧的结果。

    校验覆盖 ``len..data``（与 spec 的 ``group="{len}{proto}{cmd}{seq}{devid}{data}"``
    一致），所以长度字段也要参与异或。
    """
    devid = (devid + b"\x00" * DEVID_LEN)[:DEVID_LEN]
    body = struct.pack("!BBH", PROTO_FLAG, cmd, seq) + devid + data
    length = struct.pack("!H", len(body) + 2)  # LEN 覆盖 proto..crc
    return b"\x55\xAA" + length + body + xor8(length + body).to_bytes(2, "big")


class TestLargeFrameRoundTrip(unittest.TestCase):
    """大帧（400 字节载荷）的长度/校验回填与回环解析。"""

    DATA = bytes(range(40)) * 10

    def build(self, **kwargs):
        return FrameBuilder(dev_spec(**kwargs)).build_frame(
            0x0E, seq=7, devid=DEVID, data=self.DATA
        )

    def test_iterative_length(self):
        result = self.build()
        self.assertEqual(result.value("len"), 25 + len(self.DATA))
        self.assertEqual(result.length, 29 + len(self.DATA))
        self.assertEqual(result.rounds, 3)  # len=0 → len=425 → crc 稳定

    def test_span_length(self):
        result = self.build(length=LengthRule("len", span=("proto", "crc")))
        self.assertEqual(result.value("len"), 25 + len(self.DATA))
        self.assertEqual(result.data, self.build().data)

    def test_trace_records_every_round(self):
        result = self.build()
        self.assertEqual(len(result.trace), result.rounds)
        first = result.trace[0]
        self.assertEqual(first[1], 0)  # 第一轮帧内长度写的是 0
        self.assertEqual(first[3], 25 + len(self.DATA))  # 但量出来是真实长度

    def test_matches_hand_written(self):
        wire = Protocol(
            dev_spec(seq=SeqPolicy("seq", enabled=True)), device_id=DEVID
        ).build("Login")
        self.assertEqual(wire, manual_frame(0x00, b"", DEVID, seq=0))

    def test_parse_back_with_protocol(self):
        result = self.build()
        frame = Protocol(dev_spec(), device_id=DEVID).verify(result.data)
        self.assertEqual(frame.device_id, DEVID)
        self.assertEqual(frame.value("cmd"), 0x0E)
        self.assertEqual(frame.raw_of("data"), self.DATA)


class TestIteration(unittest.TestCase):
    def test_two_rounds_without_checksum(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xA5),
                Field.u8("len"),
                Field.u8("cmd"),
                Field.raw("data", "{len.val}-1"),
            ],
            payload="data",
            length=LengthRule("len"),
            pdus={1: Pdu("Ping", 1)},
        )
        result = FrameBuilder(spec).build_frame("Ping", data=b"abc")
        self.assertEqual(result.rounds, 2)
        self.assertEqual(result.data, b"\xA5\x04\x01abc")

    def test_single_round_without_length_or_checksum(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0x11), Field.raw("data", 2)],
            payload="data",
        )
        result = FrameBuilder(spec).build_frame(None, data=b"hi")
        self.assertEqual(result.rounds, 1)
        self.assertEqual(result.data, b"\x11hi")

    def test_two_rounds_with_checksum_but_no_length(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0x02),
                Field.raw("data", 4),
                Field.checksum("crc", 2),
            ],
            payload="data",
            checksum=ChecksumRule("crc", crc16_modbus),
        )
        result = FrameBuilder(spec).build_frame(None, data=b"ABCD")
        self.assertEqual(result.rounds, 2)
        self.assertEqual(result.data[-2:], struct.pack("!H", crc16_modbus(b"ABCD")))

    def test_not_converged_with_too_few_rounds(self):
        builder = FrameBuilder(basic_spec(), max_rounds=1)
        with self.assertRaises(FrameBuildError) as ctx:
            builder.build("Ping", data=b"abc")
        text = str(ctx.exception)
        self.assertIn("仍未收敛", text)
        self.assertIn("第 1 轮", text)

    def test_oscillation_is_detected(self):
        class Toggle:
            def __init__(self):
                self.count = 0

            def __call__(self, data):
                self.count += 1
                return b"\x00\x01" if self.count % 2 else b"\x00\x02"

        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u8("len"),
                Field.raw("data", "{len.val}"),
                Field(key="crc", length=2, crc=True),
            ],
            payload="data",
            length=LengthRule("len"),
            checksum=ChecksumRule("crc", Toggle()),
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, data=b"ab")
        self.assertIn("来回震荡", str(ctx.exception))


class TestLengthSpan(unittest.TestCase):
    def test_span_excludes_checksum(self):
        spec = basic_spec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u8("len"),
                Field.u8("cmd"),
                Field.raw("data", "{len.val}"),
                Field.checksum("crc", 2, group="{cmd}{data}"),
            ],
            length=LengthRule("len", span=("data", "data")),
        )
        result = FrameBuilder(spec).build("Ping", data=b"abc")
        self.assertEqual(result[1], 3)  # LEN 只数 data
        self.assertEqual(len(result), 1 + 1 + 1 + 3 + 2)

    def test_span_down_to_crc(self):
        result = FrameBuilder(
            basic_spec(length=LengthRule("len", span=("cmd", "crc")))
        ).build("Ping", data=b"abc")
        self.assertEqual(result[1:3], b"\x00\x06")  # cmd+data+sum = 1+3+2


class TestPayloadModes(unittest.TestCase):
    def test_pdu_fields_packed_in_order(self):
        spec = basic_spec(
            pdus={1: Pdu("Set", 1, [Field.u8("id"), Field.u16("value", little_endian=True)])}
        )
        result = FrameBuilder(spec).build_frame("Set", id=7, value=0x0102)
        self.assertEqual(result.value("data"), b"\x07\x02\x01")
        self.assertEqual(result.value("len"), 6)

    def test_pdu_field_with_length_expression(self):
        spec = basic_spec(
            pdus={1: Pdu("Blob", 1, [Field.u8("count"), Field.raw("blob", "{count.val}*2")])}
        )
        result = FrameBuilder(spec).build_frame("Blob", count=2, blob=b"abcd")
        self.assertEqual(result.value("data"), b"\x02abcd")

    def test_pdu_field_with_fixed_constant(self):
        spec = basic_spec(pdus={1: Pdu("K", 1, [Field.u8("magic", fixed=0x5A)])})
        result = FrameBuilder(spec).build_frame("K")
        self.assertEqual(result.value("data"), b"\x5A")

    def test_pdu_without_fields_and_without_data(self):
        result = FrameBuilder(basic_spec()).build_frame("Ping")
        self.assertEqual(result.value("data"), b"")
        self.assertEqual(result.value("len"), 3)

    def test_raw_payload_bytes(self):
        result = FrameBuilder(basic_spec()).build_frame(0x33, data=b"xyz")
        self.assertEqual(result.value("cmd"), 0x33)
        self.assertEqual(result.value("data"), b"xyz")

    def test_raw_payload_str(self):
        result = FrameBuilder(basic_spec()).build_frame(0x33, data="hi")
        self.assertEqual(result.value("data"), b"hi")

    def test_payload_wrong_type(self):
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(basic_spec()).build(0x33, data=123)
        self.assertIn("需要 bytes/str", str(ctx.exception))

    def test_pdu_payload_length_mismatch(self):
        # 表达式偏移写错（-4 而不是 -3）：载荷 2 字节但表达式算 1 字节
        spec = basic_spec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u16("len"),
                Field.u8("cmd"),
                Field.raw("data", "{len.val}-4"),
                Field.checksum("crc", 2, group="{len}{cmd}{data}"),
            ],
            pdus={1: Pdu("P", 1, [Field.raw("blob", 2)])},
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build_frame("P", blob=b"ab")
        self.assertIn("对面按同一规则解析会错位", str(ctx.exception))

    def test_fixed_payload_length_mismatch(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.raw("data", 2)],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, data=b"abc")
        self.assertIn("载荷实际 3 字节", str(ctx.exception))

    def test_pdu_needs_payload_field(self):
        fields = [Field.u8("head", fixed=0xAA), Field.u8("cmd")]
        spec = FrameSpec(fields=fields, pdus={1: Pdu("P", 1, [Field.u8("x")])})
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build("P", x=1)
        self.assertIn("payload", str(ctx.exception))

    def test_pdu_field_with_crc_rejected(self):
        spec = basic_spec(pdus={1: Pdu("P", 1, [Field.checksum("sum", 1)])})
        with self.assertRaises(FrameRuleError) as ctx:
            FrameBuilder(spec)
        self.assertIn("不能声明 crc", str(ctx.exception))

    def test_adhoc_pdu_not_declared(self):
        spec = basic_spec()
        adhoc = Pdu("Adhoc", 0x44, [Field.u8("n"), Field.raw("text", "{n.val}")])
        result = FrameBuilder(spec).build_frame(adhoc, n=3, text=b"abc")
        self.assertEqual(result.value("cmd"), 0x44)
        self.assertEqual(result.value("data"), b"\x03abc")

    def test_declared_pdu_by_value(self):
        spec = basic_spec(pdus={1: Pdu("Ping", 1, [Field.u8("n")])})
        result = FrameBuilder(spec).build_frame(Pdu("Ping", 1, [Field.u8("n")]), n=5)
        self.assertEqual(result.value("data"), b"\x05")

    def test_declared_pdu_by_object_uses_its_fields(self):
        # 同名但字段不同：按传进来的对象组帧
        spec = basic_spec(pdus={1: Pdu("Ping", 1, [Field.u8("n")])})
        other = Pdu("Ping", 1, [Field.u16("n")])
        result = FrameBuilder(spec).build_frame(other, n=5)
        self.assertEqual(result.value("data"), b"\x00\x05")

    # ------------------------------------------------------ cmd 省略（字典键回填）
    def test_cmd_omitted_matches_explicit(self):
        explicit = basic_spec(pdus={1: Pdu("Ping", 1, [Field.u8("n")])})
        inferred = basic_spec(pdus={1: Pdu("Ping", fields=[Field.u8("n")])})
        a = FrameBuilder(explicit).build(1, n=7)
        b = FrameBuilder(inferred).build(1, n=7)
        self.assertEqual(a, b)

    def test_cmd_omitted_by_name_and_code(self):
        spec = basic_spec(pdus={1: Pdu("Ping", [Field.u8("n")])})
        builder = FrameBuilder(spec)
        self.assertEqual(builder.build(1, n=7), builder.build("Ping", n=7))

    def test_cmd_omitted_pdu_object_resolved_by_name(self):
        spec = basic_spec(pdus={1: Pdu("Ping", [Field.u8("n")])})
        result = FrameBuilder(spec).build_frame(Pdu("Ping", [Field.u8("n")]), n=9)
        self.assertEqual(result.value("cmd"), 1)
        self.assertEqual(result.value("data"), b"\x09")

    def test_cmd_omitted_undeclared_pdu_raises(self):
        spec = basic_spec()
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build_frame(Pdu("Ghost", [Field.u8("n")]), n=1)
        self.assertIn("没有命令码", str(ctx.exception))

    def test_cmd_omitted_build_ack(self):
        spec = basic_spec(pdus={1: Pdu("Ping", resp=0x81)})
        self.assertEqual(Protocol(spec).build_ack(Pdu("Ping"))[3], 0x81)

    def test_cmd_omitted_build_ack_undeclared_pdu_raises(self):
        proto = Protocol(basic_spec(pdus={1: Pdu("Ping")}))
        with self.assertRaises(FrameBuildError) as ctx:
            proto.build_ack(Pdu("Ghost"))
        self.assertIn("没有命令码", str(ctx.exception))


class TestArgumentErrors(unittest.TestCase):
    def setUp(self):
        self.builder = FrameBuilder(basic_spec())

    def test_unknown_argument(self):
        with self.assertRaises(FrameBuildError) as ctx:
            self.builder.build("Ping", nope=1)
        self.assertIn("不认识的参数 ['nope']", str(ctx.exception))

    def test_manual_length_rejected(self):
        with self.assertRaises(FrameBuildError) as ctx:
            self.builder.build("Ping", len=6)
        self.assertIn("自动计算", str(ctx.exception))

    def test_manual_checksum_rejected(self):
        with self.assertRaises(FrameBuildError) as ctx:
            self.builder.build("Ping", crc=0)
        self.assertIn("自动计算", str(ctx.exception))

    def test_missing_shell_argument(self):
        spec = basic_spec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u8("len"),
                Field.u8("cmd"),
                Field.u8("tag"),
                Field.raw("data", "{len.val}-4"),
                Field.checksum("crc", 2),
            ]
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build("Ping", data=b"x")
        self.assertIn("缺少参数 ['tag']", str(ctx.exception))

    def test_missing_pdu_field(self):
        spec = basic_spec(pdus={1: Pdu("P", 1, [Field.u8("a"), Field.u8("b")])})
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build("P", a=1)
        self.assertIn("缺少参数 ['b']", str(ctx.exception))

    def test_data_argument_rejected_when_pdu_has_fields(self):
        spec = basic_spec(pdus={1: Pdu("P", 1, [Field.u8("a")])})
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build("P", a=1, data=b"x")
        self.assertIn("不认识的参数 ['data']", str(ctx.exception))

    def test_target_without_cmd_field(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.rest("data")],
            payload="data",
            framing=DelimiterFraming(end=0x0A),
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(1, data=b"x")
        self.assertIn("没有命令码字段", str(ctx.exception))

    def test_adhoc_pdu_without_cmd_field(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.rest("data")],
            payload="data",
            framing=DelimiterFraming(end=0x0A),
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(Pdu("X", 1, [Field.u8("x")]), x=1)
        self.assertIn("没有命令码字段", str(ctx.exception))

    def test_spec_without_payload(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.u8("cmd")],
            length=None,
        )
        self.assertEqual(FrameBuilder(spec).build(0x05), b"\xAA\x05")

    def test_device_int_value(self):
        spec = FrameSpec(
            fields=[Field.raw("dev", 1), Field.raw("data", 1)],
            payload="data",
            device="dev",
        )
        result = FrameBuilder(spec, device_id=7).build_frame(None, data=b"x")
        self.assertEqual(result.value("dev"), b"\x07")

    def test_build_raw_bypasses_pdu_fields(self):
        spec = basic_spec(pdus={1: Pdu("Set", 1, [Field.u8("id")])})
        wire = FrameBuilder(spec).build_raw("Set", b"\xDE\xAD")
        plain = FrameBuilder(basic_spec()).build(1, data=b"\xDE\xAD")
        self.assertEqual(wire, plain)
        self.assertEqual(wire[4:6], b"\xDE\xAD")

    def test_build_raw_without_payload_field(self):
        spec = FrameSpec(fields=[Field.u8("head", fixed=0xAA), Field.u8("cmd")])
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build_raw(1, b"x")
        self.assertIn("没有载荷字段", str(ctx.exception))

    def test_unknown_pdu_name(self):
        with self.assertRaises(FrameBuildError) as ctx:
            self.builder.build("Nope")
        self.assertIn("找不到报文", str(ctx.exception))

    def test_target_must_be_cmd_or_name(self):
        with self.assertRaises(FrameBuildError) as ctx:
            self.builder.build(["Ping"])
        self.assertIn("组帧目标必须是", str(ctx.exception))

    def test_cmd_conflict(self):
        with self.assertRaises(FrameBuildError) as ctx:
            self.builder.build("Ping", cmd=9)
        self.assertIn("一个帧只能有一个命令码", str(ctx.exception))

    def test_same_cmd_value_is_fine(self):
        self.assertEqual(
            self.builder.build("Ping", cmd=1, data=b""), b"\xAA\x00\x03\x01\x00\x04"
        )


class TestValuePacking(unittest.TestCase):
    def test_u8_overflow(self):
        spec = basic_spec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u8("len"),
                Field.u8("cmd"),
                Field.raw("data", "{len.val}"),
            ],
            payload="data",
            length=LengthRule("len"),
            checksum=None,
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(1, data=b"x" * 300)
        self.assertIn("装不进 fmt", str(ctx.exception))

    def test_raw_length_field_overflow(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.raw("len", 1),
                Field.raw("cmd", 1),
                Field.raw("data", "{len.val}"),
            ],
            payload="data",
            length=LengthRule("len"),
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, cmd=b"\x01", data=b"x" * 300)
        self.assertIn("超出 1 字节可表示范围", str(ctx.exception))

    def test_integer_field_rejects_string(self):
        spec = basic_spec(
            fields=[Field.u8("head", fixed=0xAA), Field.u8("cmd"), Field.raw("data", 1)],
            payload="data",
            cmd="cmd",
            length=None,
            checksum=None,
            pdus={},
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, cmd="x", data=b"a")
        self.assertIn("装不进 fmt", str(ctx.exception))

    def test_raw_field_accepts_int_str_bytes(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.raw("tag", 2), Field.raw("data", 1)],
            payload="data",
        )
        builder = FrameBuilder(spec)
        self.assertEqual(builder.build(None, tag=0x0102, data=b"x"), b"\xAA\x01\x02x")
        self.assertEqual(builder.build(None, tag="ab", data=b"x"), b"\xAAabx")

    def test_raw_field_int_overflow(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.raw("tag", 1), Field.raw("data", 1)],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, tag=300, data=b"x")
        self.assertIn("超出 1 字节", str(ctx.exception))

    def test_raw_field_rejects_float(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.raw("tag", 1), Field.raw("data", 1)],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, tag=1.5, data=b"x")
        self.assertIn("必须是 bytes/str/int", str(ctx.exception))

    def test_raw_field_rejects_bool(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.raw("tag", 1), Field.raw("data", 1)],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, tag=True, data=b"x")
        self.assertIn("不收布尔值", str(ctx.exception))

    def test_prepacked_bytes_with_wrong_size(self):
        spec = basic_spec(
            fields=[Field.u8("head", fixed=0xAA), Field.u16("tag"), Field.raw("data", 1)],
            payload="data",
            cmd=None,
            length=None,
            checksum=None,
            pdus={},
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, tag=b"\x01", data=b"x")
        self.assertIn("需要 2 字节", str(ctx.exception))

    def test_negative_computed_length(self):
        spec = basic_spec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u8("cmd"),
                Field.raw("extra", "{head.val}-200"),
                Field.raw("data", 1),
            ],
            payload="data",
            cmd="cmd",
            length=None,
            checksum=None,
            pdus={},
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, cmd=1, extra=b"", data=b"x")
        self.assertIn("负长度", str(ctx.exception))

    def test_length_callable_exception(self):
        def boom(fields):
            raise RuntimeError("boom")

        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.raw("tag", boom), Field.raw("data", 1)],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, tag=b"x", data=b"y")
        self.assertIn("长度回调异常", str(ctx.exception))

    def test_length_callable_rule_error_passthrough(self):
        def boom(fields):
            raise FrameRuleError("配置错了")

        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.raw("tag", boom), Field.raw("data", 1)],
            payload="data",
        )
        with self.assertRaises(FrameRuleError):
            FrameBuilder(spec).build(None, tag=b"x", data=b"y")

    def test_length_callable_must_return_int(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.raw("tag", lambda fields: "x"),
                Field.raw("data", 1),
            ],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, tag=b"x", data=b"y")
        self.assertIn("长度必须是 int", str(ctx.exception))

    def test_length_expression_on_non_int_field(self):
        spec = FrameSpec(
            fields=[
                Field.raw("head", 1),
                Field.raw("cmd", 1),
                Field.raw("data", "{cmd.val}"),
            ],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build(None, head=b"\xAA", cmd=b"\x01", data=b"x")
        self.assertIn("长度表达式求值失败", str(ctx.exception))

    def test_fixed_constant_too_wide_at_construction(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0xAA), Field.raw("tag", 4, fixed=b"ab"), Field.raw("data", 1)],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec)
        self.assertIn("常量字段", str(ctx.exception))

    def test_fixed_int_overflow_at_construction(self):
        spec = FrameSpec(
            fields=[Field.u8("head", fixed=0x1FF), Field.raw("data", 1)],
            payload="data",
        )
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec)
        self.assertIn("装不进 fmt", str(ctx.exception))

    def test_fixed_str_and_int_without_fmt(self):
        spec = FrameSpec(
            fields=[
                Field.raw("head", 2, fixed=b"\xAA\x55"),
                Field.raw("flag", 1, fixed=0x7E),
                Field.raw("name", 2, fixed="hi"),
                Field.raw("data", 1),
            ],
            payload="data",
        )
        self.assertEqual(FrameBuilder(spec).build(None, data=b"x"), b"\xAA\x55\x7Ehi" + b"x")

    def test_fixed_with_expression_length(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u8("len"),
                Field(key="pad", length="{len.val}-{len.val}+2", fixed=b"\x00\x00"),
                Field.raw("data", "{len.val}-2"),
            ],
            payload="data",
            length=LengthRule("len"),
        )
        # pad 的长度表达式只在组帧时求值，构造期算不出来 → 走非缓存分支
        result = FrameBuilder(spec).build_frame(None, data=b"x")
        self.assertEqual(result.value("len"), 3)
        self.assertEqual(result.value("pad"), b"\x00\x00")

    def test_max_frame_size(self):
        spec = basic_spec(max_frame_size=16)
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build("Ping", data=b"x" * 32)
        self.assertIn("max_frame_size", str(ctx.exception))

    def test_non_framespec(self):
        with self.assertRaises(FrameRuleError):
            FrameBuilder(basic_fields())

    def test_max_rounds_must_be_positive(self):
        with self.assertRaises(FrameRuleError):
            FrameBuilder(basic_spec(), max_rounds=0)


class TestChecksumRules(unittest.TestCase):
    def test_returned_bytes_size_must_match(self):
        spec = basic_spec(checksum=ChecksumRule("crc", lambda data: b"\x01"))
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build("Ping", data=b"a")
        self.assertIn("校验函数返回 1 字节", str(ctx.exception))

    def test_returned_type_must_be_int_or_bytes(self):
        spec = basic_spec(checksum=ChecksumRule("crc", lambda data: "nope"))
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec).build("Ping", data=b"a")
        self.assertIn("必须返回 int 或 bytes", str(ctx.exception))

    def test_int_without_fmt_packs_by_field_width(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.raw("data", 1),
                Field(key="crc", length=3, crc=True),
            ],
            payload="data",
            checksum=ChecksumRule("crc", lambda data: 0x010203),
        )
        result = FrameBuilder(spec).build_frame(None, data=b"x")
        self.assertEqual(result.data[-3:], b"\x01\x02\x03")

    def test_bytes_without_fmt(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.raw("data", 1),
                Field(key="crc", length=3, crc=True),
            ],
            payload="data",
            checksum=ChecksumRule("crc", lambda data: b"\x0A\x0B\x0C"),
        )
        result = FrameBuilder(spec).build_frame(None, data=b"x")
        self.assertEqual(result.data[-3:], b"\x0A\x0B\x0C")

    def test_bit_flip_changes_checksum(self):
        builder = FrameBuilder(basic_spec())
        one = builder.build("Ping", data=b"a")
        two = builder.build("Ping", data=b"b")
        self.assertNotEqual(one[-2:], two[-2:])


class TestDeviceHandling(unittest.TestCase):
    def test_device_from_constructor_and_padding(self):
        builder = FrameBuilder(dev_spec(seq=SeqPolicy("seq")), device_id="DEV")
        result = builder.build_frame("Login", seq=0)
        self.assertEqual(result.value("devid"), DEVID_LEN * b"DEV"[:0] + b"DEV".ljust(19, b"\x00"))
        self.assertEqual(len(result.value("devid")), DEVID_LEN)

    def test_device_from_values(self):
        builder = FrameBuilder(dev_spec())
        result = builder.build_frame("Login", seq=0, devid=b"X" * 19)
        self.assertEqual(result.value("devid"), b"X" * 19)
        self.assertEqual(builder.device_id, None)

    def test_device_too_long(self):
        builder = FrameBuilder(dev_spec(), device_id=b"Y" * 20)
        with self.assertRaises(FrameBuildError) as ctx:
            builder.build_frame("Login", seq=0)
        self.assertIn("超过字段", str(ctx.exception))

    def test_device_missing(self):
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(dev_spec()).build_frame("Login", seq=0)
        self.assertIn("没有值", str(ctx.exception))

    def test_device_as_int_field(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u32("dev"),
                Field.raw("data", 1),
            ],
            payload="data",
            device="dev",
        )
        result = FrameBuilder(spec, device_id=0x01020304).build_frame(None, data=b"x")
        self.assertEqual(result.value("dev"), 0x01020304)

    def test_device_from_constructor_bytes(self):
        spec = FrameSpec(
            fields=[Field.raw("dev", 2), Field.raw("data", 1)],
            payload="data",
            device="dev",
        )
        result = FrameBuilder(spec, device_id=b"ZZ").build_frame(None, data=b"x")
        self.assertEqual(result.value("dev"), b"ZZ")

    def test_device_id_setter(self):
        builder = FrameBuilder(dev_spec())
        builder.device_id = b"Z" * 19
        self.assertEqual(builder.device_id, b"Z" * 19)


class TestSeqPolicy(unittest.TestCase):
    def test_auto_increment(self):
        builder = FrameBuilder(ack_spec(), device_id=b"DEV1")
        first = builder.build_frame("Ping", data=b"")
        second = builder.build_frame("Ping", data=b"")
        self.assertEqual(first.value("seq"), 0)
        self.assertEqual(second.value("seq"), 1)
        self.assertEqual(builder.seq, 2)

    def test_wrap(self):
        spec = ack_spec(seq=SeqPolicy("seq", enabled=True, start=0xFFFF))
        builder = FrameBuilder(spec, device_id=b"DEV1")
        self.assertEqual(builder.build_frame("Ping", data=b"").value("seq"), 0xFFFF)
        self.assertEqual(builder.build_frame("Ping", data=b"").value("seq"), 0)

    def test_explicit_value_realigns_counter(self):
        builder = FrameBuilder(ack_spec(), device_id=b"DEV1")
        self.assertEqual(builder.build_frame("Ping", data=b"", seq=100).value("seq"), 100)
        self.assertEqual(builder.seq, 101)
        self.assertEqual(builder.build_frame("Ping", data=b"").value("seq"), 101)

    def test_explicit_value_must_be_int(self):
        builder = FrameBuilder(ack_spec(), device_id=b"DEV1")
        with self.assertRaises(FrameBuildError) as ctx:
            builder.build("Ping", data=b"", seq="x")
        self.assertIn("需要整数", str(ctx.exception))

    def test_disabled_requires_value(self):
        spec = ack_spec(seq=SeqPolicy("seq"))
        with self.assertRaises(FrameBuildError) as ctx:
            FrameBuilder(spec, device_id=b"DEV1").build("Ping", data=b"")
        self.assertIn("缺少参数 ['seq']", str(ctx.exception))


def auto_fields():
    """AA | LEN(1) | CMD | SEQ(2) | TS(4) | DATA(len-8) | SUM(1)。"""
    return [
        Field.u8("head", fixed=0xAA),
        Field.u8("len"),
        Field.u8("cmd"),
        Field.u16("seq"),
        Field.u32("ts"),
        Field.raw("data", "{len.val}-8"),
        Field.checksum("sum", 1, group="{len}{cmd}{seq}{ts}{data}"),
    ]


def auto_spec(auto, **kwargs):
    params = dict(
        fields=auto_fields(),
        payload="data",
        cmd="cmd",
        length=LengthRule("len"),
        checksum=ChecksumRule("sum", sum8),
    )
    params.update(kwargs)
    return FrameSpec(auto=auto, **params)


class TestAutoFields(unittest.TestCase):
    """一份协议里的"除指令和 data 之外、需要自动填值"的字段，可以 0..N 个。"""

    def test_two_counters_are_independent(self):
        spec = auto_spec([
            AutoField("seq", start=10, step=1),
            AutoField("ts", start=1000, step=10),
        ])
        builder = FrameBuilder(spec)
        first = builder.build_frame(0x01, data=b"")
        second = builder.build_frame(0x01, data=b"")
        self.assertEqual((first.value("seq"), first.value("ts")), (10, 1000))
        self.assertEqual((second.value("seq"), second.value("ts")), (11, 1010))
        self.assertEqual(builder.auto_keys, ["seq", "ts"])

    def test_provider_called_each_build(self):
        seen = []

        def clock():
            seen.append(len(seen))
            return 0x11223344

        spec = auto_spec([AutoField("seq"), AutoField("ts", provider=clock)])
        builder = FrameBuilder(spec)
        a = builder.build_frame(0x01, data=b"")
        b = builder.build_frame(0x01, data=b"")
        self.assertEqual(a.value("ts"), 0x11223344)
        self.assertEqual(b.value("ts"), 0x11223344)
        self.assertEqual(len(seen), 2)  # 每次组帧调一次，不随不动点轮数增加

    def test_seq_property_is_first_counter(self):
        builder = FrameBuilder(auto_spec([AutoField("seq", start=7), AutoField("ts")]))
        self.assertEqual(builder.seq, 7)
        builder.build_frame(0x01, data=b"")
        self.assertEqual(builder.seq, 8)

    def test_no_auto_fields_means_no_auto_keys(self):
        builder = FrameBuilder(basic_spec())
        self.assertEqual(builder.auto_keys, [])
        self.assertEqual(builder.seq, 0)

    def test_explicit_value_realigns_only_that_counter(self):
        builder = FrameBuilder(auto_spec([
            AutoField("seq"), AutoField("ts", start=100),
        ]))
        result = builder.build_frame(0x01, data=b"", seq=50)
        self.assertEqual(result.value("seq"), 50)
        self.assertEqual(result.value("ts"), 100)
        # 下一个 seq 从 51 走，ts 已经变成 101
        nxt = builder.build_frame(0x01, data=b"")
        self.assertEqual((nxt.value("seq"), nxt.value("ts")), (51, 101))

    def test_provider_bytes_for_raw_field(self):
        spec = FrameSpec(
            fields=[
                Field.u8("head", fixed=0xAA),
                Field.u8("len"),
                Field.u8("cmd"),
                Field.raw("tok", 2),
                Field.raw("data", "{len.val}-4"),
                Field.checksum("sum", 1, group="{len}{cmd}{tok}{data}"),
            ],
            payload="data",
            cmd="cmd",
            length=LengthRule("len"),
            checksum=ChecksumRule("sum", sum8),
            auto=[AutoField("tok", provider=lambda: b"\xBE\xEF")],
        )
        result = FrameBuilder(spec).build_frame(0x01, data=b"")
        self.assertEqual(result.value("tok"), b"\xBE\xEF")

    def test_seq_policy_and_auto_coexist(self):
        """老写法 seq= 与 auto= 可以同时用，seq 归一化后排在前面。"""
        spec = auto_spec(
            [AutoField("ts", start=100)],
            seq=SeqPolicy("seq", enabled=True, start=5),
        )
        builder = FrameBuilder(spec)
        first = builder.build_frame(0x01, data=b"")
        self.assertEqual(first.value("seq"), 5)
        self.assertEqual(first.value("ts"), 100)
        self.assertEqual(builder.auto_keys, ["seq", "ts"])

    def test_build_ack_echoes_all_echoable_autos(self):
        spec = auto_spec([
            AutoField("seq"),
            AutoField("ts", provider=lambda: 0, echo=False),
        ])
        proto = Protocol(spec)
        req = proto.build(0x01, data=b"", seq=42, ts=999)
        frame = proto.feed(req)[0]
        ack = proto.build_ack(frame)
        # 应答里 seq 回显 42；ts 声明了 echo=False，会重新取 provider=0
        parsed = proto.feed(ack)[0]
        self.assertEqual(parsed.value("seq"), 42)
        self.assertEqual(parsed.value("ts"), 0)


class TestDelimiterFramingBuild(unittest.TestCase):
    def setUp(self):
        self.framing = DelimiterFraming(start=0x7E, end=0x7E, escape=0x7D, escape_xor=0x20)
        self.spec = FrameSpec(
            fields=[
                Field.u8("cmd"),
                Field.u8("len"),
                Field.raw("data", "{len.val}"),
                Field.checksum("crc", 1, group="{cmd}{data}"),
            ],
            payload="data",
            framing=self.framing,
            length=LengthRule("len", span=("data", "data")),
            checksum=ChecksumRule("crc", xor8),
        )

    def test_escape_and_delimiters(self):
        result = FrameBuilder(self.spec).build_frame(0x7E, data=b"\x7e\x7d\x00")
        self.assertEqual(result.body, b"\x7E\x03\x7E\x7D\x00\x7D")
        self.assertEqual(result.data[0], 0x7E)
        self.assertEqual(result.data[-1], 0x7E)
        self.assertIn(b"\x7D\x5E", result.data)

    def test_round_trip(self):
        proto = Protocol(self.spec)
        wire = proto.build(0x01, data=b"\x7E weird")
        frame = proto.verify(wire)
        self.assertEqual(frame.value("data"), b"\x7E weird")
        self.assertEqual(frame.wire, wire)

    def test_frame_without_checksum(self):
        spec = FrameSpec(
            fields=[Field.rest("data")],
            payload="data",
            framing=DelimiterFraming(end=0x0A),
        )
        result = FrameBuilder(spec).build_frame(None, data=b"AT\r")
        self.assertEqual(result.data, b"AT\r\n")


class TestBuildResult(unittest.TestCase):
    def setUp(self):
        self.result = FrameBuilder(basic_spec()).build_frame("Ping", data=b"abc")

    def test_bytes_and_len(self):
        self.assertEqual(bytes(self.result), self.result.data)
        self.assertEqual(len(self.result), len(self.result.data))
        self.assertEqual(self.result.length, len(self.result.body))

    def test_value_and_hex(self):
        self.assertEqual(self.result.value("cmd"), 1)
        self.assertEqual(self.result.value("nope", "d"), "d")
        self.assertEqual(self.result.to_hex(sep=""), self.result.data.hex().upper())
        self.assertEqual(self.result.to_hex(upper=False), self.result.data.hex(" "))

    def test_fields_and_cmd(self):
        self.assertEqual(self.result.cmd, 1)
        self.assertEqual(self.result.name, "Ping")
        self.assertEqual(sorted(self.result.fields), ["cmd", "crc", "data", "head", "len"])

    def test_body_equals_data_for_length_framing(self):
        self.assertEqual(self.result.body, self.result.data)


class TestProtocol(unittest.TestCase):
    def test_build_and_feed(self):
        proto = Protocol(basic_spec())
        wire = proto.build("Ping", data=b"abc")
        frames = proto.feed(wire)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"abc")

    def test_verify_detects_mismatch(self):
        bad_rx = basic_spec(
            fields=[Field.u8("head", fixed=0x99)] + basic_fields()[1:]
        )
        proto = Protocol(basic_spec(), bad_rx)
        with self.assertRaises(FrameBuildError) as ctx:
            proto.verify(proto.build("Ping", data=b"a"))
        self.assertIn("回环自检失败", str(ctx.exception))

    def test_build_ack_from_frame_echoes_seq_and_device(self):
        spec = ack_spec()
        proto = Protocol(spec, device_id=b"DEV1")
        request = proto.feed(proto.build("Ping", data=b"hi", seq=7))[0]
        reply = proto.build_ack(request)
        self.assertEqual(reply[2], 0x81)  # cmd|0x80
        frame = proto.verify(reply)
        self.assertEqual(frame.value("seq"), 7)
        self.assertEqual(frame.value("dev"), b"DEV1")
        self.assertEqual(frame.value("data"), b"")

    def test_build_ack_uses_pdu_resp(self):
        spec = basic_spec(pdus={1: Pdu("Ping", 1, resp=0x02)})
        proto = Protocol(spec)
        self.assertEqual(proto.build_ack(1)[3], 0x02)

    def test_build_ack_from_cmd_name_and_pdu(self):
        spec = basic_spec(pdus={1: Pdu("Ping", 1)})
        proto = Protocol(spec)
        self.assertEqual(proto.build_ack("Ping")[3], 0x81)
        self.assertEqual(proto.build_ack(Pdu("Ping", 1))[3], 0x81)

    def test_build_ack_unknown_name(self):
        proto = Protocol(basic_spec())
        with self.assertRaises(FrameBuildError) as ctx:
            proto.build_ack("Nope")
        self.assertIn("找不到报文", str(ctx.exception))

    def test_build_ack_non_int_cmd(self):
        spec = basic_spec(pdus={"X": Pdu("X", "X")})
        proto = Protocol(spec)
        with self.assertRaises(FrameBuildError) as ctx:
            proto.build_ack(Pdu("X", "X"))
        self.assertIn("无法从", str(ctx.exception))

    def test_build_ack_bytes_target(self):
        proto = Protocol(basic_spec())
        with self.assertRaises(FrameBuildError) as ctx:
            proto.build_ack(b"\x01")
        self.assertIn("无法从", str(ctx.exception))

    def test_protocol_build_frame_passthrough(self):
        result = Protocol(basic_spec()).build_frame("Ping", data=b"ab")
        self.assertEqual(result.value("cmd"), 1)
        self.assertEqual(result.rounds, 3)  # 长度回填后校验要跟着重算

    def test_protocol_build_raw(self):
        proto = Protocol(basic_spec())
        self.assertEqual(proto.build_raw(0x01, b"ab"), proto.build(0x01, data=b"ab"))

    def test_build_ack_frame_without_cmd_field(self):
        fields = [Field.u8("head", fixed=0xAA), Field.u8("len"), Field.raw("data", "{len.val}")]
        rx = FrameSpec(fields=fields, payload="data", length=LengthRule("len"))
        proto = Protocol(basic_spec(), rx)
        frame = proto.feed(b"\xAA\x01x")[0]
        with self.assertRaises(FrameBuildError) as ctx:
            proto.build_ack(frame)
        self.assertIn("没有命令码字段", str(ctx.exception))

    def test_device_id_property_propagates_to_codec(self):
        proto = Protocol(dev_spec())
        codec = proto.codec
        self.assertIs(proto.codec, codec)  # 懒加载只建一次
        proto.device_id = DEVID
        self.assertEqual(proto.device_id, DEVID)
        self.assertEqual(codec.device_id, DEVID)

    def test_device_id_in_constructor_binds_codec(self):
        proto = Protocol(dev_spec(), device_id=DEVID)
        self.assertEqual(proto.codec.device_id, DEVID)

    def test_enforce_device_id(self):
        proto = Protocol(dev_spec(), device_id=b"Z" * 19, enforce_device_id=True)
        result = FrameBuilder(dev_spec(), device_id=DEVID).build_frame(
            "Login", seq=0
        )
        self.assertEqual(proto.feed(result.data), [])

    def test_diff_and_same_spec(self):
        proto = Protocol(basic_spec())
        self.assertEqual(proto.diff(), [])
        other = Protocol(basic_spec(), basic_spec(payload="cmd"))
        self.assertTrue(any("payload" in line for line in other.diff()))

    def test_reset_drops_pending(self):
        proto = Protocol(basic_spec())
        proto.feed(b"\xAA\x00")
        self.assertTrue(proto.codec.pending_bytes)
        proto.reset()
        self.assertEqual(proto.codec.pending_bytes, b"")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
