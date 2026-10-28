# -*- coding: utf-8 -*-
"""``FrameSpec`` 等组帧描述的声明期校验与查询。"""

import unittest

from kkprotocol import (
    AutoField,
    ChecksumRule,
    DelimiterFraming,
    Field,
    FrameRuleError,
    FrameSpec,
    LengthRule,
    Pdu,
    SeqPolicy,
    sum8,
    xor8,
)


def basic_fields():
    """AA | len(2) | cmd | data(len-3) | crc(2)，len 覆盖 cmd+data+crc。"""
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


class TestFrameSpecValidation(unittest.TestCase):
    def assert_rule_error(self, **kwargs):
        with self.assertRaises(FrameRuleError) as ctx:
            basic_spec(**kwargs)
        return str(ctx.exception)

    def test_empty_fields(self):
        self.assertIn("不能为空", self.assert_rule_error(fields=[]))

    def test_dict_rule_rejected(self):
        text = self.assert_rule_error(fields=[Field.u8("a"), {"key": "b", "len": 1}])
        self.assertIn("只接受 Field", text)

    def test_duplicate_key(self):
        fields = basic_fields() + [Field.u8("cmd")]
        self.assertIn("重复", self.assert_rule_error(fields=fields))

    def test_payload_missing(self):
        self.assertIn("payload", self.assert_rule_error(payload="body"))

    def test_device_missing(self):
        self.assertIn("device", self.assert_rule_error(device="dev"))

    def test_cmd_missing(self):
        self.assertIn("cmd=", self.assert_rule_error(cmd="command"))

    def test_pdus_need_cmd_field(self):
        fields = [Field.u8("head", fixed=0xAA), Field.u8("len"), Field.raw("data", "{len.val}")]
        text = self.assert_rule_error(
            fields=fields,
            payload="data",
            length=LengthRule("len"),
            checksum=None,
            pdus={1: Pdu("Ping", 1)},
        )
        self.assertIn("命令码", text)

    def test_delimiter_string_rejected(self):
        text = self.assert_rule_error(framing="delimiter")
        self.assertIn("DelimiterFraming", text)

    def test_length_key_unknown(self):
        self.assertIn("长度字段", self.assert_rule_error(length=LengthRule("size")))

    def test_length_key_must_be_fixed(self):
        fields = [
            Field.u8("head", fixed=0xAA),
            Field.raw("len", "{head.val}"),
            Field.raw("data", 2),
        ]
        text = self.assert_rule_error(fields=fields, payload="data", checksum=None, length=LengthRule("len"), pdus={})
        self.assertIn("定长字段", text)

    def test_span_unknown_field(self):
        text = self.assert_rule_error(length=LengthRule("len", span=("nope", "crc")))
        self.assertIn("不存在的字段", text)

    def test_span_must_start_after_length(self):
        text = self.assert_rule_error(length=LengthRule("len", span=("head", "crc")))
        self.assertIn("必须在长度字段", text)

    def test_span_end_before_start(self):
        text = self.assert_rule_error(length=LengthRule("len", span=("crc", "cmd")))
        self.assertIn("不能早于起点", text)

    def test_payload_cannot_be_length_field(self):
        text = self.assert_rule_error(payload="len")
        self.assertIn("不能是同一个字段", text)

    def test_checksum_cannot_be_length_field(self):
        text = self.assert_rule_error(checksum=ChecksumRule("len", sum8))
        self.assertIn("不能是同一个字段", text)

    def test_checksum_key_unknown(self):
        self.assertIn("校验字段", self.assert_rule_error(checksum=ChecksumRule("fcs", sum8)))

    def test_checksum_field_must_be_marked(self):
        fields = [
            Field.u8("head", fixed=0xAA),
            Field.u16("len"),
            Field.u8("cmd"),
            Field.raw("data", "{len.val}-3"),
            Field(key="crc", length=2, fmt="!H", group=None),
        ]
        text = self.assert_rule_error(fields=fields)
        self.assertIn("crc=True", text)

    def test_checksum_field_must_be_fixed(self):
        fields = [
            Field.u8("head", fixed=0xAA),
            Field.u8("len"),
            Field(key="crc", length="{len.val}", crc=True),
        ]
        text = self.assert_rule_error(
            fields=fields,
            payload=None,
            length=LengthRule("len"),
            checksum=ChecksumRule("crc", sum8),
            pdus={},
        )
        self.assertIn("定长字段", text)

    def test_seq_key_unknown(self):
        self.assertIn("序列号字段", self.assert_rule_error(seq=SeqPolicy("serial")))

    def test_seq_wrap_must_be_positive(self):
        text = self.assert_rule_error(seq=SeqPolicy("cmd", enabled=True, wrap=0))
        self.assertIn("seq.wrap", text)

    def test_pdu_key_must_match_cmd(self):
        text = self.assert_rule_error(pdus={1: Pdu("Ping", 2)})
        self.assertIn("不一致", text)

    def test_pdu_name_unique(self):
        text = self.assert_rule_error(pdus={1: Pdu("Ping", 1), 2: Pdu("Ping", 2)})
        self.assertIn("名字重复", text)

    def test_pdu_field_must_be_field(self):
        text = self.assert_rule_error(pdus={1: Pdu("Ping", 1, [{"key": "x", "len": 1}])})
        self.assertIn("只接受 Field", text)

    def test_pdu_field_key_unique(self):
        text = self.assert_rule_error(
            pdus={1: Pdu("Ping", 1, [Field.u8("x"), Field.u8("x")])}
        )
        self.assertIn("载荷字段 key 重复", text)

    def test_pdu_field_key_clashes_shell(self):
        text = self.assert_rule_error(pdus={1: Pdu("Ping", 1, [Field.u8("cmd")])})
        self.assertIn("与帧壳字段重名", text)

    def test_pdu_fields_default_empty(self):
        self.assertEqual(Pdu("Ping", 1).field_keys(), [])


class TestPduCmdInference(unittest.TestCase):
    """``Pdu.cmd`` 可以省略，由 ``FrameSpec.pdus`` 的键回填。"""

    def test_cmd_filled_from_key(self):
        spec = basic_spec(pdus={0x03: Pdu("Read", fields=[Field.u8("n")])})
        self.assertEqual(spec.pdus[0x03].cmd, 0x03)

    def test_explicit_cmd_still_works(self):
        spec = basic_spec(pdus={0x03: Pdu("Read", 0x03, [Field.u8("n")])})
        self.assertEqual(spec.pdus[0x03].cmd, 0x03)

    def test_fields_as_second_positional(self):
        pdu = Pdu("Read", [Field.u8("a"), Field.u16("b")])
        self.assertIsNone(pdu.cmd)
        self.assertEqual(pdu.field_keys(), ["a", "b"])

    def test_fields_sequence_normalized_to_tuple(self):
        self.assertEqual(Pdu("Read", fields=[Field.u8("a")]).fields.__class__, tuple)

    def test_fields_given_twice(self):
        with self.assertRaises(FrameRuleError) as ctx:
            Pdu("Read", [Field.u8("a")], fields=[Field.u8("b")])
        self.assertIn("两次", str(ctx.exception))

    def test_backfill_keeps_mismatch_check(self):
        with self.assertRaises(FrameRuleError) as ctx:
            basic_spec(pdus={1: Pdu("Ping", 2)})
        self.assertIn("不一致", str(ctx.exception))

    def test_backfill_reaches_pdu_lookup(self):
        spec = basic_spec(pdus={0x03: Pdu("Read", fields=[Field.u8("n")])})
        self.assertIs(spec.pdu("Read"), spec.pdus[0x03])
        self.assertIs(spec.pdu(0x03), spec.pdus[0x03])


def count_fields():
    """AA | len(2) | cmd | cnt(2) | data(len-5) | crc(2)。"""
    return [
        Field.u8("head", fixed=0xAA),
        Field.u16("len"),
        Field.u8("cmd"),
        Field.u16("cnt"),
        Field.raw("data", "{len.val}-5"),
        Field.checksum("crc", 2, group="{len}{cmd}{cnt}{data}"),
    ]


def count_spec(**kwargs):
    params = dict(
        fields=count_fields(),
        payload="data",
        length=LengthRule("len"),
        checksum=ChecksumRule("crc", sum8),
        pdus={1: Pdu("Ping", 1)},
    )
    params.update(kwargs)
    return FrameSpec(**params)


class TestAutoFieldValidation(unittest.TestCase):
    """自动填值字段：0..N 个，声明期必须校验掉所有冲突。"""

    def assert_rule_error(self, **kwargs):
        with self.assertRaises(FrameRuleError) as ctx:
            count_spec(**kwargs)
        return str(ctx.exception)

    def test_auto_key_unknown(self):
        text = self.assert_rule_error(auto=[AutoField("nope")])
        self.assertIn("不在字段里", text)

    def test_auto_not_auto_field(self):
        text = self.assert_rule_error(auto=[{"key": "cnt"}])
        self.assertIn("只接受 AutoField", text)

    def test_auto_duplicate(self):
        text = self.assert_rule_error(auto=[AutoField("cnt"), AutoField("cnt")])
        self.assertIn("重复声明", text)

    def test_auto_conflicts_with_length(self):
        text = self.assert_rule_error(auto=[AutoField("len")])
        self.assertIn("冲突", text)

    def test_auto_conflicts_with_checksum(self):
        text = self.assert_rule_error(auto=[AutoField("crc")])
        self.assertIn("冲突", text)

    def test_auto_conflicts_with_payload(self):
        text = self.assert_rule_error(auto=[AutoField("data")])
        self.assertIn("冲突", text)

    def test_auto_conflicts_with_cmd(self):
        text = self.assert_rule_error(auto=[AutoField("cmd")])
        self.assertIn("冲突", text)

    def test_auto_conflicts_with_device(self):
        text = self.assert_rule_error(auto=[AutoField("cnt")], device="cnt")
        self.assertIn("冲突", text)

    def test_auto_must_be_fixed_width(self):
        fields = count_fields() + [Field.raw("var", "{len.val}-5")]
        text = self.assert_rule_error(fields=fields, auto=[AutoField("var")])
        self.assertIn("定长", text)

    def test_counter_wrap_must_be_positive(self):
        text = self.assert_rule_error(auto=[AutoField("cnt", wrap=0)])
        self.assertIn("wrap", text)

    def test_auto_normalized_to_tuple(self):
        spec = count_spec(auto=[AutoField("cnt")])
        self.assertIsInstance(spec.auto, tuple)
        self.assertEqual(spec.auto[0].key, "cnt")

    def test_seq_enabled_appended_to_auto(self):
        spec = count_spec(seq=SeqPolicy("cnt", enabled=True, start=3))
        self.assertEqual([a.key for a in spec.auto], ["cnt"])
        self.assertEqual(spec.auto[0].start, 3)

    def test_seq_disabled_not_in_auto(self):
        spec = count_spec(seq=SeqPolicy("cnt"))
        self.assertEqual(spec.auto, ())


class TestFrameSpecQuery(unittest.TestCase):
    def setUp(self):
        self.spec = basic_spec()

    def test_cmd_key_fallback(self):
        self.assertEqual(self.spec.cmd_key, "cmd")

    def test_cmd_key_explicit(self):
        spec = basic_spec(cmd="cmd")
        self.assertEqual(spec.cmd_key, "cmd")

    def test_cmd_key_absent(self):
        fields = [Field.u8("head", fixed=0xAA), Field.u8("len"), Field.raw("data", "{len.val}")]
        spec = FrameSpec(fields=fields, payload="data", length=LengthRule("len"))
        self.assertIsNone(spec.cmd_key)

    def test_pdu_by_cmd_and_name(self):
        self.assertEqual(self.spec.pdu(1).name, "Ping")
        self.assertEqual(self.spec.pdu("Ping").cmd, 1)

    def test_pdu_unknown(self):
        with self.assertRaises(FrameRuleError) as ctx:
            self.spec.pdu("Nope")
        self.assertIn("找不到报文", str(ctx.exception))

    def test_field_lookup(self):
        self.assertEqual(self.spec.field("len").length, 2)
        with self.assertRaises(FrameRuleError):
            self.spec.field("nope")

    def test_field_keys(self):
        self.assertEqual(
            self.spec.field_keys(), ["head", "len", "cmd", "data", "crc"]
        )

    def test_group_keys_from_group(self):
        self.assertEqual(self.spec.group_keys("crc"), ("len", "cmd", "data"))

    def test_group_keys_fallback_to_preceding(self):
        fields = [
            Field.u8("head", fixed=0xAA),
            Field.u8("len"),
            Field.raw("data", "{len.val}"),
            Field.checksum("sum", 1),
        ]
        spec = FrameSpec(
            fields=fields,
            payload="data",
            length=LengthRule("len"),
            checksum=ChecksumRule("sum", sum8),
        )
        self.assertEqual(spec.group_keys("sum"), ("head", "len", "data"))


class TestFrameSpecDiff(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(basic_spec().diff(basic_spec()), [])

    def test_framing(self):
        other = basic_spec(framing=DelimiterFraming(end=0x7E))
        self.assertTrue(any("framing" in line for line in basic_spec().diff(other)))

    def test_payload(self):
        other = basic_spec(payload="cmd")
        self.assertTrue(any("payload" in line for line in basic_spec().diff(other)))

    def test_field_sequence(self):
        fields = basic_fields()[:3] + [Field.raw("data", "{len.val}-3")]
        other = basic_spec(fields=fields, checksum=None, pdus={})
        changes = basic_spec().diff(other)
        self.assertTrue(any("字段序列" in line for line in changes))

    def test_single_field_changed(self):
        fields = basic_fields()
        fields[2] = Field.u16("cmd")
        # cmd 变宽会让 data 表达式与长度不一致，这里只看 diff 报告
        other = basic_spec(fields=fields)
        changes = basic_spec().diff(other)
        self.assertTrue(any("字段 'cmd'" in line for line in changes))

    def test_length_key(self):
        other = basic_spec(length=None)
        self.assertTrue(any("length.key" in line for line in basic_spec().diff(other)))

    def test_length_span(self):
        other = basic_spec(length=LengthRule("len", span=("cmd", "crc")))
        self.assertTrue(any("length.span" in line for line in basic_spec().diff(other)))

    def test_checksum_key(self):
        other = basic_spec(checksum=None)
        self.assertTrue(any("checksum" in line for line in basic_spec().diff(other)))

    def test_checksum_impl(self):
        other = basic_spec(checksum=ChecksumRule("crc", xor8))
        self.assertTrue(
            any("impl" in line for line in basic_spec().diff(other))
        )


class TestSpecToCodec(unittest.TestCase):
    def test_parse_what_builder_writes(self):
        from kkprotocol import Protocol

        spec = basic_spec()
        wire = Protocol(spec).build("Ping", data=b"abc")
        frame = spec.to_codec().feed(wire)[0]
        self.assertEqual(frame.value("cmd"), 1)
        self.assertEqual(frame.value("data"), b"abc")
        self.assertEqual(frame.value("len"), 6)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
