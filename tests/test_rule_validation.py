# -*- coding: utf-8 -*-
"""规则与配置校验：所有写错的地方都必须在编译期抛 FrameRuleError。"""

from __future__ import annotations

import unittest

from kkprotocol import (
    AUTO_FRAMING,
    DELIMITER_FRAMING,
    LENGTH_FRAMING,
    DelimiterFraming,
    Field,
    FrameRuleError,
)

from tests.helpers import make_codec


class RuleErrorMixin(unittest.TestCase):
    def assert_rule_error(self, rules, **attrs):
        codec = make_codec(rules, **attrs)
        with self.assertRaises(FrameRuleError):
            codec.compile()


class TestFieldRules(RuleErrorMixin):
    def test_empty_rules(self):
        self.assert_rule_error([])

    def test_duplicate_key(self):
        self.assert_rule_error([Field.u8("a"), Field.u8("a")])

    def test_missing_key(self):
        self.assert_rule_error([Field(key=None, length=1, fmt="B")])

    def test_empty_key(self):
        self.assert_rule_error([Field(key="", length=1, fmt="B")])

    def test_forward_reference(self):
        self.assert_rule_error([Field.raw("a", "{b.val}"), Field.u8("b")])

    def test_unknown_reference(self):
        self.assert_rule_error([Field.u8("a"), Field.raw("b", "{zzz.val}")])

    def test_unsupported_expression_attribute(self):
        self.assert_rule_error([Field.u8("a"), Field.raw("b", "{a.foo}")])

    def test_expression_syntax_error(self):
        self.assert_rule_error([Field.u8("n"), Field.raw("a", "{n.val}-")])

    def test_expression_true_division_rejected(self):
        self.assert_rule_error([Field.u8("n"), Field.raw("a", "{n.val}/2")])

    def test_expression_arbitrary_code_rejected(self):
        self.assert_rule_error(
            [Field.u8("n"), Field.raw("a", "__import__('os').system('echo hi')")]
        )

    def test_expression_constant_division_by_zero(self):
        self.assert_rule_error([Field.u8("n"), Field.raw("a", "{n.val}-1//0")])

    def test_fmt_size_mismatch(self):
        self.assert_rule_error([Field(key="a", length=2, fmt="B")])

    def test_fmt_multiple_values(self):
        self.assert_rule_error([Field(key="a", length=4, fmt="2H")])

    def test_zero_length_with_fmt(self):
        self.assert_rule_error([Field(key="a", length=0, fmt="B")])

    def test_bad_fmt_string(self):
        self.assert_rule_error([Field(key="a", length=1, fmt="Q")])

    def test_unknown_fmt_char(self):
        self.assert_rule_error([Field(key="a", length=1, fmt="Z")])

    def test_zero_size_fmt(self):
        self.assert_rule_error([Field(key="a", length=0, fmt="0s")])

    def test_non_str_fmt(self):
        self.assert_rule_error([Field(key="a", length=1, fmt=1)])

    def test_negative_length(self):
        self.assert_rule_error([Field(key="a", length=-1)])

    def test_bool_length(self):
        self.assert_rule_error([Field(key="a", length=True)])

    def test_empty_string_length(self):
        self.assert_rule_error([Field(key="a", length="")])

    def test_unsupported_length_type(self):
        self.assert_rule_error([Field(key="a", length=1.5)])

    def test_rule_must_be_field_or_dict(self):
        self.assert_rule_error(["not-a-rule"])

    def test_group_unknown_reference(self):
        self.assert_rule_error([Field.u8("a"), Field.checksum("c", 1, group="{zzz}", fmt="B")])

    def test_group_without_reference(self):
        self.assert_rule_error([Field.u8("a"), Field.checksum("c", 1, group="abc", fmt="B")])

    def test_group_empty_string(self):
        self.assert_rule_error([Field.u8("a"), Field.checksum("c", 1, group="", fmt="B")])

    def test_checksum_field_first_without_group(self):
        self.assert_rule_error([Field.checksum("c", 1, group=None, fmt="B")])

    def test_rest_field_in_length_framing(self):
        self.assert_rule_error([Field.u8("a"), Field.rest("b")])


class TestFramingConfig(RuleErrorMixin):
    def test_unknown_framing(self):
        self.assert_rule_error([Field.u8("a")], framing="nonsense")

    def test_auto_without_delimiter(self):
        self.assert_rule_error([Field.u8("a")], framing=AUTO_FRAMING)

    def test_delimiter_mode_without_spec(self):
        self.assert_rule_error([Field.u8("a")], framing=DELIMITER_FRAMING)

    def test_bad_on_crc_error(self):
        self.assert_rule_error([Field.u8("a")], on_crc_error="ignore")

    def test_bad_sync_value(self):
        self.assert_rule_error([Field.u8("a")], sync=300)

    def test_delimiter_spec_instance_sets_mode(self):
        codec = make_codec(
            [Field.u8("a", fixed=0x02), Field.rest("b")],
            framing=DelimiterFraming(end=0x0A),
        )
        codec.compile()
        self.assertEqual(codec.framing_mode, DELIMITER_FRAMING)

    def test_length_mode_is_default(self):
        codec = make_codec([Field.u8("a")])
        codec.compile()
        self.assertEqual(codec.framing_mode, LENGTH_FRAMING)

    def test_compile_is_idempotent(self):
        codec = make_codec([Field.u8("a")])
        codec.compile()
        codec.compile()
        self.assertEqual(codec.framing_mode, LENGTH_FRAMING)

    def test_empty_rules_dict_style(self):
        self.assert_rule_error([])


class TestDeviceFieldConfig(RuleErrorMixin):
    def test_device_field_missing(self):
        self.assert_rule_error([Field.u8("a")], device_field="nope")

    def test_device_field_with_fixed(self):
        self.assert_rule_error([Field.u8("dev", fixed=1)], device_field="dev")


if __name__ == "__main__":
    unittest.main(verbosity=2)
