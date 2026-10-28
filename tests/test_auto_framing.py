# -*- coding: utf-8 -*-
"""自适应定界：长度优先、分隔符兜底、锁定与重置。"""

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

LINE_SPEC = DelimiterFraming(end=0x0A)


def length_rules():
    return [Field.u8("stx", fixed=0x02), Field.u8("n"), Field.raw("body", "{n.val}")]


def rest_rules():
    return [Field.u8("stx", fixed=0x02), Field.rest("body")]


class TestAutoDetection(unittest.TestCase):
    def test_picks_length_when_length_parse_works(self):
        codec = make_codec(
            length_rules(), framing=AUTO_FRAMING, delimiter=DelimiterFraming(end=0x04)
        )
        frames = codec.feed(b"\x02\x02hi")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("body"), b"hi")
        self.assertEqual(frames[0].framing, LENGTH_FRAMING)
        self.assertEqual(codec.framing_mode, LENGTH_FRAMING)

    def test_falls_back_to_delimiter_for_rest_field(self):
        codec = make_codec(rest_rules(), framing=AUTO_FRAMING, delimiter=LINE_SPEC)
        frames = codec.feed(b"\x02hello\n")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("body"), b"hello")
        self.assertEqual(frames[0].framing, DELIMITER_FRAMING)
        self.assertEqual(codec.framing_mode, DELIMITER_FRAMING)

    def test_waits_when_both_incomplete(self):
        codec = make_codec(rest_rules(), framing=AUTO_FRAMING, delimiter=LINE_SPEC)
        self.assertEqual(codec.feed(b"\x02hel"), [])
        self.assertIsNone(codec.framing_mode)
        frames = codec.feed(b"lo\n")
        self.assertEqual([f.value("body") for f in frames], [b"hello"])
        self.assertEqual(codec.framing_mode, DELIMITER_FRAMING)

    def test_reset_framing_leads_to_redetection(self):
        codec = make_codec(rest_rules(), framing=AUTO_FRAMING, delimiter=LINE_SPEC)
        codec.feed(b"\x02a\n")
        self.assertEqual(codec.framing_mode, DELIMITER_FRAMING)
        codec.reset_framing()
        self.assertIsNone(codec.framing_mode)
        codec.feed(b"\x02b\n")
        self.assertEqual(codec.framing_mode, DELIMITER_FRAMING)

    def test_lock_disabled_keeps_probing(self):
        codec = make_codec(
            rest_rules(),
            framing=AUTO_FRAMING,
            delimiter=LINE_SPEC,
            lock_framing=False,
        )
        frames = codec.feed(b"\x02a\n\x02b\n")
        self.assertEqual([f.value("body") for f in frames], [b"a", b"b"])
        self.assertIsNone(codec.framing_mode)

    def test_auto_requires_delimiter_spec(self):
        codec = make_codec(length_rules(), framing=AUTO_FRAMING)
        with self.assertRaises(FrameRuleError):
            codec.compile()

    def test_delimiter_string_requires_spec(self):
        codec = make_codec(length_rules(), framing=DELIMITER_FRAMING)
        with self.assertRaises(FrameRuleError):
            codec.compile()

    def test_explicit_delimiter_string_with_spec(self):
        codec = make_codec(
            rest_rules(), framing=DELIMITER_FRAMING, delimiter=LINE_SPEC
        )
        frames = codec.feed(b"\x02ok\n")
        self.assertEqual(frames[0].value("body"), b"ok")
        self.assertEqual(codec.framing_mode, DELIMITER_FRAMING)

    def test_unknown_framing_value(self):
        codec = make_codec(length_rules(), framing="bogus")
        with self.assertRaises(FrameRuleError):
            codec.compile()


if __name__ == "__main__":
    unittest.main(verbosity=2)
