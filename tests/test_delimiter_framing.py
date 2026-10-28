# -*- coding: utf-8 -*-
"""分隔符定界（转义/透明传输）：切帧、反转义、长度字段降级为校验项。"""

from __future__ import annotations

import unittest

from kkprotocol import (
    DELIMITER_FRAMING,
    DelimiterFraming,
    Field,
    PppFrameCodec,
    build_ppp_frame,
    sum8,
)

from tests.helpers import make_codec

FLAG = 0x7E


class TestPppFraming(unittest.TestCase):
    def test_single_frame(self):
        codec = PppFrameCodec()
        raw = build_ppp_frame(payload=b"ping")
        frames = codec.feed(raw)
        self.assertEqual(len(frames), 1)
        frame = frames[0]
        self.assertEqual(frame.framing, DELIMITER_FRAMING)
        self.assertEqual(frame.value("addr"), 0xFF)
        self.assertEqual(frame.value("ctrl"), 0x03)
        self.assertEqual(frame.value("data"), b"ping")
        self.assertEqual(frame.wire, raw)
        self.assertEqual(frame.raw, raw[1:-1])
        self.assertEqual(codec.framing_mode, DELIMITER_FRAMING)

    def test_payload_with_delimiters_needs_escaping(self):
        payload = b"\x7e\x7d hello \x7e\x7d"
        raw = build_ppp_frame(payload=payload)
        self.assertIn(b"\x7d\x5e", raw)
        self.assertIn(b"\x7d\x5d", raw)
        # 线上只有一个帧头和一个帧尾
        self.assertEqual(raw.count(b"\x7e"), 2)
        frames = PppFrameCodec().feed(raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), payload)

    def test_sticky_frames_with_shared_flag(self):
        codec = PppFrameCodec()
        first = build_ppp_frame(payload=b"one")
        second = build_ppp_frame(payload=b"two")
        third = build_ppp_frame(payload=b"three")
        # PPP 常见写法：帧之间共享一个 0x7E
        stream = first + second[1:] + third[1:]
        frames = codec.feed(stream)
        self.assertEqual([f.value("data") for f in frames], [b"one", b"two", b"three"])
        self.assertEqual(codec.pending_bytes, b"")

    def test_doubled_flags(self):
        codec = PppFrameCodec()
        stream = build_ppp_frame(payload=b"a") + b"\x7e" + build_ppp_frame(payload=b"b")
        frames = codec.feed(stream)
        self.assertEqual([f.value("data") for f in frames], [b"a", b"b"])

    def test_byte_by_byte(self):
        codec = PppFrameCodec()
        raw = build_ppp_frame(payload=b"escaping \x7e test")
        frames = []
        for index in range(len(raw) - 1):
            frames.extend(codec.feed(raw[index:index + 1]))
            self.assertEqual(frames, [])
        frames.extend(codec.feed(raw[-1:]))
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"escaping \x7e test")

    def test_garbage_before_flag(self):
        codec = PppFrameCodec()
        raw = build_ppp_frame(payload=b"ok")
        frames = codec.feed(b"\x11\x22\x33" + raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"ok")

    def test_bad_fcs_resync_past_frame(self):
        codec = PppFrameCodec()
        good = build_ppp_frame(payload=b"good")
        frames = codec.feed(build_ppp_frame(payload=b"bad", bad_fcs=True) + good)
        self.assertEqual([f.value("data") for f in frames], [b"good"])
        self.assertEqual(codec.stats.crc_errors, 1)
        self.assertEqual(codec.pending_bytes, b"")

    def test_declared_length_mismatch_is_rejected(self):
        codec = PppFrameCodec()
        # 声明长度 5，实际净荷只有 3 字节：定界符已给出真实边界 → 判为不合法
        frames = codec.feed(build_ppp_frame(payload=b"abc", declared_length=5))
        self.assertEqual(frames, [])
        self.assertGreaterEqual(codec.stats.length_mismatches, 1)
        self.assertEqual(codec.pending_bytes, b"")

    def test_declared_length_below_actual_is_caught_by_checksum(self):
        # 长度声明偏小 → 规则只吃到部分净荷 → 校验覆盖的字节也少了 → CRC 先失败
        codec = PppFrameCodec()
        frames = codec.feed(build_ppp_frame(payload=b"abc", declared_length=2))
        self.assertEqual(frames, [])
        self.assertGreaterEqual(codec.stats.crc_errors, 1)

    def test_unclosed_frame_over_limit_is_dropped(self):
        codec = PppFrameCodec()
        codec.max_frame_size = 16
        self.assertEqual(codec.feed(b"\x7e" + b"x" * 40), [])
        self.assertGreater(codec.stats.resyncs, 0)
        self.assertEqual(codec.pending_bytes, b"")
        # 之后仍能恢复
        self.assertEqual(len(codec.feed(build_ppp_frame(payload=b"ok"))), 1)

    def test_complete_frame_over_limit_is_dropped(self):
        codec = PppFrameCodec()
        codec.max_frame_size = 8
        self.assertEqual(codec.feed(build_ppp_frame(payload=b"1234567890")), [])
        self.assertGreater(codec.stats.resyncs, 0)

    def test_partial_then_complete(self):
        codec = PppFrameCodec()
        raw = build_ppp_frame(payload=b"split me")
        self.assertEqual(codec.feed(raw[:5]), [])
        self.assertTrue(codec.pending_bytes)
        frames = codec.feed(raw[5:])
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"split me")


class TestDelimiterVariants(unittest.TestCase):
    def test_line_protocol_with_rest_field(self):
        """行协议：\\n 结尾，净荷取到帧尾，长度字段完全不存在。"""
        rules = [Field.u8("stx", fixed=0x02), Field.rest("body")]
        codec = make_codec(
            rules, framing=DelimiterFraming(end=0x0A, escape=0x1B, escape_xor=0x20)
        )
        frames = codec.feed(b"\x02hello\n\x02wor\x1b\x2ald\n")
        self.assertEqual([f.value("body") for f in frames], [b"hello", b"wor\nld"])

    def test_line_protocol_without_escape_splits_payload(self):
        """不配置转义时，净荷里出现定界符就会被切开 —— 这正是需要转义的原因。"""
        rules = [Field.rest("line")]
        codec = make_codec(rules, framing=DelimiterFraming(end=0x0A))
        frames = codec.feed(b"line1\nline2\n")
        self.assertEqual([f.value("line") for f in frames], [b"line1", b"line2"])

    def test_distinct_start_and_end(self):
        # 配置了 start 定界符后，规则只描述两个定界符之间的内容
        rules = [Field.rest("body")]
        codec = make_codec(rules, framing=DelimiterFraming(end=0x04, start=0x02))
        frames = codec.feed(b"\x00\x01\x02abc\x04")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("body"), b"abc")
        self.assertEqual(frames[0].wire, b"\x02abc\x04")

    def test_start_scan_waits_for_header(self):
        rules = [Field.rest("body")]
        codec = make_codec(rules, framing=DelimiterFraming(end=0x04, start=0x02))
        # 垃圾里不能含帧头字节，否则会被当成帧起点（见下方说明）
        self.assertEqual(codec.feed(b"\x01\x03"), [])
        self.assertEqual(codec.pending_bytes, b"\x01\x03")
        frames = codec.feed(b"\x02ok\x04")
        self.assertEqual([f.value("body") for f in frames], [b"ok"])

    def test_no_start_delimiter_takes_prefix_as_frame(self):
        rules = [Field.rest("line")]
        codec = make_codec(rules, framing=DelimiterFraming(end=0x0A))
        frames = codec.feed(b"garbage\nOK\n")
        self.assertEqual([f.value("line") for f in frames], [b"garbage", b"OK"])

    def test_empty_frame(self):
        rules = [Field.rest("line")]
        codec = make_codec(rules, framing=DelimiterFraming(end=0x0A))
        frames = codec.feed(b"a\n\nb\n")
        self.assertEqual([f.value("line") for f in frames], [b"a", b"", b"b"])

    def test_checksum_computed_over_unescaped_bytes(self):
        """校验按反转义后的字节算（PPP 约定），转义不影响校验结果。"""

        def crc(data):
            return sum8(data)

        rules = [
            Field.u8("stx", fixed=0x02),
            Field.rest("body"),
        ]
        codec = make_codec(
            rules,
            crc=crc,
            framing=DelimiterFraming(end=0x0A, escape=0x1B, escape_xor=0x20),
        )
        # body = 0x0A 单字节，经转义成 1B 2A
        frames = codec.feed(b"\x02\x1b\x2a\n")
        self.assertEqual(frames[0].value("body"), b"\x0a")


if __name__ == "__main__":
    unittest.main(verbosity=2)
