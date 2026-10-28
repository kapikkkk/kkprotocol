# -*- coding: utf-8 -*-
"""长度定界（framing="length"）：黏包、半包、脏数据重同步、缓冲保护。"""

from __future__ import annotations

import unittest

from kkprotocol import DELIMITER_FRAMING, LENGTH_FRAMING, DeviceFrameCodec
from kkprotocol.example_device import DEVICE_FIELDS, HEADER, build_device_frame

from tests.helpers import make_codec, sum8


class TestBasic(unittest.TestCase):
    def test_single_frame(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame(payload=b"hello")
        frames = codec.feed(raw)

        self.assertEqual(len(frames), 1)
        frame = frames[0]
        self.assertEqual(frame.raw, raw)
        self.assertEqual(frame.wire, raw)
        self.assertEqual(frame.framing, LENGTH_FRAMING)
        self.assertEqual(len(frame), len(raw))
        self.assertEqual(frame.value("header"), HEADER)
        self.assertEqual(frame.value("ver"), 1)
        self.assertEqual(frame.value("cmd"), 0x03)
        self.assertEqual(frame.value("ser"), 1)
        self.assertEqual(frame["dev_id"].val, b"\x00\x00\x00\x01")
        self.assertEqual(frame["dev_id"].length, 4)
        self.assertEqual(frame.value("data"), b"hello")
        self.assertEqual(codec.pending_bytes, b"")
        self.assertEqual(codec.stats.frames, 1)
        self.assertEqual(codec.framing_mode, LENGTH_FRAMING)

    def test_as_dict_contains_and_defaults(self):
        frame = DeviceFrameCodec().feed(build_device_frame())[0]
        flat = frame.as_dict()
        self.assertEqual(flat["header"], HEADER)
        self.assertEqual(flat["data"], b"\x01\x02")
        self.assertIn("crc", frame)
        self.assertEqual(set(flat), {f.key for f in DEVICE_FIELDS})
        self.assertIsNone(frame.value("nope"))
        self.assertEqual(frame.value("nope", -1), -1)
        self.assertEqual(frame.keys(), frame.fields.keys())

    def test_zero_length_payload(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame(payload=b"")
        frames = codec.feed(raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["data"].raw, b"")
        self.assertEqual(frames[0].raw, raw)

    def test_empty_memoryview_and_bytearray_input(self):
        codec = DeviceFrameCodec()
        self.assertEqual(codec.feed(b""), [])
        raw = build_device_frame()
        self.assertEqual(len(codec.feed(memoryview(raw))), 1)
        self.assertEqual(len(codec.feed(bytearray(build_device_frame()))), 1)

    def test_type_error_on_str(self):
        with self.assertRaises(TypeError):
            DeviceFrameCodec().feed("not-bytes")  # type: ignore[arg-type]

    def test_filter_alias(self):
        self.assertEqual(len(DeviceFrameCodec().filter(build_device_frame())), 1)


class TestStickyAndSplit(unittest.TestCase):
    def test_two_frames_in_one_chunk(self):
        codec = DeviceFrameCodec()
        r1 = build_device_frame(cmd=1, payload=b"aa")
        r2 = build_device_frame(cmd=2, payload=b"bb")
        frames = codec.feed(r1 + r2)
        self.assertEqual([f.value("cmd") for f in frames], [1, 2])
        self.assertEqual(frames[1].value("data"), b"bb")
        self.assertEqual(frames[1].wire, r2)

    def test_three_frames_and_partial_tail(self):
        codec = DeviceFrameCodec()
        r1 = build_device_frame(cmd=1)
        r2 = build_device_frame(cmd=2, payload=b"x" * 5)
        r3 = build_device_frame(cmd=3)
        tail_full = build_device_frame(cmd=4, payload=b"tail")
        tail = tail_full[:7]

        frames = codec.feed(r1 + r2 + r3 + tail)
        self.assertEqual([f.value("cmd") for f in frames], [1, 2, 3])
        self.assertEqual(codec.pending_bytes, tail)

        frames = codec.feed(tail_full[7:])
        self.assertEqual([f.value("cmd") for f in frames], [4])
        self.assertEqual(codec.pending_bytes, b"")

    def test_byte_by_byte_feed(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame(payload=b"0123456789")
        frames = []
        for index in range(len(raw) - 1):
            frames.extend(codec.feed(raw[index:index + 1]))
            self.assertEqual(frames, [])
        frames.extend(codec.feed(raw[-1:]))
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"0123456789")

    def test_reset_drops_pending(self):
        codec = DeviceFrameCodec()
        codec.feed(build_device_frame()[:5])
        self.assertTrue(codec.pending_bytes)
        codec.reset()
        self.assertEqual(codec.pending_bytes, b"")
        self.assertEqual(len(codec.feed(build_device_frame())), 1)


class TestResync(unittest.TestCase):
    def test_garbage_prefix(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame()
        frames = codec.feed(b"\x00\xff\x13" + raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].raw, raw)
        self.assertGreaterEqual(codec.stats.resyncs, 1)
        self.assertGreaterEqual(codec.stats.dropped_bytes, 3)

    def test_fake_header_then_real_frame(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame(cmd=9)
        frames = codec.feed(b"\x55\x02\x01" + raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("cmd"), 9)

    def test_mid_frame_fixed_mismatch(self):
        codec = make_codec(
            [
                {"key": "start", "len": 1, "fmt": "B", "fixed": 0x7E},
                {"key": "type", "len": 1, "fmt": "B", "fixed": 0x01},
                {"key": "n", "len": 1, "fmt": "B"},
                {"key": "body", "len": "{n.val}", "fmt": ""},
            ],
            crc=None,
        )
        frames = codec.feed(b"\x7E\x02" + b"\x7E\x01\x03xyz")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("body"), b"xyz")

    def test_partial_after_garbage(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame(payload=b"abcdef")
        self.assertEqual(codec.feed(b"\xff\xfe" + raw[:6]), [])
        frames = codec.feed(raw[6:])
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"abcdef")

    def test_no_sync_anchor_still_recovers(self):
        rules = [
            {"key": "a", "len": 2, "fmt": "!H", "fixed": 0x1234},
            {"key": "b", "len": 2, "fmt": "!H"},
        ]
        codec = make_codec(rules, sync=b"")
        raw = b"\x12\x34\x01\x02"
        frames = codec.feed(b"\x00\x00" + raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("b"), 0x0102)

    def test_handle_invalid_hook_is_called(self):
        class Hook(DeviceFrameCodec):
            def __init__(self):
                super().__init__()
                self.reasons = []

            def _handle_invalid(self, exc, pos):
                self.reasons.append(exc.reason)

        hook = Hook()
        hook.feed(b"\x00\x01" + build_device_frame())
        self.assertTrue(hook.reasons)
        self.assertIn("常量不匹配", hook.reasons[0])


class TestLimits(unittest.TestCase):
    def test_max_frame_size(self):
        codec = DeviceFrameCodec()
        codec.max_frame_size = 8
        frames = codec.feed(build_device_frame(payload=b"x" * 20))
        self.assertEqual(frames, [])
        self.assertGreater(codec.stats.resyncs, 0)
        self.assertEqual(codec.pending_bytes, b"")

    def test_buffer_overflow_drops_oldest(self):
        codec = DeviceFrameCodec()
        codec.max_buffer = 16
        raw = build_device_frame(payload=b"x" * 32)
        self.assertEqual(codec.feed(raw[:30]), [])
        self.assertEqual(codec.stats.overflow_drops, 1)
        self.assertEqual(len(codec.pending_bytes), 16)

    def test_huge_garbage_does_not_grow_buffer(self):
        codec = DeviceFrameCodec()
        codec.feed(b"\x00" * 100000)
        self.assertEqual(codec.pending_bytes, b"")
        self.assertEqual(codec.stats.frames, 0)

    def test_stats_bytes_in(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame()
        codec.feed(raw)
        codec.feed(raw)
        self.assertEqual(codec.stats.bytes_in, len(raw) * 2)


class TestRulesNotMutated(unittest.TestCase):
    def test_parsing_does_not_touch_rule_objects(self):
        snapshot = list(DEVICE_FIELDS)
        codec = DeviceFrameCodec()
        codec.feed(build_device_frame())
        self.assertEqual(DEVICE_FIELDS, snapshot)
        # 第二条连接复用同一份规则也必须正常
        self.assertEqual(len(DeviceFrameCodec().feed(build_device_frame())), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
