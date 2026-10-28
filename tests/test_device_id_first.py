# -*- coding: utf-8 -*-
"""帧开头就是设备号、且设备号一开始未知的场景。

与 test_device_id.py 的区别：设备号是**第一个字段**，前面没有固定帧头，
因此既不能靠 fixed 推导重同步锚点，也无法在解析前排除任何字节。
"""

from __future__ import annotations

import unittest

from kkprotocol import Field, FrameRuleError, crc16_modbus

from tests.helpers import make_codec

DEV1 = b"\x00\x00\x00\x01"
DEV2 = b"\x00\x00\x00\x02"


def head_dev_rules():
    """dev_id 在最前面（4 字节，未知），后面是命令/长度/净荷/CRC。"""
    return [
        Field.raw("dev_id", 4),
        Field.u8("cmd"),
        Field.u8("n"),
        Field.raw("body", "{n.val}"),
        Field.checksum("crc", 2, group="{dev_id}{cmd}{n}{body}"),
    ]


def build_head_dev(dev: bytes = DEV1, cmd: int = 0x01, body: bytes = b"x") -> bytes:
    body_bytes = dev + bytes([cmd, len(body)]) + body
    return body_bytes + crc16_modbus(body_bytes).to_bytes(2, "big")


def head_dev_codec(**attrs):
    return make_codec(head_dev_rules(), crc=crc16_modbus, device_field="dev_id", **attrs)


class TestUnknownDeviceAtFrameHead(unittest.TestCase):
    def test_first_frame_learns_device_at_offset_zero(self):
        codec = head_dev_codec()
        self.assertIsNone(codec.device_id)
        frames = codec.feed(build_head_dev(DEV1))
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].device_id, DEV1)
        self.assertTrue(frames[0].learned_device)
        self.assertEqual(codec.device_id, DEV1)

    def test_learned_device_becomes_strict_for_later_frames(self):
        codec = head_dev_codec()
        codec.feed(build_head_dev(DEV1))
        same = codec.feed(build_head_dev(DEV1))[0]
        self.assertFalse(same.device_mismatch)
        other = codec.feed(build_head_dev(DEV2))[0]
        self.assertTrue(other.device_mismatch)
        self.assertEqual(other.device_id, DEV2)

    def test_no_fixed_header_means_no_sync_anchor(self):
        """首字段是未知设备号 → 推导不出锚点，只能逐字节重同步（性能特征）。"""
        codec = head_dev_codec()
        codec.compile()
        self.assertEqual(codec._sync, b"")

    def test_garbage_prefix_still_parses(self):
        codec = head_dev_codec()
        raw = build_head_dev(DEV1, body=b"payload")
        frames = codec.feed(b"\xde\xad\xbe\xef" + raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].device_id, DEV1)
        self.assertEqual(frames[0].value("body"), b"payload")
        self.assertGreaterEqual(codec.stats.resyncs, 1)

    def test_garbage_that_looks_like_a_device_id_is_rejected_by_crc(self):
        codec = head_dev_codec()
        raw = build_head_dev(DEV2, body=b"ok")
        # 前面 4 字节刚好是另一个"设备号"，后续字段全被误读，只能靠 CRC 挡掉
        frames = codec.feed(DEV1 + raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].device_id, DEV2)
        self.assertGreaterEqual(codec.stats.crc_errors, 1)

    def test_start_mid_frame_cannot_be_detected_before_learning(self):
        """设备号未知时从帧中间接入：没有任何内容可依，假长度会让它继续等。"""
        codec = head_dev_codec()
        first = build_head_dev(DEV1, body=b"aaaa")
        second = build_head_dev(DEV2, body=b"bbbb")
        self.assertEqual(codec.feed(first[3:] + second), [])
        self.assertEqual(codec.pending_bytes, first[3:] + second)

    def test_max_frame_size_bounds_the_wait_on_fake_length(self):
        """假长度声称超过 max_frame_size → 立刻判死，不必等字节凑够（自愈的关键旋钮）。"""
        codec = head_dev_codec(max_frame_size=16)  # 真实帧最大 12 字节
        first = build_head_dev(DEV1, body=b"aaaa")
        second = build_head_dev(DEV2, body=b"bbbb")
        frames = codec.feed(first[3:] + second)
        self.assertEqual([f.value("body") for f in frames], [b"bbbb"])
        self.assertGreaterEqual(codec.stats.length_mismatches + codec.stats.crc_errors, 1)

    def test_idle_gap_drop_recovers_from_mid_frame(self):
        """连接空闲 → 丢弃半包 → 下一帧立刻正常（Modbus RTU 的 T3.5 思路）。"""
        codec = head_dev_codec()
        first = build_head_dev(DEV1, body=b"aaaa")
        second = build_head_dev(DEV2, body=b"bbbb")
        self.assertEqual(codec.feed(first[3:]), [])
        self.assertEqual(codec.drop_pending(), len(first) - 3)
        self.assertEqual(codec.drop_pending(), 0)
        frames = codec.feed(second)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("body"), b"bbbb")
        self.assertEqual(codec.device_id, DEV2)

    def test_partial_frame_waits(self):
        codec = head_dev_codec()
        raw = build_head_dev(DEV1, body=b"wait")
        self.assertEqual(codec.feed(raw[:2]), [])
        self.assertEqual(codec.pending_bytes, raw[:2])
        frames = codec.feed(raw[2:])
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("body"), b"wait")

    def test_sticky_frames_with_unknown_device(self):
        codec = head_dev_codec()
        stream = b"".join(build_head_dev(DEV1, cmd=index) for index in range(4))
        frames = codec.feed(stream)
        self.assertEqual([f.value("cmd") for f in frames], [0, 1, 2, 3])
        self.assertTrue(frames[0].learned_device)
        self.assertFalse(any(f.device_mismatch for f in frames))

    def test_byte_by_byte(self):
        codec = head_dev_codec()
        raw = build_head_dev(DEV1, body=b"one-by-one")
        frames = []
        for index in range(len(raw) - 1):
            frames.extend(codec.feed(raw[index:index + 1]))
            self.assertEqual(frames, [])
        frames.extend(codec.feed(raw[-1:]))
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("body"), b"one-by-one")


class TestExternalDeviceBeforeFirstFrame(unittest.TestCase):
    def test_provider_supplies_unknown_device_at_head(self):
        codec = head_dev_codec(device_id_provider=lambda: DEV1)
        frames = codec.feed(build_head_dev(DEV1))
        self.assertEqual(len(frames), 1)
        self.assertFalse(frames[0].learned_device)
        self.assertFalse(frames[0].device_mismatch)

    def test_provider_knows_device_then_other_device_is_flagged(self):
        codec = head_dev_codec(device_id_provider=lambda: DEV1)
        frames = codec.feed(build_head_dev(DEV2))
        self.assertEqual(len(frames), 1)
        self.assertTrue(frames[0].device_mismatch)

    def test_explicit_bind_before_first_frame(self):
        codec = head_dev_codec(auto_learn_device=False)
        codec.bind_device(DEV2)
        frames = codec.feed(build_head_dev(DEV2))
        self.assertFalse(frames[0].device_mismatch)
        self.assertFalse(frames[0].learned_device)


class TestStrictMode(unittest.TestCase):
    def test_enforce_rejects_other_device(self):
        codec = head_dev_codec(enforce_device_id=True)
        codec.bind_device(DEV1)
        self.assertEqual(codec.feed(build_head_dev(DEV2)), [])
        self.assertGreaterEqual(codec.stats.resyncs, 1)
        frames = codec.feed(build_head_dev(DEV1))
        self.assertEqual(len(frames), 1)

    def test_registration_packet_gate(self):
        """只让注册包（cmd=0x00）参与学习，其他帧丢弃且不影响设备号。"""
        codec = head_dev_codec()
        codec.on_frame = lambda frame: frame.value("cmd") == 0x00
        self.assertEqual(codec.feed(build_head_dev(DEV1, cmd=0x10)), [])
        self.assertIsNone(codec.device_id)
        frames = codec.feed(build_head_dev(DEV1, cmd=0x00))
        self.assertEqual(len(frames), 1)
        self.assertTrue(frames[0].learned_device)
        self.assertEqual(codec.device_id, DEV1)


class TestLearnedDeviceAsSyncAnchor(unittest.TestCase):
    """设备号只在首帧未知，学到后固定 → 它天然是重同步锚点。"""

    def test_anchor_appears_after_learning(self):
        codec = head_dev_codec()
        codec.compile()
        self.assertEqual(codec._sync, b"")
        codec.feed(build_head_dev(DEV1))
        self.assertEqual(codec._sync, DEV1)

    def test_anchor_makes_resync_a_single_jump(self):
        codec = head_dev_codec()
        codec.feed(build_head_dev(DEV1, body=b"warm"))
        codec.stats.resyncs = 0
        frames = codec.feed(
            b"\xde\xad" + build_head_dev(DEV1, body=b"x") + build_head_dev(DEV1, body=b"y")
        )
        self.assertEqual([f.value("body") for f in frames], [b"x", b"y"])
        self.assertEqual(codec.stats.resyncs, 1)

    def test_anchor_learned_from_bound_int_device(self):
        codec = make_codec(
            [Field.u32("dev"), Field.u8("cmd"), Field.checksum("crc", 2, group="{dev}{cmd}")],
            crc=crc16_modbus,
            device_field="dev",
        )
        codec.bind_device(0x00000002)
        codec.compile()
        self.assertEqual(codec._sync, b"\x00\x00\x00\x02")

    def test_forget_device_restores_compile_time_anchor(self):
        codec = head_dev_codec()
        codec.feed(build_head_dev(DEV1))
        self.assertEqual(codec._sync, DEV1)
        codec.forget_device()
        self.assertEqual(codec._sync, b"")
        # 解绑后可以重新学习另一台设备
        codec.feed(build_head_dev(DEV2))
        self.assertEqual(codec.device_id, DEV2)
        self.assertEqual(codec._sync, DEV2)

    def test_forget_before_compile_is_harmless(self):
        codec = head_dev_codec()
        codec.forget_device()
        self.assertEqual(codec._sync, b"")

    def test_explicit_sync_wins_over_device(self):
        codec = head_dev_codec(sync=b"\x7e")
        codec.feed(build_head_dev(DEV1))
        self.assertEqual(codec._sync, b"\x7e")

    def test_sync_from_device_can_be_disabled(self):
        codec = head_dev_codec(sync_from_device=False)
        codec.feed(build_head_dev(DEV1))
        self.assertEqual(codec._sync, b"")

    def test_one_byte_device_is_too_weak_to_be_anchor(self):
        rules = [
            Field.u8("dev"),
            Field.u8("n"),
            Field.raw("body", "{n.val}"),
            Field.checksum("crc", 2, group="{dev}{n}{body}"),
        ]
        codec = make_codec(rules, crc=crc16_modbus, device_field="dev")
        codec.bind_device(0x1234)  # 宽于字段 → 还原失败，不设锚点
        codec.compile()
        self.assertEqual(codec._sync, b"")
        codec.forget_device()
        codec.bind_device(0x07)  # 单字节锚点区分度太低，也不用
        self.assertEqual(codec._sync, b"")

    def test_non_numeric_device_is_not_anchor(self):
        codec = head_dev_codec()
        codec.compile()
        codec.bind_device("dev-a")  # 非 bytes/非 int，还原不出字节
        self.assertEqual(codec._sync, b"")

    def test_device_field_not_first_keeps_fixed_header_anchor(self):
        rules = [
            Field.u8("start", fixed=0x55),
            Field.raw("dev_id", 4),
            Field.u8("n"),
            Field.raw("body", "{n.val}"),
        ]
        codec = make_codec(rules, device_field="dev_id")
        codec.feed(b"\x55" + DEV1 + b"\x01\x41")
        self.assertEqual(codec._sync, b"\x55")

    def test_dynamic_length_device_field_is_not_anchor(self):
        rules = [Field.raw("dev_id", lambda fields: 4), Field.u8("cmd")]
        codec = make_codec(rules, device_field="dev_id")
        codec.bind_device(0x0102)  # 长度是表达式/回调 → 静态还原不出字节
        codec.compile()
        self.assertEqual(codec._sync, b"")


class TestLockDeviceAfterLearn(unittest.TestCase):
    """学到即锁定：之后设备号不符的帧直接当脏数据，帧中间接入也能立刻跳开。"""

    def test_learning_flips_strict_mode(self):
        codec = head_dev_codec(lock_device_after_learn=True)
        self.assertFalse(codec.enforce_device_id)
        codec.feed(build_head_dev(DEV1))
        self.assertTrue(codec.enforce_device_id)

    def test_other_device_frame_is_dropped_after_lock(self):
        codec = head_dev_codec(lock_device_after_learn=True)
        codec.feed(build_head_dev(DEV1))
        self.assertEqual(codec.feed(build_head_dev(DEV2)), [])
        self.assertEqual(codec.device_id, DEV1)

    def test_mid_frame_start_is_rejected_immediately_after_lock(self):
        """学会后设备号是首字段：假设备号在第 1 个字段就被判死，不必等长度凑够。"""
        codec = head_dev_codec(lock_device_after_learn=True)
        codec.feed(build_head_dev(DEV1, body=b"warm"))
        first = build_head_dev(DEV1, body=b"aaaa")
        second = build_head_dev(DEV1, body=b"bbbb")
        frames = codec.feed(first[3:] + second)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("body"), b"bbbb")


class TestPreemptOnSync(unittest.TestCase):
    """假长度把后续真帧一起堵住时，用锚点直接切断（需显式开启）。"""

    @staticmethod
    def _stalled_stream():
        # 前半截从帧中间开始，n 被误读成 0x61=97 → 一直等；后半截是真帧
        stuck = build_head_dev(DEV1, body=b"aaaa")[3:]
        tail = b"".join(build_head_dev(DEV1, body=bytes([i]) * 4) for i in range(3))
        return stuck + tail

    def test_off_by_default(self):
        codec = head_dev_codec()
        codec.feed(build_head_dev(DEV1, body=b"warm"))
        self.assertEqual(codec.feed(self._stalled_stream()), [])

    def test_recovers_frames_already_in_buffer(self):
        codec = head_dev_codec(preempt_on_sync=True)
        codec.feed(build_head_dev(DEV1, body=b"warm"))
        frames = codec.feed(self._stalled_stream())
        self.assertEqual([f.value("body")[0] for f in frames], [0, 1, 2])
        self.assertEqual(codec.pending_bytes, b"")

    def test_anchor_lookalike_without_valid_frame_is_skipped(self):
        codec = head_dev_codec(preempt_on_sync=True)
        codec.feed(build_head_dev(DEV1, body=b"warm"))
        stuck = build_head_dev(DEV1, body=b"aaaa")[3:]
        decoy = DEV1 + b"\x00" * 20  # 长得像帧头，但后面凑不出合法帧
        frames = codec.feed(stuck + decoy + build_head_dev(DEV1, body=b"real"))
        self.assertEqual([f.value("body") for f in frames], [b"real"])

    def test_waits_when_no_anchor_ahead(self):
        """往前找不到锚点 → 老老实实等（抢占不能凭空造出帧）。"""
        codec = head_dev_codec(preempt_on_sync=True)
        codec.feed(build_head_dev(DEV1, body=b"warm"))
        partial = build_head_dev(DEV1, body=b"aaaa")[:5]
        self.assertEqual(codec.feed(partial), [])
        self.assertEqual(codec.pending_bytes, partial)

    def test_no_anchor_no_preemption(self):
        """设备号未知 → 没有锚点，抢占无从下手（与默认行为一致）。"""
        codec = head_dev_codec(preempt_on_sync=True)
        self.assertEqual(codec.feed(self._stalled_stream()), [])


class TestIntDeviceAtFrameHead(unittest.TestCase):
    def test_u16_device_at_head(self):
        rules = [
            Field.u16("dev"),
            Field.u8("cmd"),
            Field.checksum("crc", 2, group="{dev}{cmd}"),
        ]
        builder = lambda dev, cmd: (
            lambda head: head + crc16_modbus(head).to_bytes(2, "big")
        )(dev.to_bytes(2, "big") + bytes([cmd]))
        codec = make_codec(rules, crc=crc16_modbus, device_field="dev")

        frames = codec.feed(builder(0x0102, 1))
        self.assertEqual(frames[0].device_id, 0x0102)
        self.assertEqual(codec.device_id, 0x0102)
        self.assertFalse(codec.feed(builder(0x0102, 2))[0].device_mismatch)
        self.assertTrue(codec.feed(builder(0x0103, 3))[0].device_mismatch)


class TestConfigOnHeadDevice(unittest.TestCase):
    def test_device_field_first_with_fixed_rejected(self):
        rules = [Field.raw("dev_id", 4, fixed=DEV1), Field.u8("cmd")]
        codec = make_codec(rules, device_field="dev_id")
        with self.assertRaises(FrameRuleError):
            codec.compile()

    def test_delimiter_framing_with_head_device(self):
        """分隔符定界同样支持设备号在开头，且设备号未知。"""
        from kkprotocol import DelimiterFraming

        rules = [
            Field.raw("dev_id", 4),
            Field.rest("body"),
        ]
        codec = make_codec(
            rules, framing=DelimiterFraming(end=0x0A), device_field="dev_id"
        )
        frames = codec.feed(b"\x00\x00\x00\x01hello\n")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].device_id, DEV1)
        self.assertEqual(frames[0].value("body"), b"hello")
        self.assertTrue(frames[0].learned_device)


if __name__ == "__main__":
    unittest.main(verbosity=2)
