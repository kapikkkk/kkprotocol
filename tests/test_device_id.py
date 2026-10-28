# -*- coding: utf-8 -*-
"""设备号：未知时放行并学习、外部来源、绑定校验、严格模式、多设备总线。"""

from __future__ import annotations

import unittest

from kkprotocol import Field, sum8

from tests.helpers import make_codec

DEV1 = b"\x00\x00\x00\x01"
DEV2 = b"\x00\x00\x00\x02"


def dev_rules():
    return [
        Field.u8("header", fixed=0x5A),
        Field.raw("dev", 4),
        Field.u8("n"),
        Field.raw("body", "{n.val}"),
        Field.checksum("sum", 1, group="{dev}{n}{body}", fmt="B"),
    ]


def build_dev(dev: bytes = DEV1, body: bytes = b"x", kind: int = 0x5A) -> bytes:
    return bytes([kind]) + dev + bytes([len(body)]) + body + bytes(
        [sum8(dev + bytes([len(body)]) + body)]
    )


def dev_codec(**attrs):
    device_field = attrs.pop("device_field", "dev")
    return make_codec(dev_rules(), crc=sum8, device_field=device_field, **attrs)


class TestLearning(unittest.TestCase):
    def test_unknown_device_is_accepted_and_learned(self):
        codec = dev_codec()
        self.assertIsNone(codec.device_id)
        frames = codec.feed(build_dev(DEV1))
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].device_id, DEV1)
        self.assertTrue(frames[0].learned_device)
        self.assertEqual(codec.device_id, DEV1)

    def test_second_frame_is_not_learned_again(self):
        codec = dev_codec()
        codec.feed(build_dev(DEV1))
        frames = codec.feed(build_dev(DEV1))
        self.assertFalse(frames[0].learned_device)
        self.assertFalse(frames[0].device_mismatch)

    def test_on_device_learned_callback(self):
        learned = []
        codec = dev_codec(on_device_learned=lambda dev, frame: learned.append((dev, len(frame))))
        codec.feed(build_dev(DEV1))
        self.assertEqual(learned, [(DEV1, len(build_dev(DEV1)))])

    def test_learning_can_be_disabled(self):
        codec = dev_codec(auto_learn_device=False)
        frames = codec.feed(build_dev(DEV1))
        self.assertEqual(len(frames), 1)
        self.assertIsNone(codec.device_id)
        self.assertFalse(frames[0].learned_device)

    def test_on_frame_rejection_prevents_learning(self):
        codec = dev_codec(on_frame=lambda frame: False)
        self.assertEqual(codec.feed(build_dev(DEV1)), [])
        self.assertIsNone(codec.device_id)
        self.assertEqual(codec.stats.rejected_frames, 1)


class TestExternalProvider(unittest.TestCase):
    def test_provider_supplies_device_before_parsing(self):
        calls = []

        def provider():
            calls.append(1)
            return DEV1

        codec = dev_codec(device_id_provider=provider)
        frames = codec.feed(build_dev(DEV1))
        self.assertEqual(len(frames), 1)
        self.assertEqual(codec.device_id, DEV1)
        self.assertFalse(frames[0].learned_device)
        self.assertEqual(len(calls), 1)

    def test_provider_returning_none_falls_back_to_learning(self):
        codec = dev_codec(device_id_provider=lambda: None)
        frames = codec.feed(build_dev(DEV2))
        self.assertTrue(frames[0].learned_device)
        self.assertEqual(codec.device_id, DEV2)

    def test_provider_not_called_when_device_known(self):
        calls = []

        def provider():
            calls.append(1)
            return DEV1

        codec = dev_codec(device_id_provider=provider)
        codec.bind_device(DEV1)
        codec.feed(build_dev(DEV1))
        self.assertEqual(calls, [])

    def test_provider_exception_propagates(self):
        def broken():
            raise RuntimeError("registry down")

        codec = dev_codec(device_id_provider=broken)
        with self.assertRaises(RuntimeError):
            codec.feed(build_dev(DEV1))


class TestBindingAndEnforcement(unittest.TestCase):
    def test_mismatch_is_flagged_but_accepted_by_default(self):
        codec = dev_codec()
        codec.bind_device(DEV1)
        frames = codec.feed(build_dev(DEV2))
        self.assertEqual(len(frames), 1)
        self.assertTrue(frames[0].device_mismatch)
        self.assertEqual(codec.device_id, DEV1)
        self.assertEqual(codec.stats.device_mismatches, 1)

    def test_enforce_rejects_mismatched_frame(self):
        codec = dev_codec(enforce_device_id=True)
        codec.bind_device(DEV1)
        self.assertEqual(codec.feed(build_dev(DEV2)), [])
        self.assertGreaterEqual(codec.stats.resyncs, 1)
        # 正确设备仍然能解析
        frames = codec.feed(build_dev(DEV1))
        self.assertEqual(len(frames), 1)
        self.assertFalse(frames[0].device_mismatch)

    def test_forget_device_allows_relearn(self):
        codec = dev_codec()
        codec.feed(build_dev(DEV1))
        self.assertEqual(codec.device_id, DEV1)
        codec.forget_device()
        self.assertIsNone(codec.device_id)
        frames = codec.feed(build_dev(DEV2))
        self.assertTrue(frames[0].learned_device)
        self.assertEqual(codec.device_id, DEV2)

    def test_device_id_property_setter(self):
        codec = dev_codec()
        codec.device_id = DEV2
        self.assertEqual(codec.device_id, DEV2)
        frames = codec.feed(build_dev(DEV1))
        self.assertTrue(frames[0].device_mismatch)

    def test_bus_with_multiple_devices(self):
        codec = dev_codec()
        codec.bind_device(DEV1)
        stream = build_dev(DEV1) + build_dev(DEV2) + build_dev(DEV1)
        frames = codec.feed(stream)
        self.assertEqual(len(frames), 3)
        self.assertEqual([f.device_mismatch for f in frames], [False, True, False])
        self.assertEqual(codec.stats.device_mismatches, 1)

    def test_int_device_field(self):
        rules = [
            Field.u8("header", fixed=0x5A),
            Field.u16("dev"),
            Field.u8("n"),
            Field.raw("body", "{n.val}"),
            Field.checksum("sum", 1, group="{dev}{n}{body}", fmt="B"),
        ]
        codec = make_codec(rules, crc=sum8, device_field="dev")

        def build(dev: int, body: bytes = b"z") -> bytes:
            head = bytes([0x5A]) + dev.to_bytes(2, "big") + bytes([len(body)]) + body
            return head + bytes([sum8(head[1:])])

        frames = codec.feed(build(0x0102))
        self.assertEqual(frames[0].device_id, 0x0102)
        self.assertEqual(codec.device_id, 0x0102)

        codec.bind_device(0x0102)
        self.assertFalse(codec.feed(build(0x0102))[0].device_mismatch)
        self.assertTrue(codec.feed(build(0x0103))[0].device_mismatch)

    def test_no_device_field_configured(self):
        codec = make_codec(dev_rules(), crc=sum8)
        frames = codec.feed(build_dev(DEV1))
        self.assertIsNone(frames[0].device_id)
        self.assertFalse(frames[0].learned_device)
        self.assertIsNone(codec.device_id)

    def test_device_field_missing_in_rules(self):
        codec = dev_codec(device_field="nope")
        from kkprotocol import FrameRuleError

        with self.assertRaises(FrameRuleError):
            codec.compile()

    def test_device_field_with_fixed_is_rejected(self):
        rules = [
            Field.u8("dev", fixed=0x01),
            Field.u8("n"),
        ]
        codec = make_codec(rules, device_field="dev")
        from kkprotocol import FrameRuleError

        with self.assertRaises(FrameRuleError):
            codec.compile()


if __name__ == "__main__":
    unittest.main(verbosity=2)
