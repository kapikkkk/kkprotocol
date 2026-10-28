# -*- coding: utf-8 -*-
"""示例协议与兼容层：构造器往返、CRC 向量、旧导入路径。"""

from __future__ import annotations

import unittest

import kkprotocol
from kkprotocol import (
    DeviceFrameCodec,
    HeadDeviceFrameCodec,
    Field,
    PppFrameCodec,
    build_device_frame,
    build_head_device_frame,
    build_ppp_frame,
    crc16_modbus,
    crc16_x25,
)
from kkprotocol import frame_codec as shim


class TestDeviceExample(unittest.TestCase):
    def test_roundtrip_all_fields(self):
        raw = build_device_frame(ver=2, cmd=0x10, ser=0x1234, dev_id=b"ABCD", payload=b"xyz")
        frame = DeviceFrameCodec().feed(raw)[0]
        self.assertEqual(frame.value("ver"), 2)
        self.assertEqual(frame.value("cmd"), 0x10)
        self.assertEqual(frame.value("ser"), 0x1234)
        self.assertEqual(frame.value("dev_id"), b"ABCD")
        self.assertEqual(frame.value("data"), b"xyz")
        self.assertEqual(frame.value("crc"), crc16_modbus(raw[1:-2]))

    def test_bad_crc_frame_rejected(self):
        codec = DeviceFrameCodec()
        self.assertEqual(codec.feed(build_device_frame(bad_crc=True)), [])
        self.assertEqual(codec.stats.crc_errors, 1)

    def test_declared_length_field_counts_ver_to_crc(self):
        raw = build_device_frame(payload=b"0123456789")
        self.assertEqual(raw[1], len(raw) - 2)


class TestHeadDeviceExample(unittest.TestCase):
    """帧首就是设备号：示例类本身就是"未知→学到→固定"的标准配置。"""

    def test_roundtrip_and_learning(self):
        codec = HeadDeviceFrameCodec()
        raw = build_head_device_frame(b"\x00\x00\x00\x07", cmd=0x05, payload=b"abc")
        frame = codec.feed(raw)[0]
        self.assertEqual(frame.value("dev_id"), b"\x00\x00\x00\x07")
        self.assertEqual(frame.value("cmd"), 0x05)
        self.assertEqual(frame.value("data"), b"abc")
        self.assertTrue(frame.learned_device)
        self.assertEqual(codec.device_id, b"\x00\x00\x00\x07")
        self.assertEqual(codec._sync, b"\x00\x00\x00\x07")

    def test_bad_crc_rejected(self):
        codec = HeadDeviceFrameCodec()
        self.assertEqual(codec.feed(build_head_device_frame(bad_crc=True)), [])
        self.assertEqual(codec.stats.crc_errors, 1)

    def test_locked_after_learn(self):
        codec = HeadDeviceFrameCodec()
        codec.feed(build_head_device_frame(b"\x00\x00\x00\x01"))
        self.assertTrue(codec.enforce_device_id)
        self.assertEqual(codec.feed(build_head_device_frame(b"\x00\x00\x00\x02")), [])

    def test_frame_larger_than_max_frame_size_is_rejected(self):
        codec = HeadDeviceFrameCodec()
        big = build_head_device_frame(payload=b"x" * 255)
        self.assertEqual(len(big), 263)
        self.assertLessEqual(len(big), codec.max_frame_size)
        codec.max_frame_size = 64
        self.assertEqual(codec.feed(build_head_device_frame(payload=b"x" * 100)), [])

    def test_idle_timeout_preset(self):
        self.assertEqual(HeadDeviceFrameCodec().idle_timeout, 5.0)


class TestPppExample(unittest.TestCase):
    def test_roundtrip(self):
        raw = build_ppp_frame(dev_id=b"\x01\x02\x03\x04", payload=b"hello\x7eworld")
        frame = PppFrameCodec().feed(raw)[0]
        self.assertEqual(frame.value("addr"), 0xFF)
        self.assertEqual(frame.value("ctrl"), 0x03)
        self.assertEqual(frame.value("dev_id"), b"\x01\x02\x03\x04")
        self.assertEqual(frame.value("data"), b"hello\x7eworld")
        self.assertEqual(frame.value("fcs"), crc16_x25(frame.raw[:-2]))

    def test_bad_fcs_rejected(self):
        codec = PppFrameCodec()
        self.assertEqual(codec.feed(build_ppp_frame(bad_fcs=True)), [])
        self.assertEqual(codec.stats.crc_errors, 1)

    def test_fcs_uses_x25_not_modbus(self):
        body = b"abc"
        self.assertNotEqual(crc16_x25(body), crc16_modbus(body))


class TestCompatLayer(unittest.TestCase):
    def test_old_class_alias(self):
        self.assertIs(shim.AbstractProtocolBaseFilter, shim.AbstractFrameCodec)

    def test_shim_exports(self):
        for name in ("AbstractFrameCodec", "Field", "Frame", "DelimiterFraming", "LengthExpr"):
            self.assertTrue(hasattr(shim, name))

    def test_package_exports(self):
        for name in (
            "AbstractFrameCodec",
            "Field",
            "DeviceFrameCodec",
            "HeadDeviceFrameCodec",
            "PppFrameCodec",
        ):
            self.assertTrue(hasattr(kkprotocol, name))

    def test_field_from_dict(self):
        field = Field.from_dict({"key": "a", "len": 3, "fmt": "", "desc": "x"})
        self.assertEqual(field.key, "a")
        self.assertEqual(field.length, 3)
        self.assertEqual(field.desc, "x")

    def test_field_from_dict_rejects_non_dict(self):
        with self.assertRaises(TypeError):
            Field.from_dict("nope")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main(verbosity=2)
