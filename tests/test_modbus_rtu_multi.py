# -*- coding: utf-8 -*-
"""示例磁致伸缩位移计 B（Modbus RTU V8.0）协议：组帧/解析/黏包/异常帧闭环。

协议比示例 A 复杂：读(03H/04H)、写单(06H)、写多(10H)、异常(func|0x80) 四类响应结构不同，
所以 MultiFuncProtocol 内部按功能码分派到四份解析器。用例重点验证：组指令对表、
分派解析、黏包/分片、CRC 拦截、设备号 enforce、CDAB 浮点字节序、整数位移符号位。
"""

from __future__ import annotations

import unittest

from kkprotocol import example_modbus_rtu_multi as xw
from kkprotocol.errors import FrameBuildError

# 用现算 CRC 造合法帧，不手写错值
READ_RSP = bytes.fromhex("01 04 04 00 4E 81 A1 3A 7B".replace(" ", ""))
FLOAT_RSP = bytes.fromhex("01 04 04 02 24 42 9D 4B 3E".replace(" ", ""))
TEMP_RSP = bytes.fromhex("01 04 02 0B 1A 3F CB".replace(" ", ""))

SINGLE_RSP = bytes.fromhex("01 06 00 30 00 02") + xw.crc_bytes_le(b"\x01\x06\x00\x30\x00\x02")
MULTI_RSP = bytes.fromhex("01 10 00 30 00 01") + xw.crc_bytes_le(b"\x01\x10\x00\x30\x00\x01")
ERROR_RSP = bytes.fromhex("01 84 01") + xw.crc_bytes_le(b"\x01\x84\x01")


def make_crc(frame_head: bytes) -> bytes:
    return xw.crc_bytes_le(frame_head)


class TestCrc(unittest.TestCase):
    def test_low_byte_first(self):
        c = xw.crc_bytes_le(b"\x01\x04\x00\x00\x00\x02")
        self.assertEqual(c, bytes.fromhex("71 CB"))


class TestBuildRequests(unittest.TestCase):
    def test_read_matches_doc(self):
        self.assertEqual(xw.build_read(1), bytes.fromhex("01 04 00 00 00 02 71 CB".replace(" ", "")))

    def test_read_temperature(self):
        frame = xw.build_read(1, reg=xw.REGISTERS["TEMP1"], count=1)
        self.assertEqual(frame, bytes.fromhex("01 04 00 0C 00 01 F1 C9".replace(" ", "")))

    def test_read_holding_matches_faq(self):
        # FAQ：读从机地址 0x0030，返回 00 03 02 00 + 地址 + CRC
        self.assertEqual(
            xw.build_read_holding(0, reg=0x0030, count=1),
            bytes.fromhex("00 03 00 30 00 01 85 D4".replace(" ", "")),
        )

    def test_write_single(self):
        self.assertEqual(
            xw.build_write_single(1, xw.REGISTERS["ADDR"], 2),
            SINGLE_RSP,
        )

    def test_write_multiple_matches_doc(self):
        self.assertEqual(
            xw.build_write_multiple(1, 0x0030, [2]),
            bytes.fromhex("01 10 00 30 00 01 02 00 02 22 61".replace(" ", "")),
        )

    def test_write_multiple_three_regs(self):
        frame = xw.build_write_multiple(1, 0x0030, [2, 3, 3])
        self.assertEqual(frame[:7], bytes.fromhex("01 10 00 30 00 03 06"))
        self.assertEqual(len(frame), 15)
        self.assertEqual(frame[-2:], xw.crc_bytes_le(frame[:-2]))

    def test_all_builders_eight_byte_or_self_checked(self):
        for frame in (
            xw.build_read(1),
            xw.build_read_holding(0, 0x0030, 1),
            xw.build_write_single(1, 0x0030, 2),
        ):
            self.assertEqual(frame[-2:], xw.crc_bytes_le(frame[:-2]))


class TestProtocolBuild(unittest.TestCase):
    """MultiFuncProtocol 上也能组出同样的字节。"""

    def setUp(self):
        self.proto = xw.MultiFuncProtocol()

    def test_build_read(self):
        self.assertEqual(self.proto.build_read(1), xw.build_read(1))

    def test_build_read_holding(self):
        self.assertEqual(self.proto.build_read_holding(0), xw.build_read_holding(0))

    def test_build_write_single(self):
        self.assertEqual(self.proto.build_write_single(1, 0x30, 2), xw.build_write_single(1, 0x30, 2))

    def test_build_write_multiple(self):
        self.assertEqual(self.proto.build_write_multiple(1, 0x30, [2]), xw.build_write_multiple(1, 0x30, [2]))


class TestParseResponses(unittest.TestCase):
    def setUp(self):
        self.proto = xw.MultiFuncProtocol(device_id=1)

    def test_read_integer_displacement(self):
        frames = self.proto.feed(READ_RSP)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("func"), 0x04)
        self.assertEqual(frames[0].value("n"), 4)
        self.assertEqual(
            xw.decode_displacement_int(frames[0].raw_of("data")), 78.50637064164187
        )

    def test_read_float_displacement_cdab(self):
        frames = self.proto.feed(FLOAT_RSP)
        self.assertEqual(xw.decode_displacement_float(frames[0].raw_of("data")), [78.50418090820312])

    def test_read_temperature(self):
        frames = self.proto.feed(TEMP_RSP)
        self.assertAlmostEqual(xw.decode_temperature(frames[0].raw_of("data")), 28.42)

    def test_sticky_three_response_types(self):
        """写单 + 写多 + 异常 粘连在一起，分派器应切出三个不同结构。"""
        blob = SINGLE_RSP + MULTI_RSP + ERROR_RSP
        frames = self.proto.feed(blob)
        self.assertEqual(len(frames), 3)
        self.assertEqual([f.value("func") for f in frames], [6, 16, 132])
        self.assertEqual(frames[2].value("err"), 1)
        self.assertEqual(self.proto.pending_bytes, b"")

    def test_interleaved_read_and_write(self):
        blob = READ_RSP + SINGLE_RSP + READ_RSP
        frames = self.proto.feed(blob)
        self.assertEqual(len(frames), 3)
        self.assertEqual([f.value("func") for f in frames], [4, 6, 4])

    def test_fragmented(self):
        out = []
        for b in READ_RSP:
            out.extend(self.proto.feed(bytes([b])))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].wire, READ_RSP)

    def test_two_stuck_together(self):
        frames = self.proto.feed(READ_RSP * 2)
        self.assertEqual(len(frames), 2)
        self.assertEqual(self.proto.pending_bytes, b"")

    def test_crc_failure_rejected(self):
        bad = bytearray(READ_RSP)
        bad[4] ^= 0xFF
        self.assertEqual(self.proto.feed(bytes(bad)), [])

    def test_device_mismatch_enforced(self):
        proto = xw.MultiFuncProtocol(device_id=5, enforce_device_id=True)
        self.assertEqual(proto.feed(READ_RSP), [])
        self.assertEqual(proto.pending_bytes, READ_RSP)

    def test_device_mismatch_not_enforced(self):
        proto = xw.MultiFuncProtocol(device_id=5)
        frames = proto.feed(READ_RSP)
        self.assertEqual(len(frames), 1)

    def test_set_device_id_after_construction(self):
        proto = xw.MultiFuncProtocol()
        proto.device_id = 1
        self.assertEqual(proto.device_id, 1)
        self.assertEqual(len(proto.feed(READ_RSP)), 1)
        proto.device_id = None  # 走 forget_device 分支
        self.assertIsNone(proto.device_id)
        self.assertEqual(len(proto.feed(READ_RSP)), 1)

    def test_reset_clears_buffer(self):
        self.proto.feed(READ_RSP[:5])
        self.assertNotEqual(self.proto.pending_bytes, b"")
        self.proto.reset()
        self.assertEqual(self.proto.pending_bytes, b"")

    def test_memoryview_input(self):
        frames = self.proto.feed(memoryview(READ_RSP))
        self.assertEqual(len(frames), 1)

    def test_error_frame_parsed_by_error_codec(self):
        frames = self.proto.feed(ERROR_RSP)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("func"), 132)
        self.assertEqual(frames[0].value("err"), 1)


class TestThroughStandardProtocol(unittest.TestCase):
    def test_read_path_via_protocol(self):
        proto = xw.MultiFuncProtocol()
        frames = proto.feed_through_protocol(READ_RSP)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("n"), 4)


class TestDecodeHelpers(unittest.TestCase):
    def test_decode_displacement_int_negative(self):
        # 整数部分为负：0x8000 = -32768
        data = int(-32768).to_bytes(2, "big", signed=True) + (0).to_bytes(2, "big")
        self.assertAlmostEqual(xw.decode_displacement_int(data), -32768.0)

    def test_decode_displacement_int_wrong_length(self):
        with self.assertRaises(ValueError):
            xw.decode_displacement_int(b"\x00\x00\x00")

    def test_decode_displacement_float_two_chunks(self):
        data = bytes.fromhex("02 24 42 9D") + bytes.fromhex("00 00 00 00")
        out = xw.decode_displacement_float(data)
        self.assertEqual(len(out), 2)
        self.assertAlmostEqual(out[0], 78.50418090820312)
        self.assertEqual(out[1], 0.0)

    def test_decode_displacement_float_misaligned(self):
        with self.assertRaises(ValueError):
            xw.decode_displacement_float(b"\x00\x00\x00")

    def test_decode_temperature_wrong_length(self):
        with self.assertRaises(ValueError):
            xw.decode_temperature(b"\x00")

    def test_split_registers(self):
        self.assertEqual(xw.split_registers(bytes.fromhex("00 4E 81 A1")), (78, 33185))

    def test_split_registers_odd(self):
        with self.assertRaises(ValueError):
            xw.split_registers(b"\x00\x01\x02")


class TestRegistersTable(unittest.TestCase):
    def test_known_addresses(self):
        self.assertEqual(xw.REGISTERS["POS1_INT"], 0x0000)
        self.assertEqual(xw.REGISTERS["POS1_FLOAT"], 0x0006)
        self.assertEqual(xw.REGISTERS["TEMP1"], 0x000C)
        self.assertEqual(xw.REGISTERS["ADDR"], 0x0030)


if __name__ == "__main__":
    unittest.main()
