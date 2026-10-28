# -*- coding: utf-8 -*-
"""示例磁致伸缩位移计 A（Modbus RTU）协议：组帧/解析闭环 + 规格书示例回归。

这些用例的期望值都不是我自己算的——要么与规格书里的示例字节逐字节相同，
要么由 CRC 反推验证过（见 module docstring 里的笔误说明）。
"""

from __future__ import annotations

import unittest

from kkprotocol import example_modbus_rtu as ry
from kkprotocol.builder import Protocol
from kkprotocol.crc import crc16_modbus
from kkprotocol.errors import FrameBuildError

# 规格书第 6 章示例：读 0004H 起 3 个寄存器
READ_REQ_HEX = "010300040003440a"
# 规格书第 6 章示例：写 002CH = 0（正反向）
WRITE_REQ_HEX = "0106002c00004803"
# 规格书"返回"示例：文档写的是 00 77 CE 95 01 AC，CRC 应为 FA 57 而非 EB DA；
# 把数值换成 99 45（0x9945/0xFFFF = 0.598，与文中一致）后 CRC 恰好是 EB DA。
RSP_HEX = "010306007 79945 01acebda".replace(" ", "")
RSP_DOC_HEX = "010306007 7ce95 01acebda".replace(" ", "")


class TestCrcBytesLe(unittest.TestCase):
    """CRC 必须按线上字节序（低字节在前）返回，供字节对照用。"""

    def test_returns_two_bytes_little_endian(self):
        crc = ry.crc_bytes_le(b"\x01\x03\x00\x04\x00\x03")
        self.assertIsInstance(crc, bytes)
        self.assertEqual(len(crc), 2)
        self.assertEqual(crc, bytes.fromhex("440a"))
        self.assertEqual(crc, crc16_modbus(b"\x01\x03\x00\x04\x00\x03").to_bytes(2, "little"))

    def test_low_byte_comes_first(self):
        """不是简单的大端切片：与 int 大端写法结果不同。"""
        data = b"\x01\x03\x00\x04\x00\x03"
        big = crc16_modbus(data).to_bytes(2, "big")
        self.assertNotEqual(ry.crc_bytes_le(data), big)


class TestBuildRequest(unittest.TestCase):
    """请求帧固定 8 字节，长度/校验都得自己算出来。"""

    def test_read_request_matches_manual(self):
        self.assertEqual(ry.build_read(1), bytes.fromhex(READ_REQ_HEX))
        self.assertEqual(ry.build_read(1).hex(), READ_REQ_HEX)

    def test_read_request_default_register_and_count(self):
        """默认读位置3（0004H）的整数/小数 + 温度，共 3 个寄存器。"""
        self.assertEqual(ry.REGISTERS["POS3"], 0x0004)
        self.assertEqual(ry.build_read(0x01), ry.build_read(0x01, reg=0x0004, count=3))

    def test_read_request_other_register(self):
        frame = ry.build_read(1, reg=ry.REGISTERS["POS1"], count=2)
        self.assertEqual(frame.hex(), "010300000002" + ry.crc_bytes_le(frame[:6]).hex())
        self.assertEqual(len(frame), 8)

    def test_write_request_matches_manual(self):
        self.assertEqual(ry.build_write(1, ry.REGISTERS["DIR"], 0), bytes.fromhex(WRITE_REQ_HEX))

    def test_write_factory_reset(self):
        frame = ry.build_write(1, ry.REGISTERS["FACTORY"], 0x00FF)
        self.assertEqual(frame.hex(), "0106002e00ff" + ry.crc_bytes_le(frame[:6]).hex())

    def test_write_set_address(self):
        frame = ry.build_write(1, ry.REGISTERS["SET_ADDR"], 7)
        self.assertEqual(frame[:6], bytes.fromhex("01060020 0007".replace(" ", "")))

    def test_all_requests_are_eight_bytes_and_self_checked(self):
        for addr in (1, 2, 247):
            for func_builder, args in ((ry.build_read, (addr,)), (ry.build_write, (addr, 0x002C, 0))):
                frame = func_builder(*args)
                self.assertEqual(len(frame), 8)
                self.assertEqual(frame[-2:], ry.crc_bytes_le(frame[:-2]))

    def test_build_reports_two_rounds(self):
        """无长度字段、有 CRC：首轮用占位 CRC，次轮收敛。"""
        result = ry._REQ_BUILDER.build_frame(
            ry.FUNC_READ, addr=1, reg=0x0004, value=3
        )
        self.assertEqual(result.rounds, 2)
        self.assertEqual(bytes(result), bytes.fromhex(READ_REQ_HEX))
        self.assertEqual(result.value("addr"), 1)
        self.assertEqual(result.value("reg"), 0x0004)

    def test_addr_out_of_range_rejected(self):
        with self.assertRaises(FrameBuildError):
            ry.build_read(0x100)


class TestParseResponse(unittest.TestCase):
    """收到的是变长 03 响应，靠第 3 字节 N 切帧。"""

    def setUp(self):
        self.corrected = bytes.fromhex(RSP_HEX)
        self.as_documented = bytes.fromhex(RSP_DOC_HEX)

    def test_corrected_frame_parses(self):
        proto = ry.protocol()
        frames = proto.feed(self.corrected)
        self.assertEqual(len(frames), 1)
        frame = frames[0]
        self.assertEqual(frame.value("addr"), 1)
        self.assertEqual(frame.value("func"), 0x03)
        self.assertEqual(frame.value("n"), 6)
        self.assertEqual(frame.raw_of("data"), bytes.fromhex("00 77 99 45 01 AC".replace(" ", "")))
        self.assertEqual(frame.wire, self.corrected)

    def test_documented_frame_is_rejected_by_crc(self):
        """规格书原样帧（CE 95）过不了 CRC——证明字节对照校验真的在跑。"""
        proto = ry.protocol()
        self.assertEqual(proto.feed(self.as_documented), [])
        self.assertEqual(proto.codec.stats.crc_errors, 1)
        self.assertEqual(proto.codec.stats.frames, 0)

    def test_decoded_physics(self):
        proto = ry.protocol()
        frame = proto.feed(self.corrected)[0]
        decoded = ry.decode_read_result(frame.raw_of("data"))
        self.assertEqual(decoded["registers"], (119, 39237, 428))
        self.assertAlmostEqual(decoded["position_mm"], 119.59871824216067, places=12)
        self.assertAlmostEqual(decoded["temperature_c"], 26.75, places=12)

    def test_sticky_packet(self):
        """两帧连在一起一次喂进去，应当切出两帧、零残留。"""
        proto = ry.protocol()
        frames = proto.feed(self.corrected * 2)
        self.assertEqual(len(frames), 2)
        self.assertEqual(proto.codec.pending_bytes, b"")

    def test_fragmented_packet(self):
        """逐字节喂也应能拼回完整帧。"""
        proto = ry.protocol()
        collected = []
        for i in range(len(self.corrected)):
            collected.extend(proto.feed(self.corrected[i : i + 1]))
        self.assertEqual(len(collected), 1)
        self.assertEqual(collected[0].wire, self.corrected)

    def test_split_three_and_seven(self):
        """按 3/4/4 切开：前两次都只有半包，补齐后才出帧。"""
        proto = ry.protocol()
        self.assertEqual(proto.feed(self.corrected[:3]), [])
        self.assertEqual(proto.feed(self.corrected[3:7]), [])
        self.assertEqual(proto.codec.pending_bytes, self.corrected[:7])
        frames = proto.feed(self.corrected[7:])
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].wire, self.corrected)
        self.assertEqual(proto.codec.pending_bytes, b"")

    def test_garbage_prefix_resynced(self):
        proto = ry.protocol()
        frames = proto.feed(b"\xff\xff" + self.corrected)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].wire, self.corrected)

    def test_write_echo_parsed_by_request_spec(self):
        """06 回显与请求同格式，用请求 spec 解——rx 只认 03，解不了它。"""
        echo = ry.build_write(1, ry.REGISTERS["DIR"], 0)
        codec = ry.RY_REQ.to_codec()
        frames = codec.feed(echo)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("func"), ry.FUNC_WRITE)
        self.assertEqual(frames[0].value("reg"), 0x002C)
        self.assertEqual(frames[0].value("value"), 0)

    def test_write_echo_rejected_by_response_spec(self):
        echo = ry.build_write(1, ry.REGISTERS["DIR"], 0)
        proto = ry.protocol()
        self.assertEqual(proto.feed(echo), [])
        self.assertEqual(proto.codec.stats.frames, 0)


class TestProtocolWiring(unittest.TestCase):
    def test_tx_and_rx_are_different_specs(self):
        proto = ry.protocol()
        self.assertIs(proto.tx, ry.RY_REQ)
        self.assertIs(proto.rx, ry.RY_RSP)
        self.assertNotEqual(proto.diff(), [])
        self.assertTrue(any("payload" in line for line in proto.diff()))

    def test_build_through_protocol(self):
        proto = ry.protocol()
        self.assertEqual(
            proto.build(ry.FUNC_READ, addr=1, reg=0x0004, value=3),
            bytes.fromhex(READ_REQ_HEX),
        )

    def test_verify_rejects_asymmetric_spec(self):
        """用收帧规则回环自检必然失败：这正是需要两份 spec 的证据。"""
        proto = ry.protocol()
        with self.assertRaises(FrameBuildError) as ctx:
            proto.verify(bytes.fromhex(READ_REQ_HEX))
        self.assertIn("回环自检失败", str(ctx.exception))
        self.assertIn("diff", str(ctx.exception))

    def test_verify_ok_with_same_spec_both_sides(self):
        same = Protocol(tx=ry.RY_REQ)
        frame = same.verify(bytes.fromhex(READ_REQ_HEX))
        self.assertEqual(frame.value("addr"), 1)
        self.assertEqual(same.diff(), [])

    def test_device_id_bound_to_codec(self):
        proto = ry.protocol(device_id=1, enforce_device_id=True)
        self.assertEqual(len(proto.feed(bytes.fromhex(RSP_HEX))), 1)

    def test_device_id_mismatch_enforced(self):
        proto = ry.protocol(device_id=2, enforce_device_id=True)
        self.assertEqual(proto.feed(bytes.fromhex(RSP_HEX)), [])
        self.assertEqual(proto.codec.stats.frames, 0)
        self.assertEqual(proto.codec.stats.dropped_bytes, len(bytes.fromhex(RSP_HEX)))

    def test_device_id_mismatch_not_enforced(self):
        proto = ry.protocol(device_id=2)
        self.assertEqual(len(proto.feed(bytes.fromhex(RSP_HEX))), 1)
        self.assertEqual(proto.codec.stats.device_mismatches, 1)

    def test_device_id_set_after_codec_created(self):
        proto = ry.protocol()
        proto.feed(b"")  # 先把 codec 建出来
        proto.device_id = 1
        self.assertEqual(len(proto.feed(bytes.fromhex(RSP_HEX))), 1)

    def test_reset_clears_pending(self):
        proto = ry.protocol()
        proto.feed(bytes.fromhex(RSP_HEX)[:5])
        self.assertEqual(proto.codec.pending_bytes, bytes.fromhex(RSP_HEX)[:5])
        proto.reset()
        self.assertEqual(proto.codec.pending_bytes, b"")


class TestDecodeRegisters(unittest.TestCase):
    def test_big_endian_split(self):
        self.assertEqual(ry.decode_registers(bytes.fromhex("0077 9945 01ac".replace(" ", ""))), (119, 39237, 428))

    def test_odd_length_raises(self):
        with self.assertRaises(ValueError) as ctx:
            ry.decode_registers(b"\x01\x02\x03")
        self.assertIn("偶数", str(ctx.exception))

    def test_empty(self):
        self.assertEqual(ry.decode_registers(b""), ())


class TestDecodeReadResult(unittest.TestCase):
    def test_single_register(self):
        self.assertEqual(
            ry.decode_read_result(bytes.fromhex("002a")),
            {"value": 42, "registers": (42,)},
        )

    def test_two_registers_position_only(self):
        decoded = ry.decode_read_result(bytes.fromhex("00 77 99 45".replace(" ", "")))
        self.assertAlmostEqual(decoded["position_mm"], 119.59871824216067, places=12)
        self.assertNotIn("temperature_c", decoded)

    def test_three_registers_with_temperature(self):
        decoded = ry.decode_read_result(bytes.fromhex("0077 9945 01ac".replace(" ", "")))
        self.assertEqual(decoded["temperature_c"], 26.75)
        self.assertNotIn("extra", decoded)

    def test_four_registers_keeps_extra(self):
        decoded = ry.decode_read_result(bytes.fromhex("0077 9945 01ac 0001".replace(" ", "")))
        self.assertEqual(decoded["extra"], (1,))

    def test_no_data_raises(self):
        with self.assertRaises(ValueError) as ctx:
            ry.decode_read_result(b"")
        self.assertIn("没有数据", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
