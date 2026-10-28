# -*- coding: utf-8 -*-
"""批量健壮性测试：用 ≥10 个真实通讯协议压测 kkprotocol 库。

覆盖的协议（见 ``kkprotocol/contrib/``，不进顶层导出，按需 import）：

* 长度定界 + 单字节 magic：DL/T645-2007、CJ/T188-2004、M-Bus、ccTalk（无定界符）、
  XModem/YModem（固定帧长）、Art-Net（多字节 magic）、BACnet MS/TP（双 CRC）
* 分隔符定界 + 转义：SLIP、HDLC/PPP（rest + 尾随 FCS）、Modbus ASCII（ASCII-Hex）、
  NMEA-0183（纯文本记录）

每个协议都跑：组帧→解析往返、逐字节分片、黏包（多帧）、坏校验拦截、设备号/多帧分派。
这些测试既验证“库能落地真实协议”，也把压测中暴露的设计缺口钉成断言（见各协议 docstring）。
"""

from __future__ import annotations

import unittest

from kkprotocol import (
    AbstractFrameCodec,
    ChecksumRule,
    DelimiterFraming,
    Field,
    FrameSpec,
)
from kkprotocol.crc import crc16_ccitt, crc16_x25, crc8, sum8

from kkprotocol.contrib import artnet as M_artnet
from kkprotocol.contrib import bacnet_mstp as M_bacnet
from kkprotocol.contrib import cctalk as M_cctalk
from kkprotocol.contrib import cjt188 as M_cjt188
from kkprotocol.contrib import dlt645 as M_dlt645
from kkprotocol.contrib import hdlc as M_hdlc
from kkprotocol.contrib import mbus as M_mbus
from kkprotocol.contrib import modbus_ascii as M_modbus_ascii
from kkprotocol.contrib import nmea as M_nmea
from kkprotocol.contrib import slip as M_slip
from kkprotocol.contrib import xmodem as M_xmodem


def feed_in_chunks(codec_factory, data: bytes, size: int = 1) -> list:
    """把 ``data`` 切成 ``size`` 字节的小块逐次喂入一个全新 codec，返回解析出的帧。"""
    c = codec_factory()
    out = []
    for i in range(0, len(data), size):
        out += c.feed(data[i : i + size])
    return out


def corrupt(data: bytes, pos: int, mask: int = 0xFF) -> bytes:
    """翻转 ``pos`` 处字节的低几 bit，制造一帧“内容变了但长度/结构未变”的脏帧。"""
    b = bytearray(data)
    b[pos] ^= mask
    return bytes(b)


class _ContribRoundTripMixin:
    """子类提供 ``build()`` 与 ``codec_factory()``，复用同一套往返/分片/黏包/坏校验测试。"""

    # 子类覆盖
    def build(self) -> bytes:  # pragma: no cover - 占位
        raise NotImplementedError

    def codec_factory(self):  # pragma: no cover - 占位
        raise NotImplementedError

    def check_payload(self, frame) -> bool:  # pragma: no cover - 占位
        raise NotImplementedError

    def bad_checksum_pos(self) -> int:
        """坏校验测试要篡改的字节位置（必须在数据/头/校验覆盖范围内）。"""
        raise NotImplementedError

    # 通用测试
    def test_round_trip_full(self):
        wire = self.build()
        frames = self.codec_factory().feed(wire)
        self.assertEqual(len(frames), 1, wire.hex())
        self.assertTrue(self.check_payload(frames[0]), frames[0].fields)

    def test_round_trip_byte_by_byte(self):
        wire = self.build()
        frames = feed_in_chunks(self.codec_factory, wire, 1)
        self.assertEqual(len(frames), 1, wire.hex())
        self.assertTrue(self.check_payload(frames[0]), frames[0].fields)

    def test_sticky_two_frames(self):
        wire = self.build()
        frames = self.codec_factory().feed(wire + wire)
        self.assertEqual(len(frames), 2, wire.hex())
        self.assertTrue(self.check_payload(frames[0]))
        self.assertTrue(self.check_payload(frames[1]))

    def test_sticky_three_frames(self):
        wire = self.build()
        frames = self.codec_factory().feed(wire * 3)
        self.assertEqual(len(frames), 3)

    def test_bad_checksum_rejected(self):
        wire = corrupt(self.build(), self.bad_checksum_pos())
        frames = self.codec_factory().feed(wire)
        # 坏校验 → 整帧被否证、重同步后无完整帧（发回 0 帧）
        self.assertEqual(len(frames), 0, wire.hex())


# --------------------------------------------------------------------------- #
# 长度定界 + 单字节 magic
# --------------------------------------------------------------------------- #
class TestDLT645(unittest.TestCase, _ContribRoundTripMixin):
    ADDR = b"\x01\x00\x00\x00\x00\x00"

    def build(self):
        return M_dlt645.build_request(self.ADDR, ctrl=0x11, data=b"\x10\x01")

    def codec_factory(self):
        return M_dlt645.protocol(self.ADDR)

    def check_payload(self, frame):
        return M_dlt645.decode_data(frame.value("data")) == b"\x10\x01"

    def bad_checksum_pos(self):
        return 12  # data 字节，位于 CS 覆盖范围

    def test_length_field_covers_data_only(self):
        # L 只等于 DATA 字节数（span=("data","data")），解析后 len 字段 == 2
        wire = M_dlt645.build_request(self.ADDR, ctrl=0x11, data=b"\x10\x01")
        f = self.codec_factory().feed(wire)[0]
        self.assertEqual(f.value("len"), 2)

    def test_add33_transform(self):
        # 数据域 +0x33 / -0x33 由调用方手工完成，库本身不做字节变换
        wire = M_dlt645.build_request(self.ADDR, ctrl=0x11, data=b"\x00\x00")
        f = self.codec_factory().feed(wire)[0]
        # 应用层 0x00 经 +0x33 后线上为 0x33
        self.assertEqual(f.value("data"), b"\x33\x33")
        self.assertEqual(M_dlt645.decode_data(f.value("data")), b"\x00\x00")

    def test_bad_addr_length(self):
        with self.assertRaises(ValueError):
            M_dlt645.build_request(b"\x01\x02\x03", ctrl=0x11)


class TestCJT188(unittest.TestCase, _ContribRoundTripMixin):
    ADDR = b"\x01\x00\x00\x01\x00\x00\x00"

    def build(self):
        return M_cjt188.build_request(self.ADDR, ctrl=0x01, meter_type=0x10, data=b"\x33\x44")

    def codec_factory(self):
        return M_cjt188.protocol(self.ADDR)

    def check_payload(self, frame):
        return frame.value("data") == b"\x33\x44"

    def bad_checksum_pos(self):
        return 13

    def test_bad_addr_length(self):
        with self.assertRaises(ValueError):
            M_cjt188.build_request(b"\x01\x02\x03", ctrl=0x01)


class TestMBus(unittest.TestCase, _ContribRoundTripMixin):
    def build(self):
        return M_mbus.build_mbus(0x53, 0x01, 0x72, b"\xAA\xBB")

    def codec_factory(self):
        return M_mbus.protocol(0x01)

    def check_payload(self, frame):
        return frame.value("data") == b"\xAA\xBB"

    def bad_checksum_pos(self):
        return 9  # DATA 字节，落在 CS 覆盖内

    def test_dual_length_bytes_equal(self):
        # M-Bus 冗余两份长度字节，手工组帧保证两者一致
        wire = self.build()
        self.assertEqual(wire[1], wire[2])

    def test_group_checksum_covers_both_lengths(self):
        # 校验 group 含 len 与 len2，篡改 len2 仍被 CS 否证
        wire = corrupt(self.build(), 2)
        self.assertEqual(len(self.codec_factory().feed(wire)), 0)


class TestCCTalk(unittest.TestCase, _ContribRoundTripMixin):
    def build(self):
        return M_cctalk.build(0x02, 0x01, 0x20, b"\x01\x02\x03")

    def codec_factory(self):
        return M_cctalk.protocol()

    def check_payload(self, frame):
        return frame.value("data") == b"\x01\x02\x03"

    def bad_checksum_pos(self):
        return 4  # DATA 字节

    def test_length_byte_equals_data_count(self):
        # 修正点：ccTalk 长度字节 = 数据字节数（不是“到帧尾”），解析后 dlen == 3
        wire = self.build()
        f = self.codec_factory().feed(wire)[0]
        self.assertEqual(f.value("dlen"), 3)

    def test_no_sync_anchor_recovers_via_checksum(self):
        # ccTalk 无帧头定界符（无同步锚点）：错位后**不能靠锚点**恢复，只能靠校验和
        # 否证垃圾帧后逐字节重扫。前导垃圾若凑不出合法校验和就会被丢掉、真帧仍解出。
        wire = self.build()
        junk = b"\x00\x00" + wire
        frames = self.codec_factory().feed(junk)
        self.assertEqual(len(frames), 1)  # 真帧被恢复
        self.assertEqual(frames[0].value("data"), b"\x01\x02\x03")

    def test_no_sync_anchor_gap_documented(self):
        # 设计天花板：若垃圾恰好凑出“合法校验和”的假帧，无锚点的 ccTalk 会永久错位。
        # 这里用具确定义的坏帧验证“校验和失效即丢帧”的兜底机制确实存在（若未来想彻底
        # 解决，需要协议层给出最小帧长/最大长度字段之类的强约束）。
        wire = corrupt(self.build(), 4)  # 改 DATA → 校验和否证
        self.assertEqual(len(self.codec_factory().feed(wire)), 0)


class TestXModem(unittest.TestCase, _ContribRoundTripMixin):
    DATA = bytes(range(128))

    def build(self):
        return M_xmodem.build_xmodem(1, self.DATA)

    def codec_factory(self):
        return M_xmodem.protocol_x()

    def check_payload(self, frame):
        return frame.value("data") == self.DATA

    def bad_checksum_pos(self):
        return 3  # DATA 首字节

    def test_fixed_frame_size(self):
        wire = self.build()
        self.assertEqual(len(wire), 133)

    def test_block_inversion(self):
        # 块号与 ~块号 冗余互证（库不自动校验，这里手判）
        wire = self.build()
        f = self.codec_factory().feed(wire)[0]
        self.assertEqual(f.value("blk"), (0xFF - f.value("inv")) & 0xFF)

    def test_ymodem_1024(self):
        data = bytes(range(256)) * 4
        wire = M_xmodem.build_ymodem(2, data)
        self.assertEqual(len(wire), 1029)
        f = M_xmodem.protocol_y().feed(wire)[0]
        self.assertEqual(f.value("data"), data)

    def test_bad_block_sizes(self):
        with self.assertRaises(ValueError):
            M_xmodem.build_xmodem(1, b"\x00" * 127)
        with self.assertRaises(ValueError):
            M_xmodem.build_ymodem(1, b"\x00" * 1023)


class TestArtNet(unittest.TestCase, _ContribRoundTripMixin):
    def build(self):
        return M_artnet.build_artpoll()

    def codec_factory(self):
        return M_artnet.codec()

    def check_payload(self, frame):
        return frame.value("opcode") == 0x2000

    def bad_checksum_pos(self):
        # Art-Net 头部无校验（crc_imp=0），坏“校验”拦截不适用；改测截断不解析
        return -1

    def test_multi_byte_magic_sync(self):
        # 多字节 magic 走长度定界的 sync，解析靠它从垃圾字节后对齐
        wire = self.build()
        junk = b"\x00\x01\x02\x03" + wire  # 非 magic 的前导垃圾
        frames = self.codec_factory().feed(junk)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("opcode"), 0x2000)

    def test_truncated_not_parsed(self):
        wire = self.build()[:8]  # 仅 magic，不足头部
        self.assertEqual(len(self.codec_factory().feed(wire)), 0)

    def test_bad_checksum_rejected(self):
        # Art-Net 头部无校验字段，翻转任意内容字节仍能被“解析”（仅结构校验），
        # 因此“坏校验拦截”对 Art-Net 不适用——覆盖 Mixin 的默认断言。
        wire = corrupt(self.build(), 10)
        self.assertEqual(len(self.codec_factory().feed(wire)), 1)

    def test_crc_imp_zero(self):
        # Art-Net 头部无校验，crc_imp 兜底返回 0
        self.assertEqual(M_artnet.codec().crc_imp(b""), 0)


# --------------------------------------------------------------------------- #
# 分隔符定界 + 转义 / 文本
# --------------------------------------------------------------------------- #
class TestSLIP(unittest.TestCase, _ContribRoundTripMixin):
    def build(self):
        return M_slip.build(b"\x01\xC0\xDB\x02")

    def codec_factory(self):
        return M_slip.codec()

    def check_payload(self, frame):
        return frame.value("data") == b"\x01\xC0\xDB\x02"

    def bad_checksum_pos(self):
        return -1  # SLIP 无校验和

    def test_escape_round_trip(self):
        # 净荷含 0xC0 / 0xDB 时必须转义，且解析能还原
        payload = bytes([0x00, 0xC0, 0xDB, 0x7E, 0xFF])
        wire = M_slip.build(payload)
        self.assertIn(0xDB, wire)  # 转义字节确实出现了
        f = self.codec_factory().feed(wire)[0]
        self.assertEqual(f.value("data"), payload)

    def test_missing_end_delimiter_not_parsed(self):
        wire = M_slip.build(b"abc")[:-1]  # 去掉尾 0xC0
        self.assertEqual(len(self.codec_factory().feed(wire)), 0)


class TestHDLC(unittest.TestCase, _ContribRoundTripMixin):
    def build(self):
        return M_hdlc.build(0x01, 0x03, b"HELLO")

    def codec_factory(self):
        return M_hdlc.codec()

    def check_payload(self, frame):
        return frame.value("info") == b"HELLO"

    def bad_checksum_pos(self):
        return 9  # FCS 首字节

    def test_rest_reserves_trailing_fcs(self):
        # 关键修正点：rest 字段必须给尾随的定长 FCS 留出 2 字节，否则 FCS 解析不到
        wire = self.build()
        f = self.codec_factory().feed(wire)[0]
        self.assertEqual(f.value("info"), b"HELLO")
        from kkprotocol.crc import crc16_x25

        self.assertEqual(f.value("fcs"), crc16_x25(b"\x01\x03HELLO"))

    def test_fcs_verified(self):
        # 篡改 FCS → 校验失败 → 0 帧
        wire = corrupt(self.build(), 9)
        self.assertEqual(len(self.codec_factory().feed(wire)), 0)

    def test_escape_with_flag_in_payload(self):
        # 净荷里出现 0x7E（标志字节）必须被 0x7D 转义，解析还原
        info = bytes([0x7E, 0x7D, 0x01, 0x02])
        wire = M_hdlc.build(0x01, 0x03, info)
        self.assertIn(0x7D, wire)
        f = self.codec_factory().feed(wire)[0]
        self.assertEqual(f.value("info"), info)


class TestModbusASCII(unittest.TestCase, _ContribRoundTripMixin):
    def build(self):
        return M_modbus_ascii.build(0x01, 0x03, b"\x00\x00")

    def codec_factory(self):
        return M_modbus_ascii.codec()

    def check_payload(self, frame):
        addr, func, data = M_modbus_ascii.decode(frame.value("body"))
        return (addr, func, data) == (0x01, 0x03, b"\x00\x00")

    def bad_checksum_pos(self):
        return -1  # 校验在 ASCII 文本里，需手工构造

    def test_ascii_hex_encoding(self):
        wire = self.build()
        # 帧内 body 是 ASCII-Hex 文本，可被解码回二进制
        body = wire[1:-1].replace(b"\r", b"")
        raw = bytes.fromhex(body.decode("ascii"))
        self.assertEqual(raw[:2], b"\x01\x03")

    def test_lrc_rejected(self):
        # 篡改 LRC（最后一字节 hex）后解码应抛校验错误
        wire = bytearray(self.build())
        # body 文本中 LRC 是倒数第 3/2 字节（两个 hex 字符），翻转其一
        wire[-3] ^= 0x01
        frames = self.codec_factory().feed(bytes(wire))
        self.assertEqual(len(frames), 1)
        with self.assertRaises(ValueError):
            M_modbus_ascii.decode(frames[0].value("body"))


class TestNMEA(unittest.TestCase, _ContribRoundTripMixin):
    def build(self):
        return M_nmea.build("GPGGA,123456,3751.65,N,14507.36,E")

    def codec_factory(self):
        return M_nmea.codec()

    def check_payload(self, frame):
        payload, ok = M_nmea.decode(frame.value("body"))
        return ok and payload == "GPGGA,123456,3751.65,N,14507.36,E"

    def bad_checksum_pos(self):
        return -1

    def test_checksum_embedded(self):
        wire = self.build()
        f = self.codec_factory().feed(wire)[0]
        payload, ok = M_nmea.decode(f.value("body"))
        self.assertTrue(ok)

    def test_bad_checksum_rejected(self):
        wire = bytearray(self.build())
        # *XX 校验和嵌在帧内文本里，翻转它
        star = wire.index(b"*")
        wire[star + 1] ^= 0x01
        f = self.codec_factory().feed(bytes(wire))[0]
        _, ok = M_nmea.decode(f.value("body"))
        self.assertFalse(ok)

    def test_decode_missing_star(self):
        with self.assertRaises(ValueError):
            M_nmea.decode(b"GPGGA,123456")


# --------------------------------------------------------------------------- #
# BACnet MS/TP：一帧多校验和（压测暴露的头号设计缺口，现已在解析侧支持）
# --------------------------------------------------------------------------- #
class TestBacnetMSTP(unittest.TestCase):
    def test_token_single_crc(self):
        wire = M_bacnet.build_token(0x00, 0x05, 0x07)
        f = M_bacnet.protocol_token(0x05).feed(wire)[0]
        self.assertEqual(f.value("ftype"), 0x00)
        self.assertEqual(f.value("length"), 0)

    def test_data_dual_crc_round_trip(self):
        wire = M_bacnet.build_data(0x01, 0x05, 0x07, b"\xAA\xBB\xCC")
        f = M_bacnet.protocol_data(0x05).feed(wire)[0]
        self.assertEqual(f.value("data"), b"\xAA\xBB\xCC")
        # 两个 CRC 都被各自算法独立校验（头 CRC8 + 体 CRC16）
        head = bytes([0x01, 0x05, 0x07]) + (3).to_bytes(2, "big")
        self.assertEqual(f.value("hcrc"), crc8(head, poly=0x07, init=0xFF))
        self.assertEqual(f.value("dcrc"), crc16_ccitt(b"\xAA\xBB\xCC", init=0xFFFF))

    def test_data_bad_header_crc_rejected(self):
        wire = corrupt(M_bacnet.build_data(0x01, 0x05, 0x07, b"\xAA\xBB\xCC"), 7)
        self.assertEqual(len(M_bacnet.protocol_data(0x05).feed(wire)), 0)

    def test_data_bad_body_crc_rejected(self):
        wire = corrupt(M_bacnet.build_data(0x01, 0x05, 0x07, b"\xAA\xBB\xCC"), 11)
        self.assertEqual(len(M_bacnet.protocol_data(0x05).feed(wire)), 0)

    def test_dual_crc_spec_is_list(self):
        # 一帧多校验和：FrameSpec.checksum 现在接受 ChecksumRule 列表
        rules = M_bacnet.SPEC_DATA._checksum_rules()
        self.assertEqual(len(rules), 2)
        self.assertEqual({r.key for r in rules}, {"hcrc", "dcrc"})

    def test_codec_uses_per_field_impl(self):
        # to_codec 把每个校验字段映射到各自的 impl（不再共用一个 crc_imp）
        codec = M_bacnet.SPEC_DATA.to_codec()
        self.assertIn("hcrc", codec._crc_impls)
        self.assertIn("dcrc", codec._crc_impls)


# --------------------------------------------------------------------------- #
# 库能力边界：一帧多校验和的“解析侧”已支持，“组帧侧”仍受限（钉成断言）
# --------------------------------------------------------------------------- #
class TestMultiChecksumSupport(unittest.TestCase):
    def test_spec_accepts_single_or_list(self):
        single = ChecksumRule("c", sum8)
        spec = FrameSpec(
            fields=[Field.u8("a"), Field.checksum("c", 1)],
            checksum=single,
        )
        self.assertEqual(spec._checksum_rules(), (single,))

        spec2 = FrameSpec(
            fields=[Field.u8("a"), Field.checksum("c", 1), Field.checksum("d", 1)],
            checksum=[ChecksumRule("c", sum8), ChecksumRule("d", sum8)],
        )
        self.assertEqual(len(spec2._checksum_rules()), 2)

    def test_builder_rejects_multi_checksum_build(self):
        from kkprotocol import FrameBuilder, FrameBuildError

        # 多校验和帧无法用 builder 一次组出来（解析侧可），组帧必须手工
        spec = FrameSpec(
            fields=[
                Field.u8("a"),
                Field.checksum("c", 1),
                Field.checksum("d", 1),
            ],
            checksum=[ChecksumRule("c", sum8), ChecksumRule("d", sum8)],
        )
        builder = FrameBuilder(spec)
        # 解析侧可用
        self.assertEqual(builder._crc_key(), "c")
        with self.assertRaises(FrameBuildError):
            builder.build(1, a=1)

    def test_checksum_rule_must_be_checksumrule(self):
        from kkprotocol import FrameRuleError

        with self.assertRaises(FrameRuleError):
            FrameSpec(
                fields=[Field.u8("a"), Field.checksum("c", 1)],
                checksum=[object()],  # 不是 ChecksumRule
            )

    def test_duplicate_checksum_keys_rejected(self):
        from kkprotocol import FrameRuleError

        with self.assertRaises(FrameRuleError):
            FrameSpec(
                fields=[Field.u8("a"), Field.checksum("c", 1)],
                checksum=[ChecksumRule("c", sum8), ChecksumRule("c", sum8)],
            )

    def test_spec_codec_default_crc_imp_is_zero(self):
        # 没有校验字段的 spec，to_codec 的 crc_imp 兜底返回 0
        spec = FrameSpec(fields=[Field.u8("a")])
        self.assertEqual(spec.to_codec().crc_imp(b"abc"), 0)

    def test_codec_per_field_crc(self):
        # 同一帧内两个不同算法的 CRC 都能被各自校验
        spec = FrameSpec(
            fields=[
                Field.u8("a"),  # a.val=2 → b 正好 2 字节
                Field.raw("b", "{a.val}"),
                Field.checksum("c", 1, group="{a}"),
                Field.checksum("d", 2, fmt="!H", group="{b}"),
            ],
            checksum=[
                ChecksumRule("c", sum8),
                ChecksumRule("d", lambda g: crc16_ccitt(g, 0x0000)),
            ],
        )
        codec = spec.to_codec()
        a = 0x02
        b = bytes([0x34, 0x56])
        c = sum8(bytes([a]))
        d = crc16_ccitt(b, 0x0000)
        wire = bytes([a]) + b + bytes([c]) + d.to_bytes(2, "big")
        f = codec.feed(wire)[0]
        self.assertEqual(f.value("c"), c)
        self.assertEqual(f.value("d"), d)


class TestRestReservation(unittest.TestCase):
    """分隔符定界下 ``rest`` 为尾随定长字段预留空间；遇非定长后续字段则停止预留。"""

    def test_rest_before_variable_field_does_not_reserve(self):
        from kkprotocol import FrameSpec, wrap_frame

        spec = FrameSpec(
            fields=[
                Field.u8("h"),
                Field.rest("mid"),
                Field.rest("tail"),  # 非定长后续字段 → 不预留，mid 吃满剩余
            ],
            framing=DelimiterFraming(end=0x0A),
        )
        wire = wrap_frame(bytes([0x01, 0x02, 0x03, 0x04, 0x05]), DelimiterFraming(end=0x0A))
        frame = spec.to_codec().feed(wire)[0]
        self.assertEqual(frame.value("mid"), b"\x02\x03\x04\x05")
        self.assertEqual(frame.value("tail"), b"")

    def test_rest_before_fixed_field_reserves(self):
        from kkprotocol import FrameSpec, wrap_frame

        spec = FrameSpec(
            fields=[
                Field.u8("h"),
                Field.rest("mid"),
                Field.u8("tail"),  # 定长 1 字节 → 预留
            ],
            framing=DelimiterFraming(end=0x0A),
        )
        wire = wrap_frame(bytes([0x01, 0x02, 0x03, 0x09]), DelimiterFraming(end=0x0A))
        frame = spec.to_codec().feed(wire)[0]
        self.assertEqual(frame.value("mid"), b"\x02\x03")
        self.assertEqual(frame.value("tail"), 0x09)


if __name__ == "__main__":
    unittest.main()
