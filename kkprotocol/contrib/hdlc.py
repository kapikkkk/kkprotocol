# -*- coding: utf-8 -*-
"""HDLC / PPP 风格帧（标志 0x7E，0x7D 转义异或 0x20，FCS 为 CRC-16）。

帧结构（分隔符定界，首尾共用 0x7E）：::

    FLAG(0x7E)  ADDRESS(1)  CONTROL(1)  INFO(变长)  FCS(2, CRC-16)  FLAG(0x7E)

这里用来验证：

* 分隔符定界 + 转义（PPP/HDLC 标准做法）在通用引擎下能正确组帧/解析；
* 净荷里出现 0x7E / 0x7D 时被转义，不会误判帧边界；
* FCS 是一段末尾固定 2 字节的 CRC（这里用 ``crc16_x25`` 与现有 PPP 示例一致）。

说明：真实 HDLC 的 FCS 字节序与补码约定各异，这里只验证“库的转义 + 末尾 CRC”链路，
FCS 用库内一致的 ``crc16_x25`` 大端打包，不追求与某款硬件逐字节一致。
"""
from __future__ import annotations

from ..crc import crc16_x25
from ..framing import DelimiterFraming, wrap_frame
from ..spec import ChecksumRule, Field, FrameSpec

HDLC = DelimiterFraming(end=0x7E, start=0x7E, escape=0x7D, escape_xor=0x20)

SPEC = FrameSpec(
    fields=[
        Field.u8("address"),
        Field.u8("control"),
        Field.rest("info", desc="信息字段，取到帧尾 0x7E 前"),
        Field.checksum("fcs", 2, fmt="!H", group="{address}{control}{info}"),
    ],
    framing=HDLC,
    # 必须声明 ChecksumRule，否则 to_codec() 的 crc_imp 默认返回 0，FCS 会校验失败
    checksum=ChecksumRule("fcs", crc16_x25),
    desc="HDLC/PPP style",
)


def codec():
    return SPEC.to_codec()


def build(address: int, control: int, info: bytes) -> bytes:
    """组一条 HDLC 帧：先算 FCS，再整体加 0x7E 标志并转义。"""
    inner = bytes([address, control]) + info
    fcs = crc16_x25(inner).to_bytes(2, "big")
    return wrap_frame(inner + fcs, HDLC)
