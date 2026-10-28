# -*- coding: utf-8 -*-
"""DL/T645-2007 多功能电能表通信协议（RS-485，国内电表常见）。

帧结构（长度定界，同步字节 0x68）：:

    68  A0..A5(6)  68  C  L  DATA(L, 每字节 +0x33)  CS(1, 累加和)  16

要点（也是用来压测的点）：

* 帧首/帧尾是固定字节 ``0x68`` / ``0x16``，地址之后还有一个 ``0x68`` —— 结构化帧头里
  重复出现同步字节；若流错位落在中间的 0x68 上，只能靠长度 + 校验否证后重同步
  （库当前只支持**单字节**同步锚点，无法表达“68 + 地址 + 68”这种结构化帧头）。
* 数据域发送端逐字节 ``+0x33``、接收端 ``-0x33``（传输层字节变换，不是加密）；
  这意味着数据里会出现 0x68 / 0x16 / 0x33，库没有“逐字节变换”原语，只能在
  组帧/解析后手动 add33 / sub33。
* CS 是从第一个 0x68 到 DATA 末尾所有字节的累加和（取低 8 位）。
* 长度字段 ``L`` 只等于 DATA 字节数（不是“到帧尾”），靠 ``LengthRule(span=...)`` 圈定。

结论：库能完整组帧 + 解析（长度字段被 ``span`` 正确回填），暴露的设计缺口见上面三点。
"""
from __future__ import annotations

from ..builder import FrameBuilder, Protocol
from ..crc import sum8
from ..framing import LENGTH_FRAMING
from ..spec import ChecksumRule, Field, FrameSpec, LengthRule

START = 0x68
END = 0x16


def add33(data: bytes) -> bytes:
    """数据域发送端编码：逐字节 +0x33。"""
    return bytes((b + 0x33) & 0xFF for b in data)


def sub33(data: bytes) -> bytes:
    """数据域接收端解码：逐字节 -0x33。"""
    return bytes((b - 0x33) & 0xFF for b in data)


SPEC = FrameSpec(
    fields=[
        Field.u8("start", fixed=START),
        Field.raw("addr", 6, desc="表号（低字节在前）"),
        Field.u8("mid", fixed=START),
        Field.u8("ctrl"),
        Field.u8("len"),
        Field.raw("data", "{len.val}"),
        Field.checksum("cs", 1, group="{start}{addr}{mid}{ctrl}{len}{data}"),
        Field.u8("end", fixed=END),
    ],
    payload="data",
    # 长度字段 L 只等于 DATA 字节数：用 span=("data","data") 圈住数据字段自身
    # （span 左闭右闭、起点计入，所以 “data..data” = 仅数据段长度）
    length=LengthRule("len", span=("data", "data")),
    checksum=ChecksumRule("cs", sum8),
    device="addr",
    max_frame_size=64,
    desc="DL/T645-2007",
)

_builder = FrameBuilder(SPEC)


def protocol(device_id: bytes = None, enforce_device_id: bool = False) -> Protocol:
    """拿一个既能组指令又能解析的 Protocol。"""
    return Protocol(SPEC, device_id=device_id, enforce_device_id=enforce_device_id)


def build_request(addr: bytes, ctrl: int = 0x11, data: bytes = b"") -> bytes:
    """组一条请求帧。``data`` 传应用层原始字节（不含 +0x33），长度即 L。"""
    if len(addr) != 6:
        raise ValueError("DLT645 地址必须 6 字节")
    encoded = add33(data)
    return _builder.build_raw(None, encoded, addr=addr, ctrl=ctrl)


def decode_data(raw_data: bytes) -> bytes:
    """把解析出来的 data 原始字节还原成应用层数据（-0x33）。"""
    return sub33(raw_data)
