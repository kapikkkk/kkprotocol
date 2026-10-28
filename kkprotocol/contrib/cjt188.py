# -*- coding: utf-8 -*-
"""CJ/T188-2004 户用计量仪表数据传输技术条件（水/气/热表，RS-485）。

帧结构（长度定界，同步字节 0x68）：::

    68  T(1)  A0..A6(7)  C  L  DATA(L)  CS(1, 累加和)  16

与 DLT645 相比：

* 只有一个 ``0x68``（地址 7 字节后没有第二个 0x68），结构更干净；
* 数据域**不做** +0x33 变换；
* CS 同样是 0x68 到 DATA 末尾的累加和。

用来验证：单固定字节同步 + 长度字段（span 圈数据）+ 和校验，是最“标准”的长度定界样本。
"""
from __future__ import annotations

from ..builder import FrameBuilder, Protocol
from ..crc import sum8
from ..spec import ChecksumRule, Field, FrameSpec, LengthRule

START = 0x68
END = 0x16


SPEC = FrameSpec(
    fields=[
        Field.u8("start", fixed=START),
        Field.u8("type"),
        Field.raw("addr", 7, desc="表号（低字节在前，BCD）"),
        Field.u8("ctrl"),
        Field.u8("len"),
        Field.raw("data", "{len.val}"),
        Field.checksum("cs", 1, group="{start}{type}{addr}{ctrl}{len}{data}"),
        Field.u8("end", fixed=END),
    ],
    payload="data",
    length=LengthRule("len", span=("data", "data")),
    checksum=ChecksumRule("cs", sum8),
    device="addr",
    max_frame_size=128,
    desc="CJ/T188-2004",
)

_builder = FrameBuilder(SPEC)


def protocol(device_id: bytes = None, enforce_device_id: bool = False) -> Protocol:
    return Protocol(SPEC, device_id=device_id, enforce_device_id=enforce_device_id)


def build_request(addr: bytes, ctrl: int = 0x01, meter_type: int = 0x10,
                  data: bytes = b"") -> bytes:
    """组一条读表请求（默认读数据 CTR_0=0x01，冷水表 T=0x10）。"""
    if len(addr) != 7:
        raise ValueError("CJ/T188 地址必须 7 字节")
    return _builder.build_raw(None, data, addr=addr, ctrl=ctrl, type=meter_type)
