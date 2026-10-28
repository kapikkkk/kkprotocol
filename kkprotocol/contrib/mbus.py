# -*- coding: utf-8 -*-
"""M-Bus（Meter-Bus，EN 13757-2/3 有线抄表总线）。

长帧结构（长度定界，同步字节 0x68）：::

    68  L  L  68  C  A  CI  DATA(L-3)  CS(1)  16

要点（压测点）：

* 长度字段 ``L`` **重复出现两次**（68 L L 68），且 L = 控制/地址/CI + 数据 的字节数；
* CS 是第一个 0x68 到 DATA 末尾的累加和。

暴露的设计缺口：库当前**只支持一个长度字段**自动回填，M-Bus 这种“长度字节冗余
两次”的结构，组帧时第二份 L 无法被 builder 自动填成和第一份一样——所以这里组帧
走手工构造（见 ``build_mbus``），解析走通用引擎（能正确切帧 + 校验）。这本身不是致命
缺陷，但说明 builder 对“冗余长度/字段复制”没有原生支持。
"""
from __future__ import annotations

from ..builder import Protocol
from ..crc import sum8
from ..spec import ChecksumRule, Field, FrameSpec

START = 0x68
END = 0x16


SPEC = FrameSpec(
    fields=[
        Field.u8("start", fixed=START),
        Field.u8("len"),
        Field.u8("len2"),
        Field.u8("mid", fixed=START),
        Field.u8("ctrl"),
        Field.u8("addr", desc="从站地址（设备号）"),
        Field.u8("ci"),
        Field.raw("data", "{len.val}-3"),
        Field.checksum("cs", 1, group="{start}{len}{len2}{mid}{ctrl}{addr}{ci}{data}"),
        Field.u8("end", fixed=END),
    ],
    payload="data",
    checksum=ChecksumRule("cs", sum8),
    device="addr",
    max_frame_size=256,
    desc="M-Bus long frame",
)


def protocol(device_id: int = None, enforce_device_id: bool = False) -> Protocol:
    return Protocol(SPEC, device_id=device_id, enforce_device_id=enforce_device_id)


def build_mbus(ctrl: int, addr: int, ci: int, data: bytes = b"") -> bytes:
    """手工组一条 M-Bus 长帧（自动填两份相同的 L 与累加和 CS）。

    注意：这里没有走 ``FrameBuilder``，因为第二份长度字节无法被 builder 自动复制。
    """
    length = 3 + len(data)  # C + A + CI + DATA
    body = bytes([START, length, length, START, ctrl & 0xFF, addr & 0xFF, ci & 0xFF]) + data
    cs = sum8(body)  # 从第一个 0x68 到 DATA 末尾
    return body + bytes([cs, END])
