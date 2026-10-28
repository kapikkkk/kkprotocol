# -*- coding: utf-8 -*-
"""ccTalk 货币交易外设串行协议（硬币/纸币识别器、找零器，TTL 多-drop 总线）。

帧结构（长度定界，**没有帧头/帧尾定界符**）：::

    [目的地址] [数据长度] [源地址] [命令头] [DATA...] [校验和]

校验和：所有字节（含校验和）累加后 mod 256 == 0，因此校验和字节 = ``(256 - 前 N 字节和) % 256``。

要点（压测点）：

* **完全没有帧头/帧尾定界符**，也没有同步字节——帧边界只能靠“数据长度字段”推算；
* 一旦流错位（丢/多一个字节），后续所有帧都会整体偏移，**无法靠同步锚点恢复**
  （这与 DLT645/CJ/T188 有固定 0x68 能重同步形成对比）。
* 校验和是“凑零和”式，不是 CRC。

暴露的设计缺口：库的长度定界依赖一个同步锚点来寻找帧起点；ccTalk 这种“无锚点”
协议在错位后恢复能力弱，属于协议本身的天花板，但库也应提供“无同步、纯长度推算”
的明确模式（目前靠 ``sync=None`` 退化为“从缓冲区起点直接读”，错位即全盘皆错）。
"""
from __future__ import annotations

from ..builder import FrameBuilder, Protocol
from ..spec import ChecksumRule, Field, FrameSpec, LengthRule

SPEC = FrameSpec(
    fields=[
        Field.u8("dest", desc="目的地址（设备号）"),
        Field.u8("dlen"),
        Field.u8("source"),
        Field.u8("header"),
        Field.raw("data", "{dlen.val}"),
        Field.checksum("cs", 1, group="{dest}{dlen}{source}{header}{data}"),
    ],
    payload="data",
    # ccTalk 长度字节 = 数据字节数（不含源/头/校验），圈住数据字段自身
    length=LengthRule("dlen", span=("data", "data")),
    checksum=ChecksumRule("cs", lambda group: (-sum(group)) & 0xFF),
    device="dest",
    max_frame_size=260,
    desc="ccTalk",
)

_builder = FrameBuilder(SPEC)


def protocol(device_id: int = None, enforce_device_id: bool = False) -> Protocol:
    return Protocol(SPEC, device_id=device_id, enforce_device_id=enforce_device_id)


def build(dest: int, source: int, header: int, data: bytes = b"") -> bytes:
    """组一条 ccTalk 报文（长度与校验和自动填）。"""
    return _builder.build_raw(None, data, dest=dest, source=source, header=header)
