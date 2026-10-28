# -*- coding: utf-8 -*-
"""SLIP（Serial Line Internet Protocol，RFC 1055）。

定界方式：以 ``0xC0`` 为帧首尾标志，``0xDB`` 为转义字节：

* ``0xC0`` -> ``0xDB 0xDC``
* ``0xDB`` -> ``0xDB 0xDD``

SLIP 本身没有长度字段也没有校验和（依赖上层协议）。这里用来验证：

* 分隔符定界的转义/反转义正确性（净荷里含 0xC0 / 0xDB 时不能误判边界）；
* 首尾共用同一个标志字节（``start == end == 0xC0``，PPP/HDLC 同款写法）。
"""
from __future__ import annotations

from ..framing import DelimiterFraming, wrap_frame
from ..spec import Field, FrameSpec

SLIP = DelimiterFraming(
    end=0xC0, escape=0xDB, escape_map={0xC0: 0xDC, 0xDB: 0xDD}
)


SPEC = FrameSpec(
    fields=[Field.rest("data", desc="净荷，取到帧尾 0xC0 为止")],
    framing=SLIP,
    desc="SLIP",
)


def codec():
    """返回一个可直接 feed() 的 SLIP 解析器。"""
    return SPEC.to_codec()


def build(data: bytes) -> bytes:
    """组一条 SLIP 帧（加首尾 0xC0 + 转义）。"""
    return wrap_frame(data, SLIP)
