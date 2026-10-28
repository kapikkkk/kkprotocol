# -*- coding: utf-8 -*-
"""测试共用的帧构造器与 codec 工厂。"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Sequence, Union

from kkprotocol import (
    AbstractFrameCodec,
    DelimiterFraming,
    Field,
    LENGTH_FRAMING,
    sum8,
)
from kkprotocol.example_device import (
    DeviceFrameCodec,
    PppFrameCodec,
    build_device_frame,
    build_ppp_frame,
)

__all__ = [
    "MINI_FIELDS",
    "build_mini",
    "mini_codec",
    "make_codec",
    "build_device_frame",
    "build_ppp_frame",
    "DeviceFrameCodec",
    "PppFrameCodec",
    "sum8",
    "struct",
]

# 简单长度定界协议：AA 01 | n | body(n) | sum(1)
MINI_FIELDS: List[Field] = [
    Field.u8("start", fixed=0xAA),
    Field.u8("kind", fixed=0x01),
    Field.u8("n"),
    Field.raw("body", "{n.val}"),
    Field.checksum("sum", 1, group="{kind}{n}{body}", fmt="B"),
]


def build_mini(body: bytes = b"abc", kind: int = 0x01, bad_sum: bool = False) -> bytes:
    checksum = sum8(bytes([kind, len(body)]) + body)
    if bad_sum:
        checksum = (checksum + 1) & 0xFF
    return bytes([0xAA, kind, len(body)]) + body + bytes([checksum])


def make_codec(
    rules: Sequence[Union[Field, Dict[str, Any]]],
    crc=None,
    **attrs: Any,
) -> AbstractFrameCodec:
    """按给定规则现场造一个 codec 子类实例。"""

    class _Codec(AbstractFrameCodec):
        def rules(self):
            return rules

        def crc_imp(self, data: bytes):
            return crc(data) if crc else 0

    codec = _Codec()
    for key, value in attrs.items():
        # 设在实例上：函数型钩子不会被绑定成方法，覆盖类属性也更直观
        setattr(codec, key, value)
    return codec


def mini_codec(**attrs: Any) -> AbstractFrameCodec:
    return make_codec(MINI_FIELDS, crc=sum8, **attrs)
