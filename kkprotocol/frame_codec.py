# -*- coding: utf-8 -*-
"""兼容旧导入路径（v1 的 ``kkprotocol.frame_codec``）。

新代码请直接 ``from kkprotocol import ...``；这个模块只做转发，
并把旧类名 ``AbstractProtocolBaseFilter`` 映射到 ``AbstractFrameCodec``。
"""

from __future__ import annotations

from .codec import AbstractFrameCodec, CodecStats
from .compiler import CompiledField, compile_rules
from .errors import FrameCodecError, FrameRuleError
from .fields import Field
from .frame import FieldValue, Frame
from .framing import (
    AUTO_FRAMING,
    DELIMITER_FRAMING,
    LENGTH_FRAMING,
    DelimiterFraming,
    escape_bytes,
    find_end_delimiter,
    unescape_bytes,
    wrap_frame,
)
from .length import LengthExpr

# 旧类名兼容
AbstractProtocolBaseFilter = AbstractFrameCodec

__all__ = [
    "AbstractFrameCodec",
    "AbstractProtocolBaseFilter",
    "AUTO_FRAMING",
    "CodecStats",
    "CompiledField",
    "DELIMITER_FRAMING",
    "DelimiterFraming",
    "Field",
    "FieldValue",
    "Frame",
    "FrameCodecError",
    "FrameRuleError",
    "LENGTH_FRAMING",
    "LengthExpr",
    "compile_rules",
    "escape_bytes",
    "find_end_delimiter",
    "unescape_bytes",
    "wrap_frame",
]
