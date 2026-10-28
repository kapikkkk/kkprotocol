# -*- coding: utf-8 -*-
"""kkprotocol —— 可自定义数据帧的 TCP 流式解析器。

快速上手::

    from kkprotocol import AbstractFrameCodec, Field, LENGTH_FRAMING, crc16_modbus

    class MyCodec(AbstractFrameCodec):
        framing = LENGTH_FRAMING          # 长度定界（默认）
        device_field = "dev_id"           # 可选：自动学习/校验设备号
        def rules(self):
            return [
                Field.u8("header", fixed=0x55),
                Field.u8("len"),
                Field.raw("dev_id", 4),
                Field.raw("data", "{len.val}-7"),
                Field.checksum("crc", 2, group="{len}{dev_id}{data}"),
            ]
        def crc_imp(self, data):
            return crc16_modbus(data)

    codec = MyCodec()                      # 每个连接一个实例
    for frame in codec.feed(chunk):        # 任意切分的 TCP 数据块
        handle(frame)

帧首不是固定帧头而是设备号、且设备号首帧未知时，直接参考
:class:`HeadDeviceFrameCodec`（学到设备号后自动把它当同步字用）。
"""

from .builder import BuildResult, FrameBuilder, Protocol
from .codec import AbstractFrameCodec, CodecStats
from .compiler import CompiledField, compile_rules
from .crc import crc16_ccitt, crc16_modbus, crc16_x25, crc8, sum8, xor8
from .errors import FrameBuildError, FrameCodecError, FrameRuleError
from .fields import Field
from .frame import FieldValue, Frame
from .pack import Data, pack
from .spec import AutoField, ChecksumRule, FrameSpec, LengthRule, Pdu, SeqPolicy
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
from .example_device import (
    DeviceFrameCodec,
    HeadDeviceFrameCodec,
    PppFrameCodec,
    build_device_frame,
    build_head_device_frame,
    build_ppp_frame,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "AbstractFrameCodec",
    "AUTO_FRAMING",
    "BuildResult",
    "ChecksumRule",
    "CodecStats",
    "CompiledField",
    "DELIMITER_FRAMING",
    "DelimiterFraming",
    "DeviceFrameCodec",
    "Field",
    "FieldValue",
    "Frame",
    "FrameBuildError",
    "FrameBuilder",
    "FrameCodecError",
    "FrameRuleError",
    "FrameSpec",
    "HeadDeviceFrameCodec",
    "LENGTH_FRAMING",
    "LengthExpr",
    "LengthRule",
    "Pdu",
    "PppFrameCodec",
    "Protocol",
    "SeqPolicy",
    "AutoField",
    "Data",
    "pack",
    "build_device_frame",
    "build_head_device_frame",
    "build_ppp_frame",
    "compile_rules",
    "crc16_ccitt",
    "crc16_modbus",
    "crc16_x25",
    "crc8",
    "escape_bytes",
    "find_end_delimiter",
    "sum8",
    "unescape_bytes",
    "wrap_frame",
    "xor8",
]
