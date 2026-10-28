# -*- coding: utf-8 -*-
"""两个可直接运行的示例帧，也是写自己协议时的参考模板。

一、长度定界（推荐，TCP 场景首选）::

    55 | len | ver | cmd | ser(2) | dev_id(4) | data(len-10) | crc(2)
    len = ver..crc 的总字节数；crc = CRC16/MODBUS(len..data)，大端

二、分隔符定界（PPP/HDLC 风格，串口/透传设备常见）::

    7E | ff 03 | len | dev_id(4) | data(len) | fcs(2) | 7E
    净荷中的 7E/7D 分别转义为 7D 5E / 7D 5D；fcs = CRC16/X-25(ff03..data)
    len 只是参考值，真正切帧靠 7E —— 净荷里出现 7E 也不会误判。

三、帧首就是设备号（没有固定帧头，设备号首帧未知）::

    dev_id(4) | cmd | n | data(n) | crc(2)

    设备号只在首帧/注册包未知，学到后就固定，因此把它当同步字用，
    详见 :class:`HeadDeviceFrameCodec`。
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Sequence, Union

from .codec import AbstractFrameCodec
from .crc import crc16_modbus, crc16_x25
from .fields import Field
from .framing import DelimiterFraming, wrap_frame

__all__ = [
    "DEVICE_FIELDS",
    "HEAD_DEVICE_FIELDS",
    "HEADER",
    "PPP_FLAG",
    "PPP_ESCAPE",
    "DeviceFrameCodec",
    "HeadDeviceFrameCodec",
    "PppFrameCodec",
    "build_device_frame",
    "build_head_device_frame",
    "build_ppp_frame",
]

HEADER = 0x55
PPP_FLAG = 0x7E
PPP_ESCAPE = 0x7D
PPP_ADDRESS = 0xFF
PPP_CONTROL = 0x03

DEVICE_FIELDS: List[Field] = [
    Field.u8("header", fixed=HEADER, desc="帧头"),
    Field.u8("len", desc="ver..crc 的总字节数"),
    Field.u8("ver", desc="协议版本"),
    Field.u8("cmd", desc="命令字"),
    Field.u16("ser", desc="序列号"),
    Field.raw("dev_id", 4, desc="设备号"),
    Field.raw("data", "{len.val}-10", desc="变长净荷"),
    Field.checksum("crc", 2, group="{len}{ver}{cmd}{ser}{dev_id}{data}", desc="CRC16/MODBUS"),
]

PPP_FIELDS: List[Field] = [
    Field.u8("addr", fixed=PPP_ADDRESS),
    Field.u8("ctrl", fixed=PPP_CONTROL),
    Field.u8("len", desc="净荷长度，仅作校验"),
    Field.raw("dev_id", 4, desc="设备号"),
    Field.raw("data", "{len.val}", desc="变长净荷"),
    Field.checksum("fcs", 2, group="{addr}{ctrl}{len}{dev_id}{data}", desc="CRC16/X-25"),
]

HEAD_DEVICE_FIELDS: List[Field] = [
    Field.raw("dev_id", 4, desc="设备号（帧首，首帧未知）"),
    Field.u8("cmd", desc="命令字"),
    Field.u8("n", desc="净荷字节数"),
    Field.raw("data", "{n.val}", desc="净荷"),
    Field.checksum("crc", 2, group="{dev_id}{cmd}{n}{data}", desc="CRC16/MODBUS"),
]


class DeviceFrameCodec(AbstractFrameCodec):
    """长度定界示例：按 ``len`` 字段切帧，自动处理黏包/半包/脏数据。"""

    device_field = "dev_id"

    def rules(self) -> Sequence[Union[Field, Dict[str, Any]]]:
        return DEVICE_FIELDS

    def crc_imp(self, data: bytes) -> int:
        return crc16_modbus(data)


def build_device_frame(
    ver: int = 1,
    cmd: int = 0x03,
    ser: int = 1,
    dev_id: bytes = b"\x00\x00\x00\x01",
    payload: bytes = b"\x01\x02",
    bad_crc: bool = False,
) -> bytes:
    """按 :class:`DeviceFrameCodec` 的规则构造一帧（测试与模拟设备用）。"""
    body = struct.pack("!BBH4s", ver, cmd, ser, dev_id) + payload
    length = len(body) + 2
    crc = crc16_modbus(bytes([length]) + body)
    if bad_crc:
        crc ^= 0xFFFF
    return bytes([HEADER, length]) + body + struct.pack("!H", crc)


class HeadDeviceFrameCodec(AbstractFrameCodec):
    """帧首就是设备号、没有固定帧头的示例（设备号首帧未知，之后固定）。

    这是"设备号打头"这类私有协议的标准配置：

    * ``sync_from_device``：学到设备号后拿它当同步字，重同步从"逐字节试探"
      变成"一次跳转"；
    * ``lock_device_after_learn``：学到即固定，之后设备号不符的帧按脏数据丢掉
      （多设备挂在同一条总线上时请关掉，改为看 ``frame.device_mismatch``）；
    * ``max_frame_size``：取略大于真实最大帧（n 是 u8，最大 255+8），
      假长度一旦超过它就立刻被判死，不至于把缓冲区堵住；
    * ``preempt_on_sync``：默认关。开启后，若候选帧还在等长度、但它区间内已经
      出现"完整且校验通过"的帧，就用锚点切断——这是长度定界下唯一能救回
      "被假长度堵住的后续真帧"的手段，代价是载荷里恰好出现锚点字节串时可能误切；
    * ``idle_timeout``：``read_frames`` 空闲 5 秒就把半包丢掉（TCP 建连瞬间
      从帧中间接入时的兜底）。
    """

    device_field = "dev_id"
    max_frame_size = 300
    sync_from_device = True
    lock_device_after_learn = True
    preempt_on_sync = False
    idle_timeout = 5.0

    def rules(self) -> Sequence[Union[Field, Dict[str, Any]]]:
        return HEAD_DEVICE_FIELDS

    def crc_imp(self, data: bytes) -> int:
        return crc16_modbus(data)


def build_head_device_frame(
    dev_id: bytes = b"\x00\x00\x00\x01",
    cmd: int = 0x01,
    payload: bytes = b"ping",
    bad_crc: bool = False,
) -> bytes:
    """按 :class:`HeadDeviceFrameCodec` 的规则构造一帧。"""
    body = dev_id + bytes([cmd, len(payload)]) + payload
    crc = crc16_modbus(body)
    if bad_crc:
        crc ^= 0xFFFF
    return body + struct.pack("!H", crc)


class PppFrameCodec(AbstractFrameCodec):
    """分隔符定界示例：0x7E 首尾定界 + 0x7D 转义，长度字段仅作校验项。"""

    framing = DelimiterFraming(
        end=PPP_FLAG, start=PPP_FLAG, escape=PPP_ESCAPE, escape_xor=0x20
    )
    device_field = "dev_id"

    def rules(self) -> Sequence[Union[Field, Dict[str, Any]]]:
        return PPP_FIELDS

    def crc_imp(self, data: bytes) -> int:
        return crc16_x25(data)


def build_ppp_frame(
    dev_id: bytes = b"\x00\x00\x00\x01",
    payload: bytes = b"ping",
    bad_fcs: bool = False,
    declared_length: Optional[int] = None,
    spec: Optional[DelimiterFraming] = None,
) -> bytes:
    """按 :class:`PppFrameCodec` 的规则构造一帧（含转义）。"""
    spec = spec or PppFrameCodec.framing
    length = len(payload) if declared_length is None else declared_length
    body = bytes([PPP_ADDRESS, PPP_CONTROL, length]) + dev_id + payload
    fcs = crc16_x25(body)
    if bad_fcs:
        fcs ^= 0xFFFF
    return wrap_frame(body + struct.pack("!H", fcs), spec)
