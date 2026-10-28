# -*- coding: utf-8 -*-
"""Modbus ASCII（Modbus 的 ASCII 传输模式，与 RTU 同语义但用文本 hex 编码）。

帧结构（分隔符定界）：::

    ':'  <hex 对：地址 功能码 数据...>  <LRC(2 hex)>  CR LF

要点（压测点）：

* 协议**帧内载荷是 ASCII 十六进制文本**，每个字节用两个字符表示；库是字节级解析，
  没有“先按 ASCII-Hex 解码”的传输层原语 —— 这里在组帧/解析后手动 hex 编解码，
  说明库缺一个“传输编码（ASCII-Hex / Base64 / …）”钩子；
* LRC 是地址..数据累加和的两补码（取低 8 位），落在帧内、以 2 个 hex 字符表示；
* 分隔符是 ``':'`` 开头、``'\\n'`` 结尾（中间带 ``'\\r'``），无转义。

和 Modbus RTU（见 example_modbus_rtu / example_modbus_rtu_multi）对照：同一套应用语义，RTU 用二进制 + CRC16，
ASCII 用文本 + LRC，正好测“同协议不同传输编码”库能否分开表达。
"""
from __future__ import annotations

from ..crc import sum8
from ..framing import DelimiterFraming, wrap_frame
from ..spec import Field, FrameSpec

ASCII = DelimiterFraming(start=0x3A, end=0x0A)  # ':' ... '\n'


SPEC = FrameSpec(
    fields=[Field.rest("body", desc="ASCII-Hex 文本（地址/功能码/数据/LRC）")],
    framing=ASCII,
    desc="Modbus ASCII",
)


def codec():
    return SPEC.to_codec()


def lrc(bytes_: bytes) -> int:
    """Modbus ASCII LRC：地址..数据的累加和的两补码（低 8 位）。"""
    return (-sum8(bytes_)) & 0xFF


def build(addr: int, func: int, data: bytes = b"") -> bytes:
    """组一条 Modbus ASCII 帧（data 为应用层二进制字节）。"""
    payload = bytes([addr, func]) + data
    hexstr = payload.hex() + lrc(payload).to_bytes(1, "big").hex()
    # 加 ':' 与 '\\n'，并保留结尾前的 '\\r'
    return wrap_frame((hexstr + "\r").encode("ascii"), ASCII)


def decode(body: bytes):
    """解析 body：返回 (addr, func, data)，并校验 LRC。"""
    text = body.replace(b"\r", b"").decode("ascii")
    raw = bytes.fromhex(text)
    pdu, lrc_byte = raw[:-1], raw[-1]
    if lrc(pdu) != lrc_byte:
        raise ValueError("LRC 校验失败")
    return pdu[0], pdu[1], pdu[2:]
