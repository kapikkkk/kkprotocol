# -*- coding: utf-8 -*-
"""NMEA-0183（GPS/船舶导航文本语句）。

帧结构（分隔符定界，纯文本）：::

    '$'  <语句体，逗号分隔字段>  '*'  <XX 校验和（2 hex）>  CR LF

要点（压测点）：

* 完全是**文本记录**协议：字段靠逗号分隔、校验和嵌在 ``*XX`` 里，不是固定字节布局；
* 库是字节/字段级模型，对这种“分隔符内再嵌文本 + 内联校验和”的形态，靠一个 ``rest``
  字段把整段拿到手，再在外面（或 crc_imp 里）做 XOR 校验；说明库对纯文本记录协议
  只有“半原生”支持（能切帧，但字段解析得自己来）；
* 校验和是 ``$`` 与 ``*`` 之间所有字符的异或，落在帧内而非帧尾。

和 Modbus ASCII 一起，代表“分隔符定界 + 文本/ASCII 编码”这一类协议，测库对非二进制
协议的包容度。
"""
from __future__ import annotations

from ..framing import DelimiterFraming, wrap_frame
from ..spec import Field, FrameSpec

NMEA = DelimiterFraming(start=0x24, end=0x0A)  # '$' ... '\n'


SPEC = FrameSpec(
    fields=[Field.rest("body", desc="语句体 + '*XX' 校验和")],
    framing=NMEA,
    desc="NMEA-0183",
)


def codec():
    return SPEC.to_codec()


def sentence_checksum(text: str) -> int:
    """'$' 与 '*' 之间字符的异或。"""
    x = 0
    for ch in text:
        x ^= ord(ch)
    return x


def build(sentence: str) -> bytes:
    """组一条 NMEA 语句（sentence 不含 '$'/'*XX'/CRLF，如 'GPGGA,....'）。"""
    cks = sentence_checksum(sentence).to_bytes(1, "big").hex().upper()
    body = (sentence + "*" + cks + "\r").encode("ascii")
    return wrap_frame(body, NMEA)


def decode(body: bytes):
    """解析 body：返回 (语句体, 校验和是否通过)。"""
    text = body.replace(b"\r", b"").decode("ascii")
    if "*" not in text:
        raise ValueError("缺少 '*' 校验和分隔符")
    payload, cks = text.split("*", 1)
    return payload, sentence_checksum(payload) == int(cks, 16)
