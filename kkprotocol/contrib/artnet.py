# -*- coding: utf-8 -*-
"""Art-Net（舞台灯光 UDP 协议，这里取它的以太网头部做压测）。

Art-Net 报文以 **8 字节字符串 magic** ``"Art-Net\\0"`` 开头，然后是操作码、版本号等：:

    "Art-Net\0"  OpCode(2, 小端)  ProtVer(2, 大端)  TalkToMe(1)  Priority(1) ...

要点（压测点）：

* 同步标记是**多字节字符串** ``b"Art-Net\\0"``，而不是单字节标志。
  库的长度定界支持把 ``sync`` 配成多字节（``AbstractFrameCodec.sync = b"Art-Net\\x00"``），
  这点设计是够用的——这正好补上“DelimiterFraming.start 只支持单字节”的反例：
  **多字节 magic 走长度定界的 sync 就行，只有分隔符定界才卡在单字节**。
* 这里是 UDP，长度由 IP 层给出，所以帧内没有长度定界字段，仅靠固定头部长度 + magic。

说明：只解析前 14 字节的 ArtPoll 头部（magic + opcode + version + talktome + priority），
足以验证多字节同步；完整 ArtDmx 的 512 字节数据段不在此建模。
"""
from __future__ import annotations

from ..codec import AbstractFrameCodec, LENGTH_FRAMING
from ..spec import Field


class ArtNetCodec(AbstractFrameCodec):
    # 多字节同步标记：这是“长度定界”支持、但“分隔符定界”的 start/end 不支持的能力
    sync = b"Art-Net\x00"
    framing = LENGTH_FRAMING
    max_frame_size = 1024

    def rules(self):
        return [
            Field.raw("magic", 8, fixed=b"Art-Net\x00"),
            Field.u16("opcode", little_endian=True),
            Field.u16("version", little_endian=False),
            Field.u8("talktome"),
            Field.u8("priority"),
        ]

    def crc_imp(self, data):
        return 0


def build_artpoll(version: int = 14, talktome: int = 0, priority: int = 0) -> bytes:
    """组一条最小的 ArtPoll 头部（操作码 0x2000）。"""
    return (
        b"Art-Net\x00"
        + (0x2000).to_bytes(2, "little")
        + version.to_bytes(2, "big")
        + bytes([talktome, priority])
    )


def codec() -> AbstractFrameCodec:
    return ArtNetCodec()
