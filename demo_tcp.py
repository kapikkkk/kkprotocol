# -*- coding: utf-8 -*-
"""端到端示例：同一套解析器接两种定界的设备，全部跑在真实 asyncio TCP 上。

运行：
    python demo_tcp.py

要点：
* ``codec`` 是**每个连接一个实例**（解析进度属于连接状态）；
* ``async for frame in codec.read_frames(reader)`` 直接把 asyncio 流变成帧迭代器；
* 长度定界不需要转义；分隔符定界自动处理转义，长度字段只当校验项。
"""

from __future__ import annotations

import asyncio
import random

from kkprotocol import (
    DeviceFrameCodec,
    PppFrameCodec,
    build_device_frame,
    build_ppp_frame,
)


async def _send_in_chunks(writer, stream: bytes, seed: int) -> None:
    """随机切分写入，模拟 MSS/拥塞窗口造成的任意边界。"""
    random.seed(seed)
    pos = 0
    while pos < len(stream):
        step = random.randint(1, 40)
        writer.write(stream[pos:pos + step])
        await writer.drain()
        pos += step
        await asyncio.sleep(0)


async def run_demo(name: str, codec_factory, stream: bytes, expected: int) -> None:
    received = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        codec = codec_factory()
        print("[{}] 连接建立".format(name))
        async for frame in codec.read_frames(reader):
            received.append(frame)
            print("[{}] 定界={} 帧长={:<3} 设备={!r} 载荷={!r}".format(
                name, frame.framing, len(frame), frame.device_id, frame.value("data")))
        print("[{}] 连接关闭 统计: {}".format(name, codec.stats))
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    await _send_in_chunks(writer, stream, seed=7)
    await asyncio.sleep(0.05)
    writer.close()
    server.close()
    await server.wait_closed()

    assert len(received) == expected, "期望 {} 帧，实际 {}".format(expected, len(received))
    print("[{}] 校验通过：{} 帧全部还原\n".format(name, len(received)))


async def main() -> None:
    # 一、长度定界：前面塞脏数据 + 一个伪造帧头
    length_stream = b"\xde\xad"
    for cmd in range(4):
        length_stream += build_device_frame(cmd=cmd, payload=bytes([0x40 + cmd]) * (cmd * 3))
        if cmd == 1:
            length_stream += b"\x55\x03"          # 伪造帧头，结构不合法
    await run_demo("长度定界", DeviceFrameCodec, length_stream, expected=4)

    # 二、分隔符定界：净荷里故意带 0x7E/0x7D，靠转义保证不被切开
    ppp_stream = b"\x11\x22"
    for payload in (b"plain", b"with \x7e flag", b"with \x7d escape", b""):
        ppp_stream += build_ppp_frame(payload=payload)
    await run_demo("分隔符定界", PppFrameCodec, ppp_stream, expected=4)


if __name__ == "__main__":
    asyncio.run(main())
