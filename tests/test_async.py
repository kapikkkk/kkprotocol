# -*- coding: utf-8 -*-
"""异步接口：read_frames / iter_frames / feed_async（含线程池分发与并发串行化）。"""

from __future__ import annotations

import asyncio
import unittest

from kkprotocol import DeviceFrameCodec, PppFrameCodec, build_device_frame, build_ppp_frame


class FakeReader:
    """模拟 asyncio.StreamReader：按给定块返回，耗尽后返回 b""。"""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.reads = 0

    async def read(self, size: int) -> bytes:
        self.reads += 1
        await asyncio.sleep(0)
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class IdleReader:
    """先吐数据，之后"卡住"（读请求挂住直到被 wait_for 取消），第 n 次才 EOF。"""

    def __init__(self, chunks, idle: float = 5.0, max_stalls: int = 3):
        self._chunks = list(chunks)
        self._idle = idle
        self._stalls = 0
        self._max_stalls = max_stalls
        self.reads = 0

    async def read(self, size: int) -> bytes:
        self.reads += 1
        if self._chunks:
            await asyncio.sleep(0)
            return self._chunks.pop(0)
        self._stalls += 1
        if self._stalls >= self._max_stalls:
            return b""
        await asyncio.sleep(self._idle)  # 会被 wait_for 取消
        return b""


async def aiter_of(items):
    for item in items:
        await asyncio.sleep(0)
        yield item


class TestReadFrames(unittest.IsolatedAsyncioTestCase):
    async def test_read_frames_reassembles_frames(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame(cmd=1, payload=b"a") + build_device_frame(
            cmd=2, payload=b"bb"
        )
        reader = FakeReader([raw[:5], raw[5:20], raw[20:]])
        frames = [frame async for frame in codec.read_frames(reader, chunk_size=8)]
        self.assertEqual([f.value("cmd") for f in frames], [1, 2])
        self.assertEqual(codec.pending_bytes, b"")

    async def test_read_frames_stops_at_eof(self):
        frames = [frame async for frame in DeviceFrameCodec().read_frames(FakeReader([]))]
        self.assertEqual(frames, [])

    async def test_read_frames_keeps_partial_then_finishes(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame(payload=b"abcdef")
        reader = FakeReader([raw[:6], raw[6:]])
        frames = [frame async for frame in codec.read_frames(reader)]
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"abcdef")

    async def test_iter_frames_with_delimiter_codec(self):
        codec = PppFrameCodec()
        raw = build_ppp_frame(payload=b"async \x7e")
        frames = [
            frame async for frame in codec.iter_frames(aiter_of([raw[:4], raw[4:9], raw[9:]]))
        ]
        self.assertEqual([f.value("data") for f in frames], [b"async \x7e"])

    async def test_idle_timeout_drops_partial_frame(self):
        """空闲超时 → 丢半包；之后的整帧照常解析（帧中间接入的兜底）。"""
        codec = DeviceFrameCodec()
        codec.idle_timeout = 0.01
        raw = build_device_frame(payload=b"ok")
        reader = IdleReader([raw[:4], raw])
        frames = [frame async for frame in codec.read_frames(reader)]
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].value("data"), b"ok")
        self.assertEqual(codec.pending_bytes, b"")
        self.assertGreaterEqual(codec.stats.resyncs, 1)

    async def test_idle_timeout_can_keep_partial(self):
        codec = DeviceFrameCodec()
        codec.idle_timeout = 0.01
        codec.drop_pending_on_idle = False
        raw = build_device_frame(payload=b"half")
        reader = IdleReader([raw[:4]])
        frames = [frame async for frame in codec.read_frames(reader)]
        self.assertEqual(frames, [])
        self.assertEqual(codec.pending_bytes, raw[:4])
        self.assertEqual(codec.stats.resyncs, 0)


class TestFeedAsync(unittest.IsolatedAsyncioTestCase):
    async def test_small_chunk_uses_sync_path(self):
        codec = DeviceFrameCodec()
        raw = build_device_frame()
        self.assertLess(len(raw), codec.offload_threshold)
        frames = await codec.feed_async(raw)
        self.assertEqual(len(frames), 1)

    async def test_large_chunk_offloads_to_thread(self):
        codec = DeviceFrameCodec()
        codec.offload_threshold = 1
        frames = await codec.feed_async(build_device_frame(cmd=5))
        self.assertEqual([f.value("cmd") for f in frames], [5])

    async def test_offload_accepts_memoryview(self):
        codec = DeviceFrameCodec()
        codec.offload_threshold = 1
        frames = await codec.feed_async(memoryview(build_device_frame()))
        self.assertEqual(len(frames), 1)

    async def test_concurrent_offload_is_serialized(self):
        codec = DeviceFrameCodec()
        codec.offload_threshold = 0
        raw = build_device_frame()
        results = await asyncio.gather(*(codec.feed_async(raw) for _ in range(5)))
        self.assertEqual(sum(len(result) for result in results), 5)
        self.assertEqual(codec.stats.frames, 5)
        self.assertEqual(codec.pending_bytes, b"")

    async def test_offload_byte_by_byte_keeps_order(self):
        codec = DeviceFrameCodec()
        codec.offload_threshold = 0
        raw = b"".join(build_device_frame(cmd=index) for index in range(3))
        frames = []
        for index in range(len(raw)):
            frames.extend(await codec.feed_async(raw[index:index + 1]))
        self.assertEqual([f.value("cmd") for f in frames], [0, 1, 2])
        self.assertEqual(codec.pending_bytes, b"")

    async def test_async_and_sync_can_mix(self):
        codec = DeviceFrameCodec()
        self.assertEqual(len(codec.feed(build_device_frame(cmd=1))), 1)
        frames = await codec.feed_async(build_device_frame(cmd=2))
        self.assertEqual([f.value("cmd") for f in frames], [2])


if __name__ == "__main__":
    unittest.main(verbosity=2)
