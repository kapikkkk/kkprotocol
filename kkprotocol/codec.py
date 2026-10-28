# -*- coding: utf-8 -*-
"""编解码器基类：自适应定界 + 异步接口 + 设备号学习。

子类只需要提供两样东西::

    class MyCodec(AbstractFrameCodec):
        framing = LENGTH_FRAMING           # 或 DelimiterFraming(...) / AUTO_FRAMING
        def rules(self):  return [ Field.u8("header", fixed=0x55), ... ]
        def crc_imp(self, data): return crc16_modbus(data)

三种定界方式：

* ``LENGTH_FRAMING``（默认）：按长度字段切帧，不需要转义。
* ``DelimiterFraming(...)``：按分隔符切帧，自动处理字节转义；长度字段退化为校验项。
* ``AUTO_FRAMING`` + ``delimiter=DelimiterFraming(...)``：先用长度切帧试探，
  失败再试分隔符，命中后锁定（``lock_framing=False`` 可关闭锁定）。

线程/协程安全：**一个连接一个实例**。``feed()`` 是同步纯内存操作；
``feed_async()`` 在大块数据时把解析丢到线程池，避免阻塞事件循环；
``read_frames()`` / ``iter_frames()`` 直接对接 asyncio 流。

帧首不是固定帧头、而是**设备号**（设备号首次未知）时的处理：:

    class MyCodec(AbstractFrameCodec):
        device_field = "dev_id"              # 声明哪一个是设备号
        auto_learn_device = True             # 首帧/注册包学到就记住
        lock_device_after_learn = True       # 学到即固定（不符的帧按脏数据丢）
        sync_from_device = True              # 学到的设备号兼作重同步锚点
        preempt_on_sync = True               # 假长度堵住后续真帧时用锚点切断
        idle_timeout = 5.0                   # 空闲超时丢半包（read_frames）

生命周期：**未知 → 学到 → 固定成锚点**。未知阶段没有任何内容可依，
从帧中间接入只能等声明的长度凑够后由 CRC 否证；学到之后设备号本身
就是最强的同步字，重同步从"逐字节试探"变成"一次跳转"。
"""

from __future__ import annotations

import asyncio
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, replace
from typing import (
    Any,
    AsyncIterable,
    AsyncIterator,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from .compiler import CompiledField, compile_rules
from .errors import FrameCodecError, FrameInvalid, FrameRuleError
from .fields import Field
from .frame import FieldValue, Frame
from .framing import (
    AUTO_FRAMING,
    DELIMITER_FRAMING,
    FRAMING_MODES,
    LENGTH_FRAMING,
    DelimiterFraming,
    find_end_delimiter,
    unescape_bytes,
)
from .length import LengthExpr

__all__ = ["AbstractFrameCodec", "CodecStats"]


@dataclass
class CodecStats:
    """运行期统计，便于接入监控告警。"""

    bytes_in: int = 0
    frames: int = 0
    resyncs: int = 0
    crc_errors: int = 0
    length_mismatches: int = 0
    device_mismatches: int = 0
    rejected_frames: int = 0
    dropped_bytes: int = 0
    overflow_drops: int = 0


@dataclass
class _ParsedFields:
    fields: Dict[str, FieldValue]
    end: int
    device_id: Any
    device_mismatch: bool


def _device_equal(known: Any, fv: FieldValue) -> bool:
    """比较已知设备号与字段值，兼容 int / bytes 两种表示。"""
    if isinstance(known, (bytes, bytearray, memoryview)):
        return bytes(known) == fv.raw
    if isinstance(known, int) and not isinstance(known, bool):
        if isinstance(fv.val, int):
            return known == fv.val
        return known == int.from_bytes(fv.raw, "big")
    return known == fv.val


class AbstractFrameCodec(metaclass=ABCMeta):
    """TCP 流式帧解析器基类。"""

    # ---- 定界 ---------------------------------------------------------------
    framing: Union[str, DelimiterFraming] = LENGTH_FRAMING
    delimiter: Optional[DelimiterFraming] = None
    sync: Optional[Union[bytes, int]] = None
    lock_framing: bool = True

    # ---- 限制与策略 ---------------------------------------------------------
    max_frame_size: int = 64 * 1024
    max_buffer: int = 1024 * 1024
    on_crc_error: str = "resync"

    # ---- 设备号 -------------------------------------------------------------
    device_field: Optional[str] = None
    auto_learn_device: bool = True
    enforce_device_id: bool = False
    device_id_provider: Optional[Callable[[], Any]] = None
    # 设备号只在首帧/注册包未知，之后基本固定：
    #   lock_device_after_learn=True 时，学到即锁定（等价于自动打开 enforce_device_id）
    #   sync_from_device=True 时，学到的设备号兼作重同步锚点（长度 ≥2 才启用）
    lock_device_after_learn: bool = False
    sync_from_device: bool = True
    # 帧内出现同步锚点且该处已经是一个"完整且校验通过"的帧时，判定前面的候选是脏数据
    # 并直接跳过去。长度定界下这是唯一能救回"被假长度堵住的后续真帧"的手段，
    # 代价是若载荷里恰好出现锚点字节串 + 校验通过的帧，会被误切（概率极低）。
    preempt_on_sync: bool = False

    # ---- 异步 ---------------------------------------------------------------
    offload_threshold: int = 256 * 1024
    idle_timeout: Optional[float] = None
    drop_pending_on_idle: bool = True

    # ------------------------------------------------------------------ 抽象
    @abstractmethod
    def rules(self) -> Sequence[Union[Field, Dict[str, Any]]]:
        """返回字段规则列表，顺序即帧内字节顺序。推荐用 ``Field`` 字段类。"""
        raise NotImplementedError

    @abstractmethod
    def crc_imp(self, data: bytes) -> Union[int, bytes]:
        """校验实现，返回 int（与字段数值比较）或 bytes（与字段原始字节比较）。"""
        raise NotImplementedError

    # ------------------------------------------------------------------ 生命周期
    def __init__(self) -> None:
        self._buf = bytearray()
        self._compiled: Optional[List[CompiledField]] = None
        self._delimiter_spec: Optional[DelimiterFraming] = None
        self._mode: Optional[str] = None
        self._auto = False
        self._sync: bytes = b""
        # 一帧多校验和：字段 key -> 校验实现；命中即用各自算法，否则回落到 crc_imp
        self._crc_impls: Dict[str, Callable[[bytes], Any]] = {}
        self._device_id: Any = None
        self._lock_obj: Optional[asyncio.Lock] = None
        self.stats = CodecStats()

    def compile(self) -> None:
        """提前编译并校验规则（建议启动时调用，把配置错误暴露在启动期）。"""
        self._ensure_compiled()

    def reset(self) -> None:
        """丢弃未完成的半包数据（连接重建时调用）。统计信息保留。"""
        self._buf.clear()

    def drop_pending(self) -> int:
        """丢弃缓冲区里尚未成帧的字节，返回丢弃数量。

        长度定界且帧首没有固定帧头时，"从帧中间开始的数据"无法靠内容识别
        （只能等声明的长度凑够后由 CRC 否证）。连接空闲、设备重连或人工判定
        卡死时调用本方法，直接把这一小段脏数据丢掉，从下一个字节重新对齐。
        """
        dropped = len(self._buf)
        if dropped:
            self._buf.clear()
            self.stats.dropped_bytes += dropped
            self.stats.resyncs += 1
        return dropped

    def reset_framing(self) -> None:
        """清除 auto 模式的探测结果，重新开始探测。"""
        if self._auto:
            self._mode = None

    @property
    def pending_bytes(self) -> bytes:
        """缓冲区中尚未消费的字节（半包内容），便于排查。"""
        return bytes(self._buf)

    @property
    def framing_mode(self) -> Optional[str]:
        """当前生效的定界方式；``auto`` 尚未探测成功时为 ``None``。"""
        return self._mode

    # ------------------------------------------------------------------ 设备号
    @property
    def device_id(self) -> Any:
        """已绑定的设备号；``None`` 表示未知（此时不校验设备字段）。"""
        return self._device_id

    @device_id.setter
    def device_id(self, value: Any) -> None:
        self._device_id = value

    def bind_device(self, device_id: Any) -> None:
        """绑定设备号：之后该字段会按此值校验。"""
        self._device_id = device_id
        self._refresh_sync()

    def forget_device(self) -> None:
        """解绑设备号（换设备/重新注册时调用），之后可再次自动学习。"""
        self._device_id = None
        self._reset_sync()

    def _pull_device_from_provider(self) -> None:
        """设备号未知时，从外部来源（注册表/缓存/DB）拉取一次。"""
        if self._device_id is None and self.device_id_provider is not None:
            value = self.device_id_provider()
            if value is not None:
                self._device_id = value
                self._refresh_sync()

    def _refresh_sync(self) -> None:
        """设备号已知且位于帧首时，把它当作重同步锚点。

        帧首不是固定帧头而是设备号时，本来推不出任何锚点（``_sync`` 为空，
        重同步只能逐字节试探）。但设备号通常只在首帧未知，学到后长期不变，
        此时它比固定帧头更有辨识度，天然适合做锚点。
        """
        if not self.sync_from_device or self.sync is not None:
            return
        compiled = self._compiled
        if not compiled or self._mode == DELIMITER_FRAMING:
            return
        first = compiled[0]
        if not first.is_device:
            return
        anchor = _anchor_bytes(self._device_id, first)
        if anchor is not None and len(anchor) >= 2:
            self._sync = anchor

    def _reset_sync(self) -> None:
        """设备号被解绑后，把锚点退回编译期的推导结果。"""
        compiled = self._compiled
        if compiled and self._mode != DELIMITER_FRAMING:
            self._sync = self._resolve_sync(compiled[0])
        else:
            self._sync = b""

    # ------------------------------------------------------------------ 业务钩子
    def on_frame(self, frame: Frame) -> bool:
        """帧级过滤钩子，返回 False 表示丢弃该帧（字节已被消费，不影响后续解析）。"""
        return True

    def on_device_learned(self, device_id: Any, frame: Frame) -> None:
        """学到新设备号时的回调（落库/日志/白名单校验等），默认不做任何事。"""
        return None

    # ------------------------------------------------------------------ 同步入口
    def feed(self, data: Union[bytes, bytearray, memoryview]) -> List[Frame]:
        """喂入任意切分的数据块，返回本次能完整解析出的帧（可能为空列表）。"""
        if isinstance(data, memoryview):
            data = data.tobytes()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("feed() 只接受 bytes / bytearray / memoryview")
        if not data:
            return []

        self._ensure_compiled()
        self._pull_device_from_provider()
        self.stats.bytes_in += len(data)
        self._buf += data
        return self._drain()

    def filter(self, data: Union[bytes, bytearray, memoryview]) -> List[Frame]:
        """``feed`` 的别名，兼容旧命名。"""
        return self.feed(data)

    # ------------------------------------------------------------------ 异步入口
    async def feed_async(self, data: Union[bytes, bytearray, memoryview]) -> List[Frame]:
        """异步喂数据。

        小数据块直接同步解析（解析是纯内存操作，比线程调度快几个数量级）；
        超过 ``offload_threshold`` 才丢线程池，避免单个巨帧阻塞事件循环。
        """
        if isinstance(data, memoryview):
            data = data.tobytes()
        if len(data) < self.offload_threshold:
            return self.feed(data)
        if self._lock_obj is None:
            self._lock_obj = asyncio.Lock()
        async with self._lock_obj:
            return await asyncio.to_thread(self.feed, data)

    async def read_frames(
        self, reader: Any, chunk_size: int = 4096
    ) -> AsyncIterator[Frame]:
        """从 asyncio 流（``StreamReader`` 或任何有 ``await read(n)`` 的对象）持续读帧。

        设置 ``idle_timeout`` 后，读超时即视为"这条连接上没有更多数据了"：
        残留半包直接丢弃（Modbus RTU 用帧间空闲时间定界，思路相同），
        避免一段脏数据把后续所有真帧长期堵在缓冲区里。
        """
        while True:
            if self.idle_timeout is None:
                chunk = await reader.read(chunk_size)
            else:
                try:
                    chunk = await asyncio.wait_for(reader.read(chunk_size), self.idle_timeout)
                except asyncio.TimeoutError:
                    if self.drop_pending_on_idle:
                        self.drop_pending()
                    continue
            if not chunk:
                return
            for frame in await self.feed_async(chunk):
                yield frame

    async def iter_frames(self, chunks: AsyncIterable[bytes]) -> AsyncIterator[Frame]:
        """从任意异步字节块迭代器读帧。"""
        async for chunk in chunks:
            for frame in await self.feed_async(chunk):
                yield frame

    # ------------------------------------------------------------------ 主循环
    def _drain(self) -> List[Frame]:
        frames: List[Frame] = []
        pos = 0
        size = len(self._buf)
        while pos < size:
            try:
                parsed = self._parse_at(pos)
            except FrameInvalid as exc:
                self._handle_invalid(exc, pos)
                if exc.crc_failed:
                    self.stats.crc_errors += 1
                if exc.length_mismatch:
                    self.stats.length_mismatches += 1
                self.stats.resyncs += 1
                new_pos = pos + exc.consumed if exc.consumed else self._find_next_sync(pos + 1)
                if new_pos <= pos:  # pragma: no cover - 防御：保证解析器前进
                    new_pos = pos + 1
                self.stats.dropped_bytes += new_pos - pos
                pos = new_pos
                continue
            if parsed is None:  # 半包，等下一次 feed
                break
            frame, consumed = parsed
            pos += consumed
            if frame is None:  # 只消费了帧间标志位，不产生帧
                continue
            accepted = self._post_process(frame)
            if accepted is None:
                self.stats.rejected_frames += 1
                continue
            frames.append(accepted)
            self.stats.frames += 1

        if pos:
            del self._buf[:pos]
        if len(self._buf) > self.max_buffer:
            excess = len(self._buf) - self.max_buffer
            del self._buf[:excess]
            self.stats.overflow_drops += 1
            self.stats.dropped_bytes += excess
        return frames

    def _handle_invalid(self, exc: FrameInvalid, pos: int) -> None:
        """预留钩子：需要把重同步原因写日志时覆盖它。"""
        return None

    def _post_process(self, frame: Frame) -> Optional[Frame]:
        if frame.device_mismatch:
            self.stats.device_mismatches += 1
        if not self.on_frame(frame):
            return None
        if (
            self.auto_learn_device
            and self._device_id is None
            and self.device_field is not None
            and frame.device_id is not None
        ):
            self._device_id = frame.device_id
            if self.lock_device_after_learn:
                # 设备号只在首帧未知，学到即固定：之后设备号不符的帧直接当脏数据
                self.enforce_device_id = True
            self._refresh_sync()
            frame = replace(frame, learned_device=True)
            self.on_device_learned(frame.device_id, frame)
        return frame

    # ------------------------------------------------------------------ 分派
    def _parse_at(self, pos: int) -> Optional[Tuple[Optional[Frame], int]]:
        mode = self._mode
        if mode == LENGTH_FRAMING:
            return self._parse_length(pos)
        if mode == DELIMITER_FRAMING:
            return self._parse_delimiter(pos)
        return self._parse_auto(pos)

    def _parse_auto(self, pos: int) -> Optional[Tuple[Optional[Frame], int]]:
        """自适应：长度定界优先，失败回退到分隔符定界，命中后锁定。"""
        length_result: Optional[Tuple[Optional[Frame], int]] = None
        length_error: Optional[FrameInvalid] = None
        try:
            length_result = self._parse_length(pos)
        except FrameInvalid as exc:
            length_error = exc
        if length_result is not None:
            self._lock_framing(LENGTH_FRAMING)
            return length_result

        delimiter_result: Optional[Tuple[Optional[Frame], int]] = None
        delimiter_error: Optional[FrameInvalid] = None
        try:
            delimiter_result = self._parse_delimiter(pos)
        except FrameInvalid as exc:
            delimiter_error = exc
        if delimiter_result is not None:
            self._lock_framing(DELIMITER_FRAMING)
            return delimiter_result

        # 只要有一方表示“数据不足”，就继续等：另一方判非法可能只是因为
        # 用错了定界方式去解读同一个半包，贸然丢数据会吞掉后面的真帧。
        if length_error is None or delimiter_error is None:
            return None
        raise length_error

    def _lock_framing(self, mode: str) -> None:
        if self.lock_framing:
            self._mode = mode

    # ------------------------------------------------------------------ 长度定界
    def _parse_length(self, pos: int) -> Optional[Tuple[Optional[Frame], int]]:
        parsed = self._parse_fields(self._buf, pos, allow_rest=False)
        if parsed is None:
            if self.preempt_on_sync:
                cut = self._preempt_offset(pos)
                if cut is not None:
                    # 前面这段声称的长度把后面的真帧一起吞了：判定为脏数据，跳过去
                    raise FrameInvalid(
                        "候选帧内出现同步锚点且锚点处已是完整帧", consumed=cut - pos
                    )
            return None
        raw = bytes(self._buf[pos:parsed.end])
        frame = Frame(
            raw=raw,
            fields=parsed.fields,
            wire=raw,
            framing=LENGTH_FRAMING,
            device_id=parsed.device_id,
            device_mismatch=parsed.device_mismatch,
        )
        return frame, parsed.end - pos

    # ------------------------------------------------------------------ 分隔符定界
    def _parse_delimiter(self, pos: int) -> Optional[Tuple[Optional[Frame], int]]:
        spec = self._delimiter_spec
        if spec is None:  # pragma: no cover - 编译期已保证
            raise FrameRuleError("未配置 DelimiterFraming")
        buf = self._buf
        size = len(buf)
        index = pos

        if spec.start is not None and spec.start != spec.end:
            # 帧头与帧尾不同：跳过帧头前的垃圾
            while index < size and buf[index] != spec.start:
                index += 1
            if index >= size:
                if size - pos > self.max_frame_size:
                    raise FrameInvalid(
                        "找不到帧头分隔符且积压超过 max_frame_size", consumed=size - pos
                    )
                return None
            wire_start = index
            content_start = index + 1
        elif spec.start is not None:
            # 首尾共用一个标志位（PPP/HDLC）：跳过前导标志
            wire_start = index
            while index < size and buf[index] == spec.end:
                index += 1
            if index >= size:
                # 只剩标志位：把它们消费掉，等下一条数据（帧间分隔符不是帧）
                return None, size - pos
            content_start = index
        else:
            wire_start = index
            content_start = index

        end_index = find_end_delimiter(buf, content_start, spec)
        if end_index is None:
            if size - pos > self.max_frame_size:
                raise FrameInvalid(
                    "分隔符帧超过 max_frame_size 仍未闭合", consumed=size - pos
                )
            return None

        wire_len = end_index + 1 - pos
        if wire_len > self.max_frame_size:
            raise FrameInvalid(
                "分隔符帧长度 {} 超过 max_frame_size".format(wire_len), consumed=wire_len
            )

        content = bytes(buf[content_start:end_index])
        try:
            raw = unescape_bytes(content, spec)
        except ValueError as exc:  # pragma: no cover - 扫描阶段已排除悬空转义
            raise FrameInvalid(str(exc), consumed=wire_len) from exc

        parsed = self._parse_fields(raw, 0, allow_rest=True)
        if parsed is None:
            # 定界符已经给出确切边界，此时“数据不足”只可能是长度字段与实际不符
            raise FrameInvalid(
                "声明长度与分隔符区间不一致（长度字段仅作校验项）",
                consumed=wire_len,
                length_mismatch=True,
            )
        if parsed.end != len(raw):
            raise FrameInvalid(
                "帧尾前仍有 {} 字节未被规则消费".format(len(raw) - parsed.end),
                consumed=wire_len,
                length_mismatch=True,
            )

        frame = Frame(
            raw=raw,
            fields=parsed.fields,
            wire=bytes(buf[wire_start:end_index + 1]),
            framing=DELIMITER_FRAMING,
            device_id=parsed.device_id,
            device_mismatch=parsed.device_mismatch,
        )
        return frame, wire_len

    # ------------------------------------------------------------------ 字段解析
    def _parse_fields(
        self, buf: Union[bytes, bytearray], start: int, allow_rest: bool
    ) -> Optional[_ParsedFields]:
        """按规则解析一段字节；字节不足返回 None（长度定界下即半包）。

        ``allow_rest`` 为 True 时允许 ``length=None`` 的“剩余长度”字段
        （只有分隔符定界能给出确定的帧边界）。
        """
        fields: Dict[str, FieldValue] = {}
        offset = start
        total = 0
        device_id: Any = None
        device_mismatch = False
        compiled = self._compiled or []

        for idx, cf in enumerate(compiled):
            if cf.length is None:
                if not allow_rest:
                    raise FrameInvalid(
                        "字段 {!r} 声明为“取到帧尾”，长度定界无法确定边界".format(cf.key)
                    )
                # 留出后续“定长尾字段”（如 HDLC/PPP 的 FCS）的空间，否则 rest
                # 会把尾部定长字段一并吞掉，导致它们永远解析不到。
                # 遇到非定长后续字段即停止预留（无法安全预留时退回原语义）。
                reserve = 0
                for nxt in compiled[idx + 1:]:
                    if isinstance(nxt.length, int):
                        reserve += nxt.length
                    else:
                        break
                length = len(buf) - offset - reserve
            else:
                length = self._resolve_length(cf, fields)
            if length < 0:
                raise FrameInvalid("字段 {!r} 计算出负长度 {}".format(cf.key, length))
            total += length
            if total > self.max_frame_size:
                raise FrameInvalid("帧长超过 max_frame_size={}".format(self.max_frame_size))

            end = offset + length
            if end > len(buf):
                return None

            if length == 0:
                if cf.struct is not None:
                    raise FrameInvalid(
                        "字段 {!r} 长度为 0 但声明了 fmt {!r}".format(cf.key, cf.fmt)
                    )
                raw = b""
                val: Any = b""
            else:
                raw = bytes(buf[offset:end])
                if cf.struct is not None:
                    # 长度表达式算出的字节数必须与 fmt 的字节数一致，否则视为脏数据
                    if cf.fmt_size is not None and cf.fmt_size != length:
                        raise FrameInvalid(
                            "字段 {!r} 长度 {} 与 fmt {!r} 不匹配".format(cf.key, length, cf.fmt)
                        )
                    val = cf.struct.unpack(raw)[0]
                else:
                    val = raw

            if cf.fixed is not None and not _fixed_matches(cf.fixed, val, raw):
                raise FrameInvalid("字段 {!r} 常量不匹配: {!r}".format(cf.key, val))

            fv = FieldValue(cf.key, raw, val)
            fields[cf.key] = fv
            offset = end

            if cf.is_device:
                device_id = raw if cf.struct is None else val
                if self._device_id is not None and not _device_equal(self._device_id, fv):
                    device_mismatch = True
                    if self.enforce_device_id:
                        raise FrameInvalid(
                            "设备号不匹配：期望 {!r}，收到 {!r}".format(self._device_id, val)
                        )

            if cf.is_crc and not self._verify_checksum(cf, fv, fields):
                consumed = 0
                if self.on_crc_error == "skip_frame" and compiled[-1] is cf:
                    consumed = total
                raise FrameInvalid(
                    "字段 {!r} 校验失败".format(cf.key),
                    consumed=consumed,
                    crc_failed=True,
                )

        return _ParsedFields(fields, offset, device_id, device_mismatch)

    # ------------------------------------------------------------------ 内部工具
    def _resolve_length(self, cf: CompiledField, fields: Dict[str, FieldValue]) -> int:
        length = cf.length
        if isinstance(length, int):
            return length
        if isinstance(length, LengthExpr):
            return length.evaluate(fields)
        try:
            value = length(fields)
        except FrameCodecError:
            raise
        except Exception as exc:  # 开发者的回调抛错 → 视为脏数据，不炸连接
            raise FrameInvalid("字段 {!r} 长度回调异常: {}".format(cf.key, exc)) from exc
        if isinstance(value, bool) or not isinstance(value, int):
            raise FrameInvalid("字段 {!r} 长度回调必须返回 int".format(cf.key))
        return int(value)

    def _verify_checksum(
        self, cf: CompiledField, fv: FieldValue, fields: Dict[str, FieldValue]
    ) -> bool:
        impl = self._crc_impls.get(cf.key, self.crc_imp)
        payload = b"".join(fields[key].raw for key in (cf.group_refs or ()))
        expected = impl(payload)
        if isinstance(expected, (bytes, bytearray, memoryview)):
            return bytes(expected) == fv.raw
        if isinstance(expected, bool) or not isinstance(expected, int):
            raise FrameRuleError(
                "crc_imp 必须返回 int 或 bytes，实际返回 {}".format(type(expected).__name__)
            )
        if isinstance(fv.val, int):
            return expected == fv.val
        return expected == int.from_bytes(fv.raw, cf.byteorder, signed=False)

    def _find_next_sync(self, start: int) -> int:
        size = len(self._buf)
        if start >= size:
            return size
        if self._mode == DELIMITER_FRAMING and self._delimiter_spec is not None:
            index = find_end_delimiter(self._buf, start, self._delimiter_spec)
            return size if index is None else index + 1
        if not self._sync:
            return start
        index = self._buf.find(self._sync, start)
        return size if index < 0 else index

    def _preempt_offset(self, pos: int) -> Optional[int]:
        """在 ``pos`` 之后找一个"锚点处已经是完整帧"的位置，用于切断脏数据前缀。

        只有当场就能完整解析（含校验）的帧才算数，避免把候选项误判成脏数据；
        载荷里要同时出现锚点字节串和一个校验通过的帧才会误切，概率可以忽略。
        """
        sync = self._sync
        if not sync:
            return None
        start = pos + 1
        while True:
            index = self._buf.find(sync, start)
            if index < 0:
                return None
            if self._frame_ready_at(index):
                return index
            start = index + 1

    def _frame_ready_at(self, index: int) -> bool:
        try:
            return self._parse_fields(self._buf, index, allow_rest=False) is not None
        except FrameInvalid:
            return False

    # ------------------------------------------------------------------ 规则编译
    def _ensure_compiled(self) -> None:
        if self._compiled is not None:
            return

        if self.on_crc_error not in ("resync", "skip_frame"):
            raise FrameRuleError(
                "on_crc_error 只能是 'resync' 或 'skip_frame'，实际 {!r}".format(self.on_crc_error)
            )

        spec = self.framing
        if isinstance(spec, DelimiterFraming):
            mode: Optional[str] = DELIMITER_FRAMING
            self._delimiter_spec = spec
        elif spec == LENGTH_FRAMING:
            mode = LENGTH_FRAMING
        elif spec == DELIMITER_FRAMING:
            if self.delimiter is None:
                raise FrameRuleError(
                    "framing='delimiter' 需要设置 delimiter=DelimiterFraming(...)"
                )
            mode, self._delimiter_spec = DELIMITER_FRAMING, self.delimiter
        elif spec == AUTO_FRAMING:
            if self.delimiter is None:
                raise FrameRuleError(
                    "framing='auto' 需要同时设置 delimiter=DelimiterFraming(...)"
                )
            mode, self._delimiter_spec = None, self.delimiter
            self._auto = True
        else:
            raise FrameRuleError(
                "framing 必须是 {} 之一或 DelimiterFraming 实例，实际 {!r}".format(
                    sorted(FRAMING_MODES), spec
                )
            )

        self._compiled = compile_rules(list(self.rules() or ()), self.device_field)
        self._mode = mode
        if mode == LENGTH_FRAMING:
            for cf in self._compiled:
                if cf.length is None:
                    raise FrameRuleError(
                        "字段 {!r} 声明为“取到帧尾”，只能用于分隔符定界"
                        "（改为 DelimiterFraming(...) 或 AUTO_FRAMING）".format(cf.key)
                    )
            self._sync = self._resolve_sync(self._compiled[0])
        elif mode is None:
            # auto 模式需要长度定界的同步锚点做兜底重同步
            self._sync = self._resolve_sync(self._compiled[0])
        # 设备号若在编译前就已通过 bind_device/外部来源获得，直接拿来当锚点
        self._refresh_sync()

    def _resolve_sync(self, first: CompiledField) -> bytes:
        sync = self.sync
        if sync is not None:
            if isinstance(sync, int):
                if not 0 <= sync <= 0xFF:
                    raise FrameRuleError("sync 单字节值必须在 0..255")
                return bytes([sync])
            return bytes(sync)
        if (
            first.length == 1
            and (first.fmt_size is None or first.fmt_size == 1)
            and first.fixed is not None
        ):
            fixed = first.fixed
            if isinstance(fixed, int) and 0 <= fixed <= 0xFF:
                return bytes([fixed])
            if isinstance(fixed, (bytes, bytearray, memoryview)) and len(fixed) == 1:
                return bytes(fixed)
        return b""

    def __repr__(self) -> str:  # pragma: no cover - 调试展示
        keys = [cf.key for cf in (self._compiled or ())]
        return "<{} framing={} fields={} pending={} device={!r}>".format(
            type(self).__name__, self._mode, keys, len(self._buf), self._device_id
        )


def _fixed_matches(fixed: Any, val: Any, raw: bytes) -> bool:
    if isinstance(fixed, (bytes, bytearray, memoryview)):
        return bytes(fixed) == raw
    return fixed == val


def _anchor_bytes(value: Any, cf: CompiledField) -> Optional[bytes]:
    """把已知设备号还原成帧内原始字节，供 ``_find_next_sync`` 使用。

    定长字段才能还原（表达式长度取决于帧内容，静态推不出来）。
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not isinstance(cf.length, int) or cf.length <= 0:
        return None
    try:
        return value.to_bytes(cf.length, cf.byteorder, signed=False)
    except OverflowError:  # 设备号宽于字段，属配置矛盾，不设锚点即可
        return None
