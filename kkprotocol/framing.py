# -*- coding: utf-8 -*-
"""定界方式：长度前缀定界 与 分隔符定界（含字节转义 / 透明传输）。

两种定界的本质区别：

* ``length``（长度定界）：先读长度字段，再按长度取字节。净荷里出现任何字节都
  无害，**不需要转义**；但长度字段一旦被破坏，整条流会跟着错位。
* ``delimiter``（分隔符定界）：按特殊字节（如 ``0x7E``）切帧。净荷里若出现同样的
  字节会误判帧边界，因此**必须转义**；此时长度字段只能作为“参考值/校验项”，
  不能当作切帧依据（转义会让线上长度和净荷长度不一致）。

``auto`` 模式会先用长度定界尝试解析，失败再试分隔符定界，命中一次后锁定策略。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Union

from .errors import FrameRuleError

__all__ = [
    "LENGTH_FRAMING",
    "DELIMITER_FRAMING",
    "AUTO_FRAMING",
    "FRAMING_MODES",
    "DelimiterFraming",
    "escape_bytes",
    "unescape_bytes",
    "find_end_delimiter",
    "wrap_frame",
]

LENGTH_FRAMING = "length"
DELIMITER_FRAMING = "delimiter"
AUTO_FRAMING = "auto"
FRAMING_MODES = frozenset({LENGTH_FRAMING, DELIMITER_FRAMING, AUTO_FRAMING})


def _check_byte(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise FrameRuleError("{} 必须是 0..255 的整数，实际 {!r}".format(name, value))


@dataclass(frozen=True)
class DelimiterFraming:
    """分隔符定界配置。

    :param end: 帧尾定界字节（必须）
    :param start: 帧头定界字节，可省略。``start == end`` 表示首尾共用一个标志
        （PPP/HDLC 风格）；两者都配置时，帧内容取两者之间。
    :param escape: 转义字节；``None`` 表示不做转义
    :param escape_xor: 转义字节后一字节与原始字节的异或值（PPP/HDLC 为 0x20）
    :param escape_map: 显式映射（原始字节 -> 转义后第二字节），用于 SLIP 这类
        非异或方案；未命中的字节仍按 ``escape_xor`` 还原
    """

    end: int
    start: Optional[int] = None
    escape: Optional[int] = None
    escape_xor: int = 0x20
    escape_map: Optional[Mapping[int, int]] = None

    _map: Dict[int, int] = field(init=False, repr=False, compare=False, default_factory=dict)
    _reverse: Dict[int, int] = field(init=False, repr=False, compare=False, default_factory=dict)
    _targets: frozenset = field(init=False, repr=False, compare=False, default_factory=frozenset)

    def __post_init__(self) -> None:
        _check_byte("end", self.end)
        if self.start is not None:
            _check_byte("start", self.start)
        if self.escape is not None:
            _check_byte("escape", self.escape)
        _check_byte("escape_xor", self.escape_xor)

        if self.escape is not None and self.escape in (self.end, self.start):
            raise FrameRuleError("转义字节不能与定界符相同（会造成歧义）")

        forward: Dict[int, int] = {}
        reverse: Dict[int, int] = {}
        if self.escape_map:
            for original, second in self.escape_map.items():
                _check_byte("escape_map 键", original)
                _check_byte("escape_map 值", second)
                if second in reverse:
                    raise FrameRuleError("escape_map 中第二字节 {!r} 重复".format(second))
                forward[original] = second
                reverse[second] = original

        targets = set()
        if self.escape is not None:
            for value in (self.start, self.end, self.escape):
                if value is not None:
                    targets.add(value)
            for target in list(targets):
                second = reverse.get(target, target ^ self.escape_xor)
                if second in targets and reverse.get(second) != target:
                    raise FrameRuleError(
                        "转义后字节 {:#04x} 与定界/转义字节冲突，请显式提供 escape_map".format(second)
                    )

        object.__setattr__(self, "_map", forward)
        object.__setattr__(self, "_reverse", reverse)
        object.__setattr__(self, "_targets", frozenset(targets))

    # ------------------------------------------------------------------ 查询
    @property
    def targets(self) -> frozenset:
        """必须被转义的字节集合（帧头/帧尾/转义字节自身）。"""
        return self._targets

    @property
    def reversed_map(self) -> Dict[int, int]:
        """转义后第二字节 -> 原始字节。"""
        return self._reverse

    def second_byte(self, original: int) -> int:
        """原始字节转义后跟在转义字节后面的那一字节。"""
        return self._map.get(original, original ^ self.escape_xor)


def escape_bytes(data: Union[bytes, bytearray], spec: DelimiterFraming) -> bytes:
    """按配置转义（发送方向）。"""
    if spec.escape is None:
        return bytes(data)
    targets = spec.targets
    escape = spec.escape
    out = bytearray()
    for byte in data:
        if byte in targets:
            out.append(escape)
            out.append(spec.second_byte(byte))
        else:
            out.append(byte)
    return bytes(out)


def unescape_bytes(data: Union[bytes, bytearray], spec: DelimiterFraming) -> bytes:
    """按配置反转义。遇到悬空转义字节（帧被截断）或非法转义序列抛 ``ValueError``。"""
    if spec.escape is None:
        return bytes(data)
    escape = spec.escape
    reverse = spec.reversed_map
    xor = spec.escape_xor
    out = bytearray()
    index = 0
    size = len(data)
    while index < size:
        byte = data[index]
        if byte == escape:
            if index + 1 >= size:
                raise ValueError("帧以转义字节 0x{:02X} 结尾，数据被截断".format(escape))
            second = data[index + 1]
            original = reverse.get(second)
            out.append(second ^ xor if original is None else original)
            index += 2
        else:
            out.append(byte)
            index += 1
    return bytes(out)


def find_end_delimiter(
    buf: Union[bytes, bytearray], start: int, spec: DelimiterFraming
) -> Optional[int]:
    """从 start 起找第一个**未被转义**的帧尾定界字节，返回其下标。"""
    end = spec.end
    escape = spec.escape
    index = start
    size = len(buf)
    if escape is None:
        found = bytes(buf[index:]).find(bytes([end]))
        return None if found < 0 else index + found
    while index < size:
        byte = buf[index]
        if byte == escape:
            index += 2
            continue
        if byte == end:
            return index
        index += 1
    return None


def wrap_frame(payload: Union[bytes, bytearray], spec: DelimiterFraming) -> bytes:
    """发送方向：把净荷按分隔符/转义规则封装成线上字节（便于构造测试与设备下行）。"""
    body = escape_bytes(payload, spec)
    if spec.start is not None:
        return bytes([spec.start]) + body + bytes([spec.end])
    return body + bytes([spec.end])
