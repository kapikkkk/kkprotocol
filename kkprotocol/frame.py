# -*- coding: utf-8 -*-
"""解析结果：字段值与整帧。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

__all__ = ["FieldValue", "Frame"]


@dataclass(frozen=True)
class FieldValue:
    """单个字段的解析结果。

    ``raw`` 是字段原始字节（定界模式下为**反转义后**的字节），``val`` 是 ``fmt``
    解出的值；``fmt`` 为空时 ``val`` 就是 ``raw`` 本身。
    """

    key: str
    raw: bytes
    val: Any

    @property
    def length(self) -> int:
        """该字段实际占用的字节数。"""
        return len(self.raw)

    def __len__(self) -> int:
        return len(self.raw)

    def __int__(self) -> int:
        if not isinstance(self.val, int):
            raise TypeError("字段 {} 的值不是整数（fmt 为空时值为 bytes）".format(self.key))
        return int(self.val)

    def __repr__(self) -> str:  # pragma: no cover - 调试展示
        return "FieldValue(key={!r}, len={}, val={!r})".format(self.key, len(self.raw), self.val)


@dataclass(frozen=True)
class Frame:
    """一帧完整数据的解析结果。

    * ``raw``：解析器交给规则的字节（定界模式下已去掉定界符并完成反转义）
    * ``wire``：这一帧在流中实际占用的字节（含定界符与转义字节），便于抓包比对
    * ``framing``：本帧使用的定界方式，``"length"`` 或 ``"delimiter"``
    * ``device_id``：该帧携带的设备标识（由 ``device_field`` 指定字段得出），
      未配置 ``device_field`` 时为 ``None``
    * ``device_mismatch``：与已绑定设备号不一致（仅在 ``enforce_device_id=False`` 时还会返回）
    * ``learned_device``：本帧是否触发了设备号自动学习
    """

    raw: bytes
    fields: Dict[str, FieldValue] = field(default_factory=dict)
    wire: Optional[bytes] = None
    framing: str = "length"
    device_id: Any = None
    device_mismatch: bool = False
    learned_device: bool = False

    def __getitem__(self, key: str) -> FieldValue:
        return self.fields[key]

    def __contains__(self, key: str) -> bool:
        return key in self.fields

    def __len__(self) -> int:
        return len(self.raw)

    def keys(self):
        return self.fields.keys()

    def value(self, key: str, default: Any = None) -> Any:
        """取字段值；字段不存在时返回 default。"""
        fv = self.fields.get(key)
        return default if fv is None else fv.val

    def raw_of(self, key: str) -> bytes:
        """取字段原始字节。"""
        return self.fields[key].raw

    # ------------------------------------------------------------------ 整帧字节
    def to_bytes(self, wire: bool = True) -> bytes:
        """整帧字节。

        ``wire=True``（默认）返回这一帧在流里实际占用的字节：长度定界就是
        ``55 AA ...`` 的原文，分隔符定界还包含首尾标志位和转义字节。
        ``wire=False`` 返回交给规则解析的净帧字节（已去定界符、已反转义）。
        """
        if wire and self.wire is not None:
            return self.wire
        return self.raw

    def to_hex(self, sep: str = " ", upper: bool = True, wire: bool = True) -> str:
        """整帧的十六进制字符串，默认形如 ``"55 AA 00 59 02 00 ..."``。

        ``sep=""`` 得到 ``"55AA00590200..."``，``upper=False`` 得到小写。
        """
        data = self.to_bytes(wire)
        text = data.hex() if not sep else data.hex(sep)
        return text.upper() if upper else text

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def as_dict(self) -> Dict[str, Any]:
        """{字段名: 值} 的扁平字典，便于直接消费。"""
        return {k: v.val for k, v in self.fields.items()}

    def __repr__(self) -> str:  # pragma: no cover - 调试展示
        return "Frame(framing={}, len={}, fields={})".format(
            self.framing, len(self.raw), list(self.fields)
        )
