# -*- coding: utf-8 -*-
"""把「一串有类型的值」直接拼成字节，不必先声明字段名。

``Field`` 回答的是「字段长什么样」，所以需要 key；本模块反过来——你已经知道值，
只想把它编码成字节塞进载荷::

    from kkprotocol import Data, pack

    body = pack(
        Data.u8(0x00),
        Data.u8(0x00),
        Data.bool(True),
        Data.str("test", count=24, fill=b"\\x00"),
    )

    proto.build_raw(0x03, body, type=1, seq=1)      # 也可以直接把列表传进去

``Data`` 的每个方法返回一个已编码的小对象（``_Encoded``），``pack()`` 把它们按顺序
拼成 ``bytes``。多字节整数默认大端，与 :class:`Field` 一致。
"""

from __future__ import annotations

import struct
from typing import Any, Optional, Union

__all__ = ["Data", "pack"]

BytesLike = Union[bytes, bytearray, memoryview]


class _Encoded:
    """一个已经编码好的值：只保留最终字节。"""

    __slots__ = ("data",)

    def __init__(self, data: BytesLike) -> None:
        self.data = bytes(data)

    # 方便直接当 bytes 用
    def __bytes__(self) -> bytes:
        return self.data

    def __len__(self) -> int:
        return len(self.data)

    def __add__(self, other: Any) -> "_Encoded":
        return _Encoded(self.data + _as_bytes(other))

    def __radd__(self, other: Any) -> "_Encoded":
        return _Encoded(_as_bytes(other) + self.data)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, _Encoded):
            return self.data == other.data
        if isinstance(other, (bytes, bytearray, memoryview)):
            return self.data == bytes(other)
        return NotImplemented

    def __repr__(self) -> str:
        return "Data({})".format(self.data.hex(" "))


def _as_bytes(item: Any) -> bytes:
    """把一条载荷项转成字节。"""
    if isinstance(item, _Encoded):
        return item.data
    if isinstance(item, (bytes, bytearray, memoryview)):
        return bytes(item)
    raise TypeError(
        "载荷项必须是 Data.xxx(...) 或 bytes，实际 {}".format(type(item).__name__)
    )


def _fill_byte(fill: Union[int, bytes, bytearray, str]) -> bytes:
    """把 fill 归一成 1 字节。"""
    if isinstance(fill, int):
        if not 0 <= fill <= 0xFF:
            raise ValueError("fill 必须在 0..255，实际 {}".format(fill))
        return bytes([fill])
    if isinstance(fill, str):
        raw = fill.encode("latin-1")
    else:
        raw = bytes(fill)
    if len(raw) != 1:
        raise ValueError("fill 必须是 1 个字节，实际 {!r}".format(fill))
    return raw


class Data:
    """值构造器：给值，拿到字节。与 :class:`Field` 的相对应工厂一一对应。

    用法::

        Data.u8(0x12)          # 1 字节
        Data.u16(0x1234)       # 2 字节，大端
        Data.u16(0x1234, little_endian=True)
        Data.bool(True)        # b"\\x01"
        Data.str("test", count=24, fill=b"\\x00")   # 定长 24，不足补 \\x00
        Data.raw(b"\\x01\\x02")   # 原样字节
        Data.zeros(4)          # 4 个 \\x00
    """

    # ------------------------------------------------------------------ 整数
    @staticmethod
    def _pack(fmt: str, value: Any, label: str) -> _Encoded:
        try:
            return _Encoded(struct.pack(fmt, value))
        except struct.error as exc:
            raise ValueError("{}: {!r} 无法按 {} 打包（{}）".format(label, value, fmt, exc))

    @classmethod
    def u8(cls, value: int) -> _Encoded:
        """1 字节无符号整数。"""
        return cls._pack("B", value, "Data.u8")

    @classmethod
    def i8(cls, value: int) -> _Encoded:
        """1 字节有符号整数。"""
        return cls._pack("b", value, "Data.i8")

    @classmethod
    def u16(cls, value: int, *, little_endian: bool = False) -> _Encoded:
        """2 字节无符号整数，默认大端。"""
        return cls._pack("<H" if little_endian else "!H", value, "Data.u16")

    @classmethod
    def i16(cls, value: int, *, little_endian: bool = False) -> _Encoded:
        """2 字节有符号整数，默认大端。"""
        return cls._pack("<h" if little_endian else "!h", value, "Data.i16")

    @classmethod
    def u32(cls, value: int, *, little_endian: bool = False) -> _Encoded:
        """4 字节无符号整数，默认大端。"""
        return cls._pack("<I" if little_endian else "!I", value, "Data.u32")

    @classmethod
    def i32(cls, value: int, *, little_endian: bool = False) -> _Encoded:
        """4 字节有符号整数，默认大端。"""
        return cls._pack("<i" if little_endian else "!i", value, "Data.i32")

    @classmethod
    def u64(cls, value: int, *, little_endian: bool = False) -> _Encoded:
        """8 字节无符号整数，默认大端。"""
        return cls._pack("<Q" if little_endian else "!Q", value, "Data.u64")

    @classmethod
    def i64(cls, value: int, *, little_endian: bool = False) -> _Encoded:
        """8 字节有符号整数，默认大端。"""
        return cls._pack("<q" if little_endian else "!q", value, "Data.i64")

    # ------------------------------------------------------------------ 浮点
    @classmethod
    def f32(cls, value: float, *, little_endian: bool = False) -> _Encoded:
        """4 字节单精度浮点，默认大端。"""
        return cls._pack("<f" if little_endian else "!f", value, "Data.f32")

    @classmethod
    def f64(cls, value: float, *, little_endian: bool = False) -> _Encoded:
        """8 字节双精度浮点，默认大端。"""
        return cls._pack("<d" if little_endian else "!d", value, "Data.f64")

    # ------------------------------------------------------------------ 其它
    @classmethod
    def bool(cls, value: Any) -> _Encoded:
        """1 字节布尔（真 = 0x01，假 = 0x00）。"""
        return _Encoded(b"\x01" if value else b"\x00")

    @classmethod
    def raw(cls, data: BytesLike) -> _Encoded:
        """原样字节，不做任何解释。"""
        return _Encoded(data)

    @classmethod
    def zeros(cls, count: int) -> _Encoded:
        """``count`` 个 0x00。"""
        if count < 0:
            raise ValueError("count 不能为负，实际 {}".format(count))
        return _Encoded(b"\x00" * count)

    @classmethod
    def str(
        cls,
        text: str,
        *,
        count: Optional[int] = None,
        fill: Union[int, bytes, bytearray, str] = b"\x00",
        encoding: str = "utf-8",
    ) -> _Encoded:
        """字符串。

        ``count`` 给定时按定长处理：超长截断，不足用 ``fill`` 补齐（C 字符串风格）。
        不给 ``count`` 就按实际长度输出。
        """
        raw = text.encode(encoding)
        if count is None:
            return _Encoded(raw)
        if count < 0:
            raise ValueError("count 不能为负，实际 {}".format(count))
        if len(raw) >= count:
            return _Encoded(raw[:count])
        return _Encoded(raw + _fill_byte(fill) * (count - len(raw)))

    # ``Data.char`` 是 ``Data.str`` 的别名，方便从「字符数组」的写法迁移过来
    char = str


def pack(*items: Any) -> bytes:
    """把若干 ``Data.xxx(...)``（或 bytes）按顺序拼成 ``bytes``。

    也接受单个列表/元组，便于写成 ``pack([Data.u8(1), Data.u8(2)])``::

        pack(Data.u8(0), Data.u8(0), Data.bool(True), Data.str("test", count=24))
        pack([Data.u8(0), Data.u8(0), Data.bool(True)])
        b"\\x00" + pack(Data.u8(1))            # 也能和 bytes 直接相加
    """
    if len(items) == 1 and isinstance(items[0], (list, tuple)):
        items = tuple(items[0])
    out = bytearray()
    for item in items:
        out += _as_bytes(item)
    return bytes(out)
