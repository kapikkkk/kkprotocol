# -*- coding: utf-8 -*-
"""字段规则：用字段类代替字典，获得完整的 IDE 智能提示。

三种写法都支持（推荐第一种）：

1. 工厂方法，最短且有类型提示::

       Field.u8("header", fixed=0x55)
       Field.u16("ser")
       Field.raw("data", "{len.val}-10")
       Field.checksum("crc", 2, group="{len}{ver}{data}")

2. 完整构造::

       Field(key="header", length=1, fmt="B", fixed=0x55)

3. 旧式字典（兼容既有代码）::

       {"key": "header", "len": 1, "fmt": "B", "fixed": 0x55}

字段属性说明：

``key``
    字段名，帧内唯一。
``length``
    长度。取值：``int``、``"10"``、表达式 ``"{len.val}-10"``、
    回调 ``callable(fields) -> int``，或 ``None`` 表示“取到帧尾为止”
    （只能用于分隔符定界，长度定界下编译期就会报错）。
    表达式里 ``{字段.属性}`` 的属性只能是 ``val``（数值）、``len``/``bytes``
    （该字段实际字节数）。
``fmt``
    ``struct`` 格式串，必须只解析出一个值；为空表示字段值就是原始 ``bytes``。
    多字节数值请显式带字节序前缀（``!``/``<``），避免原生对齐差异。
``fixed``
    期望常量。``int`` 与解析值比较，``bytes`` 与原始字节比较，``None`` 表示不校验。
``group``
    校验字段专用：参与校验的字段模板，如 ``"{len}{ver}{data}"``。
    给出了 ``group`` 就自动视为校验字段，``crc`` 可省略；省略 ``group`` 时
    校验它前面所有字段。
``crc``
    显式标记为校验字段（配合 ``crc_imp`` 使用）。
``desc``
    仅注释用，方便阅读规则表。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Union

__all__ = ["Field"]


@dataclass(frozen=True)
class Field:
    """一个字段的声明式规则。"""

    key: str
    length: Optional[Union[int, str, Callable[[Dict[str, Any]], int]]] = 0
    fmt: str = ""
    fixed: Any = None
    group: Optional[str] = None
    crc: bool = False
    desc: str = ""

    # ------------------------------------------------------------------ 工厂
    @classmethod
    def u8(cls, key: str, *, fixed: Optional[int] = None, desc: str = "") -> "Field":
        """1 字节无符号整数。"""
        return cls(key=key, length=1, fmt="B", fixed=fixed, desc=desc)

    @classmethod
    def u16(
        cls,
        key: str,
        *,
        fixed: Optional[int] = None,
        little_endian: bool = False,
        desc: str = "",
    ) -> "Field":
        """2 字节无符号整数，默认大端。"""
        return cls(
            key=key, length=2, fmt="<H" if little_endian else "!H", fixed=fixed, desc=desc
        )

    @classmethod
    def u32(
        cls,
        key: str,
        *,
        fixed: Optional[int] = None,
        little_endian: bool = False,
        desc: str = "",
    ) -> "Field":
        """4 字节无符号整数，默认大端。"""
        return cls(
            key=key, length=4, fmt="<I" if little_endian else "!I", fixed=fixed, desc=desc
        )

    @classmethod
    def u64(
        cls,
        key: str,
        *,
        fixed: Optional[int] = None,
        little_endian: bool = False,
        desc: str = "",
    ) -> "Field":
        """8 字节无符号整数，默认大端。"""
        return cls(
            key=key, length=8, fmt="<Q" if little_endian else "!Q", fixed=fixed, desc=desc
        )

    @classmethod
    def raw(
        cls,
        key: str,
        length: Optional[Union[int, str, Callable[[Dict[str, Any]], int]]] = 0,
        *,
        fixed: Optional[bytes] = None,
        desc: str = "",
    ) -> "Field":
        """原始字节字段（不做 struct 解包，值即 bytes）。"""
        return cls(key=key, length=length, fmt="", fixed=fixed, desc=desc)

    @classmethod
    def rest(cls, key: str, *, desc: str = "") -> "Field":
        """“取到帧尾为止”的字段（仅分隔符定界可用，行协议常用）。"""
        return cls(key=key, length=None, fmt="", desc=desc)

    @classmethod
    def checksum(
        cls,
        key: str,
        length: Union[int, str] = 2,
        *,
        group: Optional[str] = None,
        fmt: Optional[str] = None,
        desc: str = "",
    ) -> "Field":
        """校验字段（CRC/累加和等），校验算法由 ``crc_imp`` 提供。

        ``fmt`` 省略时按 ``length`` 自动选（1 字节 ``B``、2 字节 ``!H``、
        4 字节 ``!I``、8 字节 ``!Q``，其他情况按原始字节处理）。
        """
        if fmt is None:
            fmt = {1: "B", 2: "!H", 4: "!I", 8: "!Q"}.get(
                length if isinstance(length, int) else -1, ""
            )
        return cls(key=key, length=length, fmt=fmt, group=group, crc=True, desc=desc)

    # ------------------------------------------------------------------ 兼容
    @classmethod
    def from_dict(cls, rule: Dict[str, Any]) -> "Field":
        """把旧式字典规则转成字段类（内部编译也走这里）。"""
        if not isinstance(rule, dict):
            raise TypeError("规则必须是 dict 或 Field，实际 {}".format(type(rule).__name__))
        spec_len = rule["len"] if "len" in rule else rule.get("length", 0)
        return cls(
            key=rule.get("key"),
            length=spec_len,
            fmt=rule.get("fmt") or "",
            fixed=rule.get("fixed"),
            group=rule.get("group"),
            crc=bool(rule.get("crc", False)),
            desc=rule.get("desc", ""),
        )
