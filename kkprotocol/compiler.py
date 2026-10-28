# -*- coding: utf-8 -*-
"""规则编译：把 ``Field``/字典规则校验并编译成解析期使用的结构。

所有配置错误都在**编译期**暴露（可在启动时调用 ``codec.compile()``），
而不是等到运行期解析到某帧才炸。
"""

from __future__ import annotations

import struct
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from .errors import FrameRuleError
from .fields import Field
from .length import _GROUP_REF_RE, _LEN_ATTRS, LengthExpr

__all__ = ["CompiledField", "compile_rules", "normalize_rule"]

_LENGTH_KINDS = (int, LengthExpr)


def normalize_rule(item: Any) -> Field:
    """把 dict 规则或 Field 统一成 Field。"""
    if isinstance(item, Field):
        return item
    if isinstance(item, MappingABC):
        return Field.from_dict(dict(item))
    raise FrameRuleError(
        "规则项必须是 Field 或 dict，实际 {}".format(type(item).__name__)
    )


@dataclass
class CompiledField:
    """编译后的字段描述，解析热路径只读它。"""

    key: str
    length: Optional[Union[int, LengthExpr, Callable[[Dict[str, Any]], int]]]
    fmt: str
    fixed: Any
    group_refs: Optional[Tuple[str, ...]]
    is_crc: bool
    is_device: bool
    desc: str = ""
    struct: Optional[struct.Struct] = None
    fmt_size: Optional[int] = None
    byteorder: str = "big"


def _compile_length(key: str, spec: Any) -> Optional[Union[int, LengthExpr, Callable]]:
    if spec is None:  # 取到帧尾为止，只有分隔符定界能确定边界
        return None
    if callable(spec):
        return spec
    if isinstance(spec, bool):
        raise FrameRuleError("字段 {!r} 的长度不能是 bool".format(key))
    if isinstance(spec, int):
        return spec
    if isinstance(spec, str):
        text = spec.strip()
        if not text:
            raise FrameRuleError("字段 {!r} 的长度为空字符串".format(key))
        try:
            return int(text)
        except ValueError:
            return LengthExpr(text)
    raise FrameRuleError(
        "字段 {!r} 的长度必须是 int / str / callable，实际 {}".format(key, type(spec).__name__)
    )


def compile_rules(
    raw_rules: Sequence[Union[Field, Dict[str, Any]]],
    device_field: Optional[str] = None,
) -> List[CompiledField]:
    """校验并编译规则列表；任何不一致都抛 :class:`FrameRuleError`。"""
    if not raw_rules:
        raise FrameRuleError("rules() 返回空规则，至少需要一个字段")

    compiled: List[CompiledField] = []
    seen: List[str] = []

    for item in raw_rules:
        field = normalize_rule(item)
        key = field.key
        if not isinstance(key, str) or not key:
            raise FrameRuleError("规则缺少合法的 key: {!r}".format(key))
        if key in seen:
            raise FrameRuleError("字段 key 重复: {!r}".format(key))
        fmt = field.fmt
        if not isinstance(fmt, str):
            raise FrameRuleError("字段 {!r} 的 fmt 必须是字符串".format(key))

        st: Optional[struct.Struct] = None
        fmt_size: Optional[int] = None
        if fmt:
            try:
                st = struct.Struct(fmt)
            except struct.error as exc:
                raise FrameRuleError("字段 {!r} 的 fmt {!r} 非法: {}".format(key, fmt, exc)) from exc
            if st.size <= 0:
                raise FrameRuleError("字段 {!r} 的 fmt {!r} 长度为 0".format(key, fmt))
            if len(st.unpack(b"\x00" * st.size)) != 1:
                raise FrameRuleError("字段 {!r} 的 fmt {!r} 必须只解析出一个值".format(key, fmt))
            fmt_size = st.size

        length = _compile_length(key, field.length)
        if isinstance(length, int):
            if length < 0:
                raise FrameRuleError("字段 {!r} 长度为负数".format(key))
            if length == 0 and st is not None:
                raise FrameRuleError("字段 {!r} 为零长度，不能声明 fmt".format(key))
            if fmt_size is not None and fmt_size != length:
                raise FrameRuleError(
                    "字段 {!r} 声明长度 {} 与 fmt {!r} 的字节数 {} 不一致".format(
                        key, length, fmt, fmt_size
                    )
                )
        elif isinstance(length, LengthExpr):
            for ref_key, attr in length.refs:
                if ref_key not in seen:
                    raise FrameRuleError(
                        "字段 {!r} 的长度表达式引用了不存在或尚未解析的字段 {!r}"
                        "（只能引用前面的字段）".format(key, ref_key)
                    )
                if attr != "val" and attr not in _LEN_ATTRS:
                    raise FrameRuleError(
                        "字段 {!r} 的长度表达式引用了不支持的属性 {!r}".format(key, attr)
                    )

        group_refs: Optional[Tuple[str, ...]] = None
        is_crc = bool(field.crc)
        if field.group is not None:
            group = field.group
            if not isinstance(group, str) or not group:
                raise FrameRuleError("字段 {!r} 的 group 必须是非空字符串".format(key))
            refs = tuple(m.group(1) for m in _GROUP_REF_RE.finditer(group))
            if not refs:
                raise FrameRuleError("字段 {!r} 的 group 未包含任何 {{字段}} 引用".format(key))
            for ref_key in refs:
                if ref_key not in seen:
                    raise FrameRuleError(
                        "字段 {!r} 的 group 引用了不存在或尚未解析的字段 {!r}".format(key, ref_key)
                    )
            group_refs = refs
            is_crc = True
        elif is_crc:
            if not seen:
                raise FrameRuleError("校验字段 {!r} 之前没有可参与校验的内容".format(key))
            group_refs = tuple(seen)

        compiled.append(
            CompiledField(
                key=key,
                length=length,
                fmt=fmt,
                fixed=field.fixed,
                group_refs=group_refs,
                is_crc=is_crc,
                is_device=(device_field is not None and key == device_field),
                desc=field.desc,
                struct=st,
                fmt_size=fmt_size,
                byteorder="little" if fmt.startswith("<") else "big",
            )
        )
        seen.append(key)

    if device_field is not None and device_field not in seen:
        raise FrameRuleError(
            "device_field={!r} 不在规则里，可用字段: {}".format(device_field, seen)
        )
    for cf in compiled:
        if cf.is_device and cf.fixed is not None:
            raise FrameRuleError(
                "设备号字段 {!r} 不能同时声明 fixed（设备号由 device_id/自动学习决定）".format(
                    cf.key
                )
            )
    return compiled
