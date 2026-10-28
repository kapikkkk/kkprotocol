# -*- coding: utf-8 -*-
"""组帧描述：``FrameSpec`` / ``Pdu`` / ``LengthRule`` / ``ChecksumRule`` / ``SeqPolicy``。

解析侧用继承式 ``rules()``，组帧侧用本模块的声明式描述。两者**互不依赖**：
发送帧和接收帧格式不同时，各写一份 spec，交给 ``Protocol(tx=..., rx=...)``；
两者相同时传同一个对象即可。

一段最小声明::

    TX = FrameSpec(
        fields=[
            Field.u8("head", fixed=0xAA),
            Field.u16("len"),
            Field.u8("cmd"),
            Field.raw("data", "{len.val}-3"),
            Field.checksum("crc", 2, group="{len}{cmd}{data}"),
        ],
        payload="data",
        length=LengthRule("len"),
        checksum=ChecksumRule("crc", crc16_modbus),
        pdus={0x01: Pdu("SetParam", [Field.u8("id"), Field.u16("value")])},
    )
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .compiler import _GROUP_REF_RE
from .errors import FrameRuleError
from .fields import Field
from .framing import DelimiterFraming, LENGTH_FRAMING

__all__ = [
    "FrameSpec",
    "Pdu",
    "LengthRule",
    "ChecksumRule",
    "SeqPolicy",
    "AutoField",
]


@dataclass(frozen=True)
class LengthRule:
    """长度字段的组帧规则。

    ``key``
        哪个字段是长度字段（必须是定长整数字段，如 ``Field.u16("len")``）。
    ``span``
        长度覆盖哪一段，用**字段名**界定，左闭右闭（含两端字段的全部字节）。

        * ``span=None``（默认）：长度字段**之后**的所有字段，直到帧尾，**含校验字段**。
          这是"字面全包"的口径——填什么就是什么，不做任何隐式排除。
        * ``span=("proto", "crc")``：从 ``proto`` 的第一个字节到 ``crc`` 的最后一个字节。
          需要排除校验字段、或只覆盖中间一段时必须显式写。
    """

    key: str
    span: Optional[Tuple[str, str]] = None


@dataclass(frozen=True)
class ChecksumRule:
    """校验字段的组帧规则。

    ``impl`` 返回 ``int`` 时按字段的 ``fmt`` 打包，返回 ``bytes`` 时直接使用。
    """

    key: str
    impl: Callable[[bytes], Union[int, bytes, bytearray, memoryview]]


@dataclass(frozen=True)
class SeqPolicy:
    """序列号策略：默认不动，显式开启才自增。

    ``key`` 指定哪个字段放序列号（必须是定长整数字段）；``enabled=False`` 时
    该字段按普通字段处理，需要调用方自己传值。
    """

    key: str
    enabled: bool = False
    start: int = 0
    step: int = 1
    wrap: int = 0x10000


@dataclass(frozen=True)
class AutoField:
    """一个**由 builder 自动填值**的字段：序列号、时间戳、计数器……

    一份协议可以声明 0 个、1 个或多个，彼此完全独立。与长度/校验/设备号
    的区别：这三个有各自的专用机制，``AutoField`` 管的是"剩下那些业务字段"。

    * ``provider=None``（默认）：自增计数器。本次取当前值，之后
      ``当前值 = (当前值 + step) % wrap``。适合 SEQ、流水号。
    * ``provider=callable``：每次组帧调用 ``provider()`` 取值，适合时间戳、
      随机数等"不由上次数值决定"的字段。
    * ``echo=True``：``Protocol.build_ack`` 回显请求帧里的同名字段（应答里
      通常要把 SEQ 原样带回去）；``False`` 则不回显。

    显式在 ``build(..., key=值)`` 里给了该字段时，以显式值为准；若是计数器，
    内部计数器会从这个值之后接着走。
    """

    key: str
    start: int = 0
    step: int = 1
    wrap: int = 0x10000
    provider: Optional[Callable[[], Any]] = None
    echo: bool = True


@dataclass(frozen=True)
class Pdu:
    """一条报文（指令或应答）。

    ``cmd`` 可以**不写**：放进 ``FrameSpec.pdus`` 时，字典的键就是命令码，
    ``FrameSpec`` 会自动把它回填进 ``Pdu.cmd``。下面两种写法完全等价::

        pdus={0x03: Pdu("Read", 0x03, [Field.u8("addr")])}   # 显式写 cmd
        pdus={0x03: Pdu("Read", fields=[Field.u8("addr")])}  # 由键回填

    ``fields`` 是**载荷**字段表，与帧壳字段分开；``None`` 长度（``Field.rest``）
    表示"长度由传入字节数决定"。

    第二位置参数允许直接给字段表（``Pdu("Read", [Field.u8("addr")])``）——
    命令码只会是标量，不可能是序列，所以不存在歧义。
    """

    name: str
    cmd: Any = None
    fields: Sequence[Field] = ()
    resp: Optional[Any] = None
    desc: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.cmd, (list, tuple)):
            # Pdu("Read", [Field...])：第二位置参数是字段表，命令码留给字典键回填
            if self.fields:
                raise FrameRuleError(
                    "Pdu {!r} 的字段表给了两次：第二位置参数和 fields= 都是字段表".format(
                        self.name
                    )
                )
            object.__setattr__(self, "fields", tuple(self.cmd))
            object.__setattr__(self, "cmd", None)
        elif isinstance(self.fields, (list, tuple)):
            object.__setattr__(self, "fields", tuple(self.fields))

    def field_keys(self) -> List[str]:
        return [f.key for f in self.fields]


@dataclass(frozen=True)
class FrameSpec:
    """一个方向（发送或接收）的完整帧描述。

    ``cmd``
        哪个字段放命令码。声明了 ``pdus`` 时组帧必须知道命令码往哪写；不写则
        自动取名为 ``cmd`` 的字段。收发两个方向的命令码字段名不同时显式指定。
    """

    fields: Sequence[Field]
    framing: Union[str, DelimiterFraming] = LENGTH_FRAMING
    payload: Optional[str] = None
    cmd: Optional[str] = None
    length: Optional[LengthRule] = None
    # 一个（最常见）或一组校验和（一帧多校验和，如 BACnet MS/TP 的头 CRC + 体 CRC）。
    # 解析侧**已全部支持**：每个校验字段用自己的 impl 独立校验；组帧侧仍只回填
    # 第一个（库暂不支持一帧多校验和），多校验和帧需手工组帧（见 bacnet_mstp）。
    checksum: Optional[Union[ChecksumRule, Sequence[ChecksumRule]]] = None
    pdus: Mapping[Any, Pdu] = field(default_factory=dict)
    device: Optional[str] = None
    seq: Optional[SeqPolicy] = None
    auto: Sequence[AutoField] = ()
    max_frame_size: int = 64 * 1024
    desc: str = ""

    # ------------------------------------------------------------------ 校验
    def __post_init__(self) -> None:
        fields = list(self.fields)
        if not fields:
            raise FrameRuleError("FrameSpec.fields 不能为空")

        keys: List[str] = []
        for one in fields:
            if not isinstance(one, Field):
                raise FrameRuleError(
                    "FrameSpec.fields 只接受 Field 对象，实际 {}".format(type(one).__name__)
                )
            if one.key in keys:
                raise FrameRuleError("FrameSpec 字段 key 重复: {!r}".format(one.key))
            keys.append(one.key)

        if self.payload is not None and self.payload not in keys:
            raise FrameRuleError(
                "payload={!r} 不在字段里，可用字段: {}".format(self.payload, keys)
            )
        if self.device is not None and self.device not in keys:
            raise FrameRuleError(
                "device={!r} 不在字段里，可用字段: {}".format(self.device, keys)
            )
        if self.cmd is not None and self.cmd not in keys:
            raise FrameRuleError(
                "cmd={!r} 不在字段里，可用字段: {}".format(self.cmd, keys)
            )
        if self.pdus and self.cmd_key is None:
            raise FrameRuleError(
                "声明了 pdus 就必须指定 cmd 字段（或提供一个名为 'cmd' 的字段），"
                "否则命令码无处安放；当前字段: {}".format(keys)
            )
        for role, key in (("payload", self.payload),):
            if key is not None and self.length is not None and key == self.length.key:
                raise FrameRuleError(
                    "{} 字段与长度字段不能是同一个字段 {!r}".format(role, key)
                )
        # 先校验 checksum 项类型，后面的分支才能安全读 .key
        for one in self._checksum_rules():
            if not isinstance(one, ChecksumRule):
                raise FrameRuleError(
                    "checksum 必须是 ChecksumRule 或其序列，实际 {}".format(
                        type(one).__name__
                    )
                )
        for crk in (r.key for r in self._checksum_rules()):
            if self.length is not None and crk == self.length.key:
                raise FrameRuleError(
                    "checksum 字段与长度字段不能是同一个字段 {!r}".format(crk)
                )

        if isinstance(self.framing, str) and self.framing != LENGTH_FRAMING:
            raise FrameRuleError(
                "framing 为分隔符定界时请直接传 DelimiterFraming(...) 实例，"
                "而不是字符串 {!r}（解析与组帧都要用它做转义/封包）".format(self.framing)
            )

        autos = tuple(self.auto)
        for one in autos:
            if not isinstance(one, AutoField):
                raise FrameRuleError(
                    "FrameSpec.auto 只接受 AutoField 对象，实际 {}".format(type(one).__name__)
                )
        auto_keys: List[str] = []
        _crc_rules = self._checksum_rules()
        _crc_first = (
            _crc_rules[0].key
            if _crc_rules and isinstance(_crc_rules[0], ChecksumRule)
            else None
        )
        busy = {
            "payload": self.payload,
            "cmd": self.cmd_key,
            "length": self.length.key if self.length is not None else None,
            "checksum": _crc_first,
            "device": self.device,
        }
        for one in autos:
            if one.key not in keys:
                raise FrameRuleError(
                    "auto 字段 {!r} 不在字段里，可用字段: {}".format(one.key, keys)
                )
            if one.key in auto_keys:
                raise FrameRuleError("auto 字段 {!r} 重复声明".format(one.key))
            for role, other in busy.items():
                if other is not None and other == one.key:
                    raise FrameRuleError(
                        "auto 字段 {!r} 与 {} 字段冲突：一个字段只能承担一个角色".format(
                            one.key, role
                        )
                    )
            # 自动填值字段必须是定长，否则组帧时无法在不知道宽度的情况下写入
            self._check_int_field(one.key, keys, "自动字段")
            if one.provider is None and one.wrap <= 0:
                raise FrameRuleError("auto 字段 {!r} 的 wrap 必须为正整数".format(one.key))
            auto_keys.append(one.key)

        if self.seq is not None:
            self._check_int_field(self.seq.key, keys, "序列号字段")
            if self.seq.enabled:
                if self.seq.wrap <= 0:
                    raise FrameRuleError("seq.wrap 必须为正整数")
                # seq= 只是 auto= 的语法糖，老写法继续可用
                if self.seq.key not in auto_keys:
                    autos = (
                        AutoField(
                            self.seq.key,
                            start=self.seq.start,
                            step=self.seq.step,
                            wrap=self.seq.wrap,
                        ),
                    ) + autos
                    auto_keys.insert(0, self.seq.key)
        object.__setattr__(self, "auto", autos)

        if self.length is not None:
            self._check_int_field(self.length.key, keys, "长度字段")
            if self.length.span is not None:
                start, end = self.length.span
                for name in (start, end):
                    if name not in keys:
                        raise FrameRuleError(
                            "length.span 引用了不存在的字段 {!r}，可用字段: {}".format(name, keys)
                        )
                if keys.index(start) <= keys.index(self.length.key):
                    raise FrameRuleError(
                        "length.span 的起点 {!r} 必须在长度字段 {!r} 之后".format(
                            start, self.length.key
                        )
                    )
                if keys.index(end) < keys.index(start):
                    raise FrameRuleError(
                        "length.span 的终点 {!r} 不能早于起点 {!r}".format(end, start)
                    )

        for rule in self._checksum_rules():
            self._check_int_field(rule.key, keys, "校验字段")
            one = list(self.fields)[keys.index(rule.key)]
            if not one.crc and one.group is None:
                # 解析侧靠 crc/group 识别校验字段，漏标会让组出来的帧"发得出、收不回"
                raise FrameRuleError(
                    "checksum.key={!r} 指向的字段必须标记 crc=True 或给出 group，"
                    "否则解析时不会校验它".format(rule.key)
                )
        _crc_keys = [r.key for r in self._checksum_rules()]
        if len(set(_crc_keys)) != len(_crc_keys):
            raise FrameRuleError("checksum 列表里校验字段 key 重复: {}".format(_crc_keys))

        # 载荷字段与壳字段重名会让 build(**values) 有歧义
        self._check_pdu_index()
        for pdu in self.pdus.values():
            for one in pdu.fields:
                if one.key in keys:
                    raise FrameRuleError(
                        "Pdu {!r} 的载荷字段 {!r} 与帧壳字段重名".format(pdu.name, one.key)
                    )

    def _check_int_field(self, key: str, keys: Sequence[str], role: str) -> None:
        if key not in keys:
            raise FrameRuleError(
                "{} {!r} 不在字段里，可用字段: {}".format(role, key, list(keys))
            )
        one = list(self.fields)[list(keys).index(key)]
        if not isinstance(one.length, int) or one.length <= 0:
            raise FrameRuleError(
                "{} {!r} 必须是定长字段（length 为正整数），组帧时无法推算其宽度".format(role, key)
            )

    def _check_pdu_index(self) -> None:
        names: Dict[str, Any] = {}
        for cmd, pdu in self.pdus.items():
            if pdu.cmd is None:
                # 键就是命令码，回填进 Pdu（省掉"同一个值写两遍"）
                object.__setattr__(pdu, "cmd", cmd)
            elif pdu.cmd != cmd:
                raise FrameRuleError(
                    "pdus 的键 {!r} 与 Pdu.cmd {!r} 不一致".format(cmd, pdu.cmd)
                )
            if pdu.name in names:
                raise FrameRuleError("Pdu 名字重复: {!r}".format(pdu.name))
            names[pdu.name] = pdu
            seen: List[str] = []
            for one in pdu.fields:
                if not isinstance(one, Field):
                    raise FrameRuleError(
                        "Pdu {!r} 的载荷字段只接受 Field，实际 {}".format(
                            pdu.name, type(one).__name__
                        )
                    )
                if one.key in seen:
                    raise FrameRuleError(
                        "Pdu {!r} 载荷字段 key 重复: {!r}".format(pdu.name, one.key)
                    )
                seen.append(one.key)

    # ------------------------------------------------------------------ 查询
    def _checksum_rules(self) -> Tuple[ChecksumRule, ...]:
        """把 ``checksum`` 归一化成 ``ChecksumRule`` 元组（单值也包成一元组）。"""
        c = self.checksum
        if c is None:
            return ()
        if isinstance(c, ChecksumRule):
            return (c,)
        return tuple(c)

    @property
    def cmd_key(self) -> Optional[str]:
        """命令码字段名：显式 ``cmd`` 优先，否则回落到名为 ``cmd`` 的字段。"""
        if self.cmd is not None:
            return self.cmd
        return "cmd" if any(one.key == "cmd" for one in self.fields) else None

    def pdu(self, target: Any) -> Pdu:
        """按 cmd 值或指令名查 Pdu。"""
        if target in self.pdus:
            return self.pdus[target]
        for pdu in self.pdus.values():
            if pdu.name == target:
                return pdu
        raise FrameRuleError(
            "找不到报文 {!r}，已声明: {}".format(
                target, [p.name for p in self.pdus.values()]
            )
        )

    def field(self, key: str) -> Field:
        for one in self.fields:
            if one.key == key:
                return one
        raise FrameRuleError("找不到字段 {!r}".format(key))

    def field_keys(self) -> List[str]:
        return [one.key for one in self.fields]

    def group_keys(self, key: str) -> Tuple[str, ...]:
        """取校验字段参与计算的字段名（按 group 出现顺序）。"""
        one = self.field(key)
        if one.group:
            return tuple(m.group(1) for m in _GROUP_REF_RE.finditer(one.group))
        index = self.field_keys().index(key)
        return tuple(self.field_keys()[:index])

    # ------------------------------------------------------------------ 转解析器
    def to_codec(self) -> Any:
        """生成一个可直接 ``feed()`` 的解析器（复用现有解析引擎）。

        支持一帧多校验和：每个校验字段按自己的 ``ChecksumRule.impl`` 独立校验。
        """
        from .codec import AbstractFrameCodec

        spec = self
        impls = {r.key: r.impl for r in self._checksum_rules()}

        class SpecCodec(AbstractFrameCodec):
            framing = spec.framing
            device_field = spec.device
            max_frame_size = spec.max_frame_size

            def rules(self):
                return spec.fields

            def crc_imp(self, data: bytes):
                # 单校验和兜底；多校验和走 _crc_impls 按字段分发
                return 0

        codec = SpecCodec()
        codec._crc_impls = impls
        return codec

    # ------------------------------------------------------------------ 对比
    def diff(self, other: "FrameSpec") -> List[str]:
        """列出两份 spec 的差异，便于排查"收发为什么对不上"。"""
        changes: List[str] = []
        if self.framing != other.framing:
            changes.append("framing: {!r} != {!r}".format(self.framing, other.framing))
        if self.payload != other.payload:
            changes.append("payload: {!r} != {!r}".format(self.payload, other.payload))
        left, right = self.field_keys(), other.field_keys()
        if left != right:
            changes.append("字段序列: {} != {}".format(left, right))
        else:
            for key in left:
                a, b = self.field(key), other.field(key)
                if a != b:
                    changes.append("字段 {!r} 定义不同: {!r} != {!r}".format(key, a, b))
        if (self.length.key if self.length else None) != (
            other.length.key if other.length else None
        ):
            changes.append(
                "length.key: {!r} != {!r}".format(
                    self.length.key if self.length else None,
                    other.length.key if other.length else None,
                )
            )
        elif self.length and self.length.span != other.length.span:
            changes.append(
                "length.span: {!r} != {!r}".format(self.length.span, other.length.span)
            )
        left_rules = self._checksum_rules()
        right_rules = other._checksum_rules()
        if [r.key for r in left_rules] != [r.key for r in right_rules]:
            changes.append(
                "checksum 字段集合: {} != {}".format(
                    [r.key for r in left_rules], [r.key for r in right_rules]
                )
            )
        else:
            for lr, rr in zip(left_rules, right_rules):
                if lr.impl is not rr.impl:
                    changes.append("checksum {!r} 的 impl 不是同一个函数".format(lr.key))
        return changes
