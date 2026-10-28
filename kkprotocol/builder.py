# -*- coding: utf-8 -*-
"""组帧：``FrameSpec`` + 指令 + 参数 → 线上字节。

组帧相对解析有三处**不对称**，这是它不能直接复用解析规则的根因：

==========================  ===============================================
解析（收）                   组帧（发）
==========================  ===============================================
长度字段：读出来             长度字段：算出来，还要回填进帧
校验字段：验一遍             校验字段：算一遍（覆盖范围按 group）
常量字段：对一下             常量字段：自动填
==========================  ===============================================

"算出来再回填"意味着长度值依赖帧体、帧体又包含长度字段本身，因此走**不动点
循环**：

1. 先假设 ``长度=0、校验=0`` 拼出一帧（:meth:`FrameBuilder._assemble`）；
2. 用这帧的真实字节量出长度、算出校验；
3. 若"帧里写的"与"按帧算出来的"完全一致 → 这一帧自己跟自己自洽，收工；
   否则带着新值回到 1。

长度字段宽度固定，回填不改变总长，所以迭代法 2 轮、带校验 3 轮即可收敛；
超过 ``max_rounds``（默认 8）说明规则自相矛盾（例如校验覆盖了校验字段自身），
会抛 :class:`~kkprotocol.errors.FrameBuildError` 并附每一轮轨迹。

长度的两种口径（:class:`~kkprotocol.spec.LengthRule`）：

* ``span=None``（迭代法）：长度字段**之后**到帧尾的全部字节，含校验字段。
  "量出来"——直接数拼好的字节，不猜开发者的意图。
* ``span=("proto", "crc")``：按字段名左闭右闭取一段，"查出来"。
  需要把校验字段排除在外、或只覆盖中间一段时必须显式写。

一段最小用法::

    proto = Protocol(tx=TX, rx=RX, device_id="SN00000000000000001")
    wire = proto.build("Login")                  # 按指令名
    wire = proto.build(0x00)                     # 按命令码
    wire = proto.build("SetParam", id=1, value=250)
    wire = proto.build_ack(frame)                # 对收到的帧回一条应答
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .compiler import CompiledField, compile_rules
from .errors import FrameBuildError, FrameInvalid, FrameRuleError
from .frame import FieldValue, Frame
from .framing import DelimiterFraming, wrap_frame
from .length import LengthExpr
from .pack import pack
from .spec import ChecksumRule, FrameSpec, Pdu

__all__ = ["BuildResult", "FrameBuilder", "Protocol"]


def _coerce_payload(payload: Any) -> Any:
    """把 ``build_raw`` 的载荷归一成「可直接放进字段的值」。

    接受 ``bytes`` / ``str`` 原样；``Data.xxx(...)`` 之类按 ``bytes()`` 转；
    列表/元组视为一组载荷项，按顺序拼接（等价于先调 :func:`kkprotocol.pack`）。
    """
    if isinstance(payload, (bytes, bytearray, str)):
        return payload
    if isinstance(payload, (list, tuple)):
        return pack(*payload)
    return bytes(payload)


@dataclass(frozen=True)
class BuildResult:
    """一次组帧的完整结果（便于排查"发出去的到底是什么"）。

    ``data`` 是**线上字节**：长度定界就是 ``55 AA ...`` 原文；分隔符定界含首尾
    标志位与转义字节。``body`` 是交给规则的**净帧字节**（未加标志、未转义）。
    """

    data: bytes
    body: bytes
    fields: Dict[str, FieldValue]
    rounds: int
    trace: Tuple[Tuple[int, Optional[int], bytes, Optional[int], bytes], ...] = ()
    cmd: Any = None
    name: str = ""

    @property
    def length(self) -> int:
        """净帧字节数。"""
        return len(self.body)

    def value(self, key: str, default: Any = None) -> Any:
        fv = self.fields.get(key)
        return default if fv is None else fv.val

    def to_hex(self, sep: str = " ", upper: bool = True) -> str:
        text = self.data.hex() if not sep else self.data.hex(sep)
        return text.upper() if upper else text

    def __bytes__(self) -> bytes:
        return self.data

    def __len__(self) -> int:
        return len(self.data)

    def __repr__(self) -> str:  # pragma: no cover - 调试展示
        return "BuildResult(cmd={!r}, len={}, rounds={}, hex={}...)".format(
            self.cmd, len(self.data), self.rounds, self.to_hex()[:23]
        )


@dataclass
class _Draft:
    """一轮拼装出来的帧。"""

    parts: List[bytes] = dc_field(default_factory=list)
    fields: Dict[str, FieldValue] = dc_field(default_factory=dict)

    @property
    def body(self) -> bytes:
        return b"".join(self.parts)

    @property
    def sizes(self) -> List[int]:
        return [len(part) for part in self.parts]


class _AutoState:
    """一个自动填值字段的运行时状态（计数器当前值 / provider）。"""

    __slots__ = ("policy", "value")

    def __init__(self, policy: Any) -> None:
        self.policy = policy
        self.value = policy.start


class FrameBuilder:
    """按一份 :class:`FrameSpec` 把指令+参数拼成字节。"""

    def __init__(
        self,
        spec: FrameSpec,
        *,
        device_id: Any = None,
        max_rounds: int = 8,
    ) -> None:
        if not isinstance(spec, FrameSpec):
            raise FrameRuleError(
                "FrameBuilder 需要 FrameSpec，实际 {}".format(type(spec).__name__)
            )
        if max_rounds < 1:
            raise FrameRuleError("max_rounds 至少为 1")
        self.spec = spec
        self.max_rounds = int(max_rounds)
        self._device_id = device_id
        self._compiled = compile_rules(list(spec.fields), spec.device)
        self._keys = [cf.key for cf in self._compiled]
        self._index = {key: i for i, key in enumerate(self._keys)}
        self._length_index = (
            self._index[spec.length.key] if spec.length is not None else None
        )
        # 校验规则归一化：单校验和直接用；一帧多校验和时组帧侧只回填第一个
        # （多校验和完整组帧暂不支持，见 _build_frame 的显式拒绝）。
        checksum_spec = spec.checksum
        if checksum_spec is None:
            self._crc_rule: Optional[ChecksumRule] = None
        elif isinstance(checksum_spec, ChecksumRule):
            self._crc_rule = checksum_spec
        else:
            rules = list(checksum_spec)
            self._crc_rule = rules[0] if rules else None
        self._crc_index = (
            self._index[self._crc_rule.key] if self._crc_rule is not None else None
        )
        # 自动填值字段：0 个、1 个或多个，各自独立维护计数器/取值方式
        self._autos: List[_AutoState] = [_AutoState(p) for p in spec.auto]
        self._auto_keys: List[str] = [st.policy.key for st in self._autos]
        self._pdu_compiled: Dict[Any, List[CompiledField]] = {}
        for cmd, pdu in spec.pdus.items():
            self._pdu_compiled[cmd] = self._compile_payload(pdu)
        self._fixed: Dict[str, bytes] = {}
        for cf in self._compiled:
            # 定长（或无长度）的常量字段在构造期就转成字节，写错了立刻报
            if cf.fixed is None or cf.is_device:
                continue
            if isinstance(cf.length, int) or cf.length is None:
                self._fixed[cf.key] = self._fixed_raw(cf, {})

    # ------------------------------------------------------------------ 对外
    @property
    def device_id(self) -> Any:
        return self._device_id

    @device_id.setter
    def device_id(self, value: Any) -> None:
        self._device_id = value

    @property
    def seq(self) -> int:
        """第一个自增计数器**下一个**将被填入的值（兼容旧写法）。"""
        for st in self._autos:
            if st.policy.provider is None:
                return st.value
        return 0

    @property
    def auto_keys(self) -> List[str]:
        """所有自动填值字段的字段名（按声明顺序）。"""
        return list(self._auto_keys)

    def build(self, target: Any, /, **values: Any) -> bytes:
        """组一帧，返回线上字节（分隔符定界已加标志位并转义）。"""
        return self.build_frame(target, **values).data

    def build_frame(self, target: Any, /, **values: Any) -> BuildResult:
        """组一帧并返回细节（每轮轨迹、字段值、净帧字节）。"""
        return self._build_frame(*self._select(target), values=values)

    def build_raw(
        self, target: Any, payload: Any = b"", /, **values: Any
    ) -> bytes:
        """整段载荷模式：不查 Pdu 的字段表，把 ``payload`` 原样放进载荷字段。

        与 :meth:`build` 的区别只在载荷怎么来：``build`` 按 ``Pdu.fields`` 逐个
        打包，``build_raw`` 直接把一段字节塞进去（长度仍由长度字段自动回填）。
        其余帧壳字段（seq/devid 等）照旧用关键字参数给。

        ``payload`` 可以是 ``bytes``、``Data.xxx(...)`` 的结果，或由它们组成的
        列表/元组（等价于先调用 :func:`kkprotocol.pack`)。
        """
        key = self.spec.payload
        if key is None:
            raise FrameBuildError("这帧没有载荷字段（FrameSpec.payload），不需要给载荷")
        _, cmd_value = self._select(target)
        merged = dict(values)
        merged[key] = _coerce_payload(payload)
        return self._build_frame(None, cmd_value, merged).data

    def _build_frame(
        self,
        pdu: Optional[Pdu],
        cmd_value: Any,
        values: Dict[str, Any],
    ) -> BuildResult:
        # 一帧多校验和：组帧侧只回填第一个校验和，其余无法自动计算，明确报错
        if isinstance(self.spec.checksum, (list, tuple)) and len(self.spec.checksum) > 1:
            raise FrameBuildError(
                "FrameBuilder 暂不支持一帧多校验和（当前 {} 个），请手工组帧"
                "（解析侧已支持一帧多校验和）".format(len(self.spec.checksum))
            )
        if pdu is not None and pdu.fields and self.spec.payload is None:
            raise FrameBuildError(
                "Pdu {!r} 声明了载荷字段，但 FrameSpec.payload 没指定装进哪个字段".format(
                    pdu.name
                )
            )
        payload_cf = self._payload_fields(pdu)

        values = dict(values)
        accepted = self._check_arguments(pdu, payload_cf, values)
        cmd_key = self.spec.cmd_key
        if cmd_key is None:
            if cmd_value is not None:
                raise FrameBuildError(
                    "这帧没有命令码字段（FrameSpec.cmd），无法写入指令 {!r}".format(
                        cmd_value
                    )
                )
        elif cmd_value is not None:
            values[cmd_key] = cmd_value

        self._check_missing(payload_cf, values, accepted)
        device_raw = self._device_raw(values)
        auto_values = self._take_autos(values)

        state_len = 0 if self._length_index is not None else None
        state_crc = self._zero_crc()
        trace: List[Tuple[int, Optional[int], bytes, Optional[int], bytes]] = []
        seen: Dict[Tuple[Optional[int], bytes], int] = {}

        for round_no in range(1, self.max_rounds + 1):
            draft = self._assemble(
                pdu, payload_cf, values, state_len, state_crc, device_raw, auto_values
            )
            measured = (
                self._measure(draft) if self._length_index is not None else None
            )
            computed = self._checksum(draft) if self._crc_index is not None else b""
            trace.append((round_no, state_len, state_crc, measured, computed))

            if measured == state_len and computed == state_crc:
                return self._finish(draft, pdu, cmd_value, round_no, trace)

            state_len, state_crc = measured, computed
            signature = (measured, computed)
            first = seen.get(signature)
            if first is not None:
                raise FrameBuildError(
                    "长度/校验回填在第 {} 轮与第 {} 轮之间来回震荡，规则自相矛盾"
                    "（常见原因：校验函数每次算出来不一样，或校验的 group 里包含了"
                    "校验字段自己）\n{}".format(
                        first, round_no, self._format_trace(trace)
                    )
                )
            seen[signature] = round_no

        raise FrameBuildError(
            "回填 {} 轮仍未收敛（规则可能自相矛盾），可加大 max_rounds 排查\n{}".format(
                self.max_rounds, self._format_trace(trace)
            )
        )

    # ------------------------------------------------------------------ 目标
    def _select(self, target: Any) -> Tuple[Optional[Pdu], Any]:
        """把"指令名/命令码/Pdu"解析成 ``(pdu, cmd 值)``；未声明的命令码按原样用。"""
        spec = self.spec
        if target is None:  # 纯载荷帧（没有命令码字段）可以直接这么组
            return None, None
        if isinstance(target, Pdu):
            if target.cmd is None:
                # Pdu 省略了 cmd：按名字+字段表对回已声明的那份（它的 cmd 已由字典键回填）
                for pdu in spec.pdus.values():
                    if pdu.name == target.name and tuple(pdu.fields) == tuple(target.fields):
                        return pdu, pdu.cmd
                raise FrameBuildError(
                    "Pdu {!r} 没有命令码：不在 FrameSpec.pdus 里就无从回填，"
                    "请显式写成 Pdu({!r}, <命令码>, ...)".format(target.name, target.name)
                )
            declared = self._lookup_pdu(target.cmd)
            return (declared if declared == target else target), target.cmd
        found = self._lookup_pdu(target)
        if found is not None:
            return found, found.cmd
        for pdu in spec.pdus.values():
            if pdu.name == target:
                return pdu, pdu.cmd
        if isinstance(target, str):
            raise FrameBuildError(
                "找不到报文 {!r}，已声明: {}".format(
                    target, [pdu.name for pdu in spec.pdus.values()]
                )
            )
        if isinstance(target, bool) or not isinstance(target, int):
            raise FrameBuildError(
                "组帧目标必须是命令码(int)、指令名(str) 或 Pdu，实际 {!r}".format(target)
            )
        return None, target

    def _lookup_pdu(self, cmd: Any) -> Optional[Pdu]:
        try:
            return self.spec.pdus.get(cmd)
        except TypeError:  # cmd 不可哈希（如 list），当作未声明
            return None

    def _payload_fields(self, pdu: Optional[Pdu]) -> List[CompiledField]:
        if pdu is None:
            return []
        declared = self._lookup_pdu(pdu.cmd)
        if declared is not None and declared == pdu:
            return self._pdu_compiled[pdu.cmd]
        return self._compile_payload(pdu)

    def _compile_payload(self, pdu: Pdu) -> List[CompiledField]:
        """载荷字段与帧壳字段一起编译：载荷里的长度表达式可以引用 ``{len.val}``。"""
        combined = compile_rules(list(self.spec.fields) + list(pdu.fields), None)
        payload_cf = combined[len(self._keys) :]
        for cf in payload_cf:
            if cf.is_crc:
                raise FrameRuleError(
                    "Pdu {!r} 的载荷字段 {!r} 不能声明 crc/group："
                    "自动校验只支持帧壳字段（放在载荷之后的壳字段上）".format(
                        pdu.name, cf.key
                    )
                )
        return payload_cf

    # ------------------------------------------------------------------ 参数
    def _check_arguments(
        self, pdu: Optional[Pdu], payload_cf: Sequence[CompiledField], values: Dict[str, Any]
    ) -> List[str]:
        auto = [key for key in (self._length_key(), self._crc_key()) if key is not None]
        accepted = [key for key in self._keys if key not in auto]
        if payload_cf:
            # 载荷由 Pdu 的字段拼出来，此时不能再直接塞整段 data=
            accepted = [key for key in accepted if key != self.spec.payload]
            accepted += [cf.key for cf in payload_cf]

        for key in auto:
            if key in values:
                raise FrameBuildError(
                    "字段 {!r} 由 builder 自动计算（长度/校验），不要手动传".format(key)
                )
        unknown = [key for key in values if key not in accepted]
        if unknown:
            raise FrameBuildError(
                "不认识的参数 {}；这帧可用: {}".format(unknown, accepted)
            )
        if pdu is not None and self.spec.cmd_key is None:
            raise FrameBuildError(
                "这帧没有命令码字段（FrameSpec.cmd），无法写入指令 {}".format(pdu.name)
            )
        cmd_key = self.spec.cmd_key
        if (
            pdu is not None
            and cmd_key is not None
            and cmd_key in values
            and values[cmd_key] != pdu.cmd
        ):
            raise FrameBuildError(
                "cmd 字段 {!r} 与目标指令 {!r} 冲突：一个帧只能有一个命令码".format(
                    cmd_key, pdu.cmd
                )
            )
        return accepted

    def _check_missing(
        self,
        payload_cf: Sequence[CompiledField],
        values: Dict[str, Any],
        accepted: Sequence[str],
    ) -> None:
        missing: List[str] = []
        for cf in self._compiled:
            if cf.key in (self._length_key(), self._crc_key()):
                continue
            if cf.key == self.spec.payload:
                continue  # 载荷缺省就是"空载荷"，长度表达式会当场核对
            if cf.fixed is not None or cf.is_device:
                continue
            if cf.key in self._auto_keys and cf.key not in values:
                continue
            if cf.key not in values:
                missing.append(cf.key)
        for cf in payload_cf:
            if cf.fixed is None and cf.key not in values:
                missing.append(cf.key)
        if missing:
            raise FrameBuildError(
                "缺少参数 {}；这帧可用: {}".format(missing, accepted)
            )

    def _length_key(self) -> Optional[str]:
        return self.spec.length.key if self.spec.length is not None else None

    def _crc_key(self) -> Optional[str]:
        """校验字段名（组帧回填目标）。一帧多校验和时返回第一个。"""
        return self._crc_rule.key if self._crc_rule is not None else None

    def _zero_crc(self) -> bytes:
        if self._crc_index is None:
            return b""
        cf = self._compiled[self._crc_index]
        return b"\x00" * int(cf.length)  # type: ignore[arg-type]

    # ------------------------------------------------------------------ 拼装
    def _assemble(
        self,
        pdu: Optional[Pdu],
        payload_cf: Sequence[CompiledField],
        values: Dict[str, Any],
        length_value: Optional[int],
        crc_raw: bytes,
        device_raw: Optional[bytes],
        auto_values: Dict[str, Any],
    ) -> _Draft:
        draft = _Draft()
        for index, cf in enumerate(self._compiled):
            key = cf.key
            if index == self._length_index:
                raw = self._pack_int(cf, length_value)  # type: ignore[arg-type]
            elif index == self._crc_index:
                raw = crc_raw
            elif key == self.spec.payload:
                if pdu is not None and payload_cf:
                    raw = self._pack_payload(pdu, payload_cf, values, draft.fields)
                else:
                    # 直接给整段载荷：字节数就是长度，不套长度表达式（否则长度↔载荷
                    # 互相依赖，永远解不开）；末尾由 _check_payload_length 统一核对
                    raw = self._payload_bytes(cf, values.get(key, b""))
            elif cf.is_device and device_raw is not None:
                raw = device_raw
            elif cf.fixed is not None:
                cached = self._fixed.get(key)
                raw = cached if cached is not None else self._fixed_raw(cf, draft.fields)
            elif key in auto_values:
                raw = self._pack_auto(cf, auto_values[key], draft.fields)
            else:
                raw = self._pack_value(cf, values[key], draft.fields)
            draft.parts.append(raw)
            draft.fields[key] = FieldValue(key, raw, self._value_of(cf, raw))
        return draft

    def _payload_bytes(self, cf: CompiledField, value: Any) -> bytes:
        """整段载荷：只认 bytes/str，长度以实际字节数为准。"""
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8")
        raise FrameBuildError(
            "载荷字段 {!r} 需要 bytes/str（整段给），实际 {}；"
            "想按字段逐个填请声明 Pdu".format(cf.key, type(value).__name__)
        )

    def _pack_payload(
        self,
        pdu: Pdu,
        payload_cf: Sequence[CompiledField],
        values: Dict[str, Any],
        shell_fields: Dict[str, FieldValue],
    ) -> bytes:
        out: List[bytes] = []
        ctx = dict(shell_fields)  # 载荷内表达式可以引用 {len.val} 这类帧壳字段
        for cf in payload_cf:
            if cf.fixed is not None and cf.key not in values:
                raw = self._fixed_raw(cf, ctx)
            else:
                raw = self._pack_value(cf, values[cf.key], ctx)
            out.append(raw)
            ctx[cf.key] = FieldValue(cf.key, raw, self._value_of(cf, raw))
        return b"".join(out)

    # ------------------------------------------------------------------ 长度
    def _measure(self, draft: _Draft) -> int:
        """按 ``LengthRule`` 量出长度字段该填的值。"""
        rule = self.spec.length
        if rule is None:  # pragma: no cover - 调用处已按 None 分支处理
            return 0
        sizes = draft.sizes
        if rule.span is None:
            start, end = self._length_index + 1, len(sizes)  # type: ignore[operator]
        else:
            start = self._index[rule.span[0]]
            end = self._index[rule.span[1]] + 1
        return sum(sizes[start:end])

    # ------------------------------------------------------------------ 校验
    def _checksum(self, draft: _Draft) -> bytes:
        rule = self._crc_rule
        if rule is None:  # pragma: no cover - 调用处已按 None 分支处理
            return b""
        cf = self._compiled[self._crc_index]  # type: ignore[index]
        data = b"".join(draft.fields[key].raw for key in self.spec.group_keys(rule.key))
        value = rule.impl(data)
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            if len(raw) != cf.length:
                raise FrameBuildError(
                    "校验函数返回 {} 字节，但字段 {!r} 声明 {} 字节".format(
                        len(raw), cf.key, cf.length
                    )
                )
            return raw
        if isinstance(value, bool) or not isinstance(value, int):
            raise FrameBuildError(
                "校验函数必须返回 int 或 bytes，实际 {}".format(type(value).__name__)
            )
        return self._pack_int(cf, value)

    # ------------------------------------------------------------------ 收尾
    def _finish(
        self,
        draft: _Draft,
        pdu: Optional[Pdu],
        cmd_value: Any,
        rounds: int,
        trace: Sequence[Tuple[int, Optional[int], bytes, Optional[int], bytes]],
    ) -> BuildResult:
        body = draft.body
        if len(body) > self.spec.max_frame_size:
            raise FrameBuildError(
                "帧长 {} 超过 max_frame_size={}".format(len(body), self.spec.max_frame_size)
            )
        self._check_payload_length(draft, pdu)
        framing = self.spec.framing
        data = (
            wrap_frame(body, framing)
            if isinstance(framing, DelimiterFraming)
            else body
        )
        return BuildResult(
            data=data,
            body=body,
            fields=draft.fields,
            rounds=rounds,
            trace=tuple(trace),
            cmd=cmd_value,
            name=pdu.name if pdu is not None else "",
        )

    def _check_payload_length(self, draft: _Draft, pdu: Optional[Pdu]) -> None:
        """回环校验：载荷字段声明的长度必须和实际载荷字节数一致。

        写得对不上时帧仍然"发得出去"，但对面按同一套规则解析会错位，属于最难查
        的一类问题，因此在组帧末尾直接拦下来。
        """
        key = self.spec.payload
        if key is None:
            return
        cf = self._compiled[self._index[key]]
        expected = self._resolve_length(cf, draft.fields)
        if expected is None:
            return
        actual = len(draft.fields[key].raw)
        if expected != actual:
            raise FrameBuildError(
                "载荷字段 {!r} 声明长度 {}，但载荷实际 {} 字节{}；"
                "对面按同一规则解析会错位".format(
                    key,
                    "（{}）".format(cf.length.source)
                    if isinstance(cf.length, LengthExpr)
                    else expected,
                    actual,
                    "（Pdu {!r}）".format(pdu.name) if pdu is not None else "",
                )
            )

    # ------------------------------------------------------------------ 取值
    def _pack_value(self, cf: CompiledField, value: Any, ctx: Dict[str, FieldValue]) -> bytes:
        expect = self._resolve_length(cf, ctx)
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)  # 已经打好的字节，直接放行（长度下面统一校验）
        elif cf.struct is not None:
            raw = self._struct_pack(cf, value)
        else:
            raw = self._coerce_bytes(cf, value, expect)
        if expect is not None and len(raw) != expect:
            raise FrameBuildError(
                "字段 {!r} 需要 {} 字节，实际给了/打包出 {} 字节".format(
                    cf.key, expect, len(raw)
                )
            )
        return raw

    def _struct_pack(self, cf: CompiledField, value: Any) -> bytes:
        st = cf.struct
        if st is None:  # pragma: no cover - 调用前已判断
            raise FrameBuildError("字段 {!r} 没有 fmt".format(cf.key))
        try:
            return st.pack(value)
        except struct.error as exc:
            raise FrameBuildError(
                "字段 {!r} 的值 {!r} 装不进 fmt {!r}: {}".format(
                    cf.key, value, cf.fmt, exc
                )
            ) from exc

    def _coerce_bytes(self, cf: CompiledField, value: Any, expect: Optional[int]) -> bytes:
        """无 fmt 的字段：bytes/str/int 都接受。"""
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, bool):
            raise FrameBuildError(
                "字段 {!r} 不收布尔值，请给 bytes/str/int".format(cf.key)
            )
        if isinstance(value, int):
            width = expect if expect is not None else 1
            try:
                return value.to_bytes(width, "big")
            except OverflowError:
                raise FrameBuildError(
                    "字段 {!r} 的值 {} 超出 {} 字节可表示范围".format(
                        cf.key, value, width
                    )
                ) from None
        raise FrameBuildError(
            "字段 {!r} 的值必须是 bytes/str/int，实际 {}".format(
                cf.key, type(value).__name__
            )
        )

    def _pack_int(self, cf: CompiledField, value: Any) -> bytes:
        if isinstance(value, bool) or not isinstance(value, int):
            raise FrameBuildError(  # pragma: no cover - 调用处已保证是 int
                "字段 {!r} 需要整数，实际 {!r}".format(cf.key, value)
            )
        if cf.struct is not None:
            return self._struct_pack(cf, value)
        width = cf.length if isinstance(cf.length, int) else 1
        try:
            return value.to_bytes(width, "big")
        except OverflowError:
            raise FrameBuildError(
                "字段 {!r} 的值 {} 超出 {} 字节可表示范围（多为长度/序列号越界）".format(
                    cf.key, value, width
                )
            ) from None

    def _resolve_length(
        self, cf: CompiledField, ctx: Dict[str, FieldValue]
    ) -> Optional[int]:
        """算出一个字段这次该占多少字节；``None`` 表示"取到帧尾"。"""
        length = cf.length
        if length is None:
            return None
        if isinstance(length, int):
            return length
        try:
            if isinstance(length, LengthExpr):
                value = length.evaluate(ctx)
            else:
                value = length(ctx)
        except FrameInvalid as exc:
            raise FrameBuildError(
                "字段 {!r} 的长度表达式求值失败: {}".format(cf.key, exc)
            ) from exc
        except FrameRuleError:
            raise
        except Exception as exc:  # 开发者的长度回调抛错
            raise FrameBuildError(
                "字段 {!r} 的长度回调异常: {}".format(cf.key, exc)
            ) from exc
        if isinstance(value, bool) or not isinstance(value, int):
            raise FrameBuildError(
                "字段 {!r} 的长度必须是 int，实际 {!r}".format(cf.key, value)
            )
        if value < 0:
            raise FrameBuildError(
                "字段 {!r} 算出负长度 {}（表达式或参数不对）".format(cf.key, value)
            )
        return int(value)

    def _value_of(self, cf: CompiledField, raw: bytes) -> Any:
        if cf.struct is not None and cf.fmt_size == len(raw):
            return cf.struct.unpack(raw)[0]
        return raw

    def _fixed_raw(self, cf: CompiledField, ctx: Dict[str, FieldValue]) -> bytes:
        fixed = cf.fixed
        if isinstance(fixed, (bytes, bytearray, memoryview)):
            raw = bytes(fixed)
        elif isinstance(fixed, str):
            raw = fixed.encode("utf-8")
        elif isinstance(fixed, int):
            raw = self._struct_pack(cf, fixed) if cf.struct is not None else bytes([fixed])
        else:  # pragma: no cover - 声明阶段的怪值
            raise FrameBuildError(
                "字段 {!r} 的 fixed 必须是 bytes/str/int，实际 {}".format(
                    cf.key, type(fixed).__name__
                )
            )
        expect = self._resolve_length(cf, ctx)
        if expect is not None and len(raw) != expect:
            raise FrameBuildError(
                "常量字段 {!r} 的值 {} 字节，但字段声明 {} 字节".format(
                    cf.key, len(raw), expect
                )
            )
        return raw

    # ------------------------------------------------------------------ 设备号
    def _device_raw(self, values: Dict[str, Any]) -> Optional[bytes]:
        key = self.spec.device
        if key is None:
            return None
        cf = self._compiled[self._index[key]]
        value = values.get(key)
        if value is None:
            value = self._device_id
        if value is None:
            raise FrameBuildError(
                "设备号字段 {!r} 没有值：构造时传 device_id=...，或 build(..., {}=...)"
                "；若设备号就放在载荷里，请改写 FrameSpec.device".format(key, key)
            )
        if cf.struct is not None:
            return self._pack_value(cf, value, {})
        if isinstance(value, str):
            raw = value.encode("utf-8")
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
        else:
            raw = self._coerce_bytes(cf, value, None)
        expect = self._resolve_length(cf, {})
        if expect is not None:
            if len(raw) > expect:
                raise FrameBuildError(
                    "设备号 {!r} 有 {} 字节，超过字段 {!r} 的 {} 字节".format(
                        raw, len(raw), key, expect
                    )
                )
            raw = raw.ljust(expect, b"\x00")  # 不足右侧补 0x00，与设备端一致
        return raw

    # ------------------------------------------------------------------ 自动字段
    def _take_autos(self, values: Dict[str, Any]) -> Dict[str, Any]:
        """给所有自动填值字段各取一个值（每帧调用一次，计数器只前进一格）。"""
        out: Dict[str, Any] = {}
        for st in self._autos:
            key = st.policy.key
            if key in values:
                value = values[key]
                if st.policy.provider is None:
                    if isinstance(value, bool) or not isinstance(value, int):
                        raise FrameBuildError(
                            "自增字段 {!r} 需要整数，实际 {!r}".format(key, value)
                        )
                    # 显式指定后，自动计数从这个值之后接着走
                    st.value = (value + st.policy.step) % st.policy.wrap
                out[key] = value
            elif st.policy.provider is None:
                value = st.value
                st.value = (value + st.policy.step) % st.policy.wrap
                out[key] = value
            else:
                out[key] = st.policy.provider()
        return out

    def _pack_auto(
        self, cf: CompiledField, value: Any, ctx: Dict[str, FieldValue]
    ) -> bytes:
        """自动字段的值：计数器给 int，provider 也可能给 bytes。"""
        if isinstance(value, (bytes, bytearray, memoryview)):
            return self._pack_value(cf, value, ctx)
        return self._pack_int(cf, value)

    # ------------------------------------------------------------------ 其他
    def echo_value(self, key: str, frame: Frame) -> Any:
        """从收到的帧里取同名字段的值用于回显（tx 要整数就给整数，否则给字节）。"""
        cf = self._compiled[self._index[key]]
        fv = frame.fields[key]
        return fv.val if cf.struct is not None else fv.raw

    def _format_trace(
        self, trace: Sequence[Tuple[int, Optional[int], bytes, Optional[int], bytes]]
    ) -> str:
        lines = []
        for round_no, written_len, written_crc, measured, computed in trace:
            lines.append(
                "  第 {} 轮: 帧内 len={} crc={} → 量出 len={} 算出 crc={}".format(
                    round_no,
                    "-" if written_len is None else written_len,
                    written_crc.hex().upper() or "-",
                    "-" if measured is None else measured,
                    computed.hex().upper() or "-",
                )
            )
        return "\n".join(lines)

    def __repr__(self) -> str:  # pragma: no cover - 调试展示
        return "<FrameBuilder cmd={!r} fields={}>".format(self.spec.cmd_key, self._keys)


class Protocol:
    """一个方向对（收/发）的粘合层：``build`` 发出去、``feed`` 收进来。

    ``tx`` 是**我方发出**的帧格式，``rx`` 是**我方接收**的帧格式；两者格式相同
    就传同一个对象。收发不对称的协议（例如应答帧少了某个字段、命令码差 0x80）
    各写一份即可，互不影响。
    """

    def __init__(
        self,
        tx: FrameSpec,
        rx: Optional[FrameSpec] = None,
        *,
        device_id: Any = None,
        enforce_device_id: bool = False,
        max_rounds: int = 8,
    ) -> None:
        self.tx = tx
        self.rx = rx if rx is not None else tx
        self.builder = FrameBuilder(tx, device_id=device_id, max_rounds=max_rounds)
        self.enforce_device_id = enforce_device_id
        self._codec = None

    # ------------------------------------------------------------------ 属性
    @property
    def device_id(self) -> Any:
        return self.builder.device_id

    @device_id.setter
    def device_id(self, value: Any) -> None:
        self.builder.device_id = value
        if self._codec is not None:
            self._codec.bind_device(value)

    @property
    def codec(self):
        """接收侧解析器（首次访问时创建）。"""
        if self._codec is None:
            codec = self.rx.to_codec()
            codec.enforce_device_id = self.enforce_device_id
            if self.builder.device_id is not None:
                codec.bind_device(self.builder.device_id)
            self._codec = codec
        return self._codec

    # ------------------------------------------------------------------ 发送
    def build(self, target: Any, /, **values: Any) -> bytes:
        """组一帧，返回线上字节。"""
        return self.builder.build(target, **values)

    def build_frame(self, target: Any, /, **values: Any) -> BuildResult:
        """组一帧并返回细节（轨迹/字段值/净帧字节）。"""
        return self.builder.build_frame(target, **values)

    def build_raw(
        self, target: Any, payload: Any = b"", /, **values: Any
    ) -> bytes:
        """整段载荷模式：载荷不再按 ``Pdu.fields`` 打包，直接塞一段字节。

        ``payload`` 可以是 ``bytes``、``Data.xxx(...)``，或它们的列表
        （见 :func:`kkprotocol.pack`）。
        """
        return self.builder.build_raw(target, payload, **values)

    def build_ack(self, req: Union[Frame, Pdu, int, str], /, **values: Any) -> bytes:
        """给收到的帧组一条应答：命令码取 ``cmd|0x80``（或 ``Pdu.resp``），
        序列号/设备号默认回显请求帧里的同名字段。"""
        cmd_value, echo = self._ack_context(req)
        for key, value in echo.items():
            values.setdefault(key, value)
        return self.builder.build(cmd_value, **values)

    def _ack_context(self, req: Union[Frame, Pdu, int, str]) -> Tuple[Any, Dict[str, Any]]:
        echo: Dict[str, Any] = {}
        if isinstance(req, Frame):
            rx_cmd = self.rx.cmd_key
            if rx_cmd is None or rx_cmd not in req:
                raise FrameBuildError(
                    "收到的帧里没有命令码字段（rx.cmd={!r}），无法推导应答命令码".format(
                        rx_cmd
                    )
                )
            cmd_value = req.value(rx_cmd)
            # 回显：所有声明 echo=True 的自动字段 + 设备号
            echo_keys: List[Optional[str]] = [
                st.policy.key for st in self.builder._autos if st.policy.echo
            ]
            echo_keys.append(self.tx.device)
            for key in echo_keys:
                if key is not None and key in req:
                    echo[key] = self._echo_value(key, req)
        elif isinstance(req, Pdu):
            cmd_value = req.cmd
            if cmd_value is None:
                # Pdu 省略了 cmd：按名字对回已声明的那份
                matched = [p for p in self.tx.pdus.values() if p.name == req.name]
                if not matched:
                    raise FrameBuildError(
                        "Pdu {!r} 没有命令码：不在 tx.pdus 里就无从回填，"
                        "请显式写成 Pdu({!r}, <命令码>, ...)".format(req.name, req.name)
                    )
                cmd_value = matched[0].cmd
        else:
            pdu = self.tx.pdus.get(req) if isinstance(req, int) else None
            if pdu is None:
                matched = [p for p in self.tx.pdus.values() if p.name == req]
                pdu = matched[0] if matched else None
            if pdu is None:
                if isinstance(req, str):
                    raise FrameBuildError("找不到报文 {!r}".format(req))
                cmd_value = req
            else:
                cmd_value = pdu.cmd
        return self._ack_cmd(cmd_value), echo

    def _ack_cmd(self, cmd_value: Any) -> Any:
        pdu = self.tx.pdus.get(cmd_value) if isinstance(cmd_value, int) else None
        if pdu is not None and pdu.resp is not None:
            return pdu.resp
        if isinstance(cmd_value, int) and not isinstance(cmd_value, bool):
            return cmd_value | 0x80
        raise FrameBuildError(
            "无法从 {!r} 推导应答命令码：请在 Pdu.resp 里显式写出".format(cmd_value)
        )

    def _echo_value(self, key: str, frame: Frame) -> Any:
        """回显请求帧里的同名字段：tx 需要整数就取解出的值，否则取原始字节。"""
        return self.builder.echo_value(key, frame)

    # ------------------------------------------------------------------ 接收
    def feed(self, chunk: Union[bytes, bytearray, memoryview]) -> List[Frame]:
        """喂入收到的字节，返回解析出的帧。"""
        return self.codec.feed(chunk)

    def verify(self, data: Union[bytes, bytearray, memoryview]) -> Frame:
        """回环自检：把刚组出来的字节用收帧规则解析一遍，必须一帧一字节不剩。"""
        codec = self.rx.to_codec()
        codec.enforce_device_id = self.enforce_device_id
        if self.builder.device_id is not None:
            codec.bind_device(self.builder.device_id)
        payload = bytes(data)
        frames = codec.feed(payload)
        if len(frames) != 1 or frames[0].wire != payload:
            raise FrameBuildError(
                "回环自检失败：{} 字节只解析出 {} 帧。收帧规则与发帧规则对不上，"
                "用 Protocol.diff() 看差异".format(len(payload), len(frames))
            )
        return frames[0]

    def diff(self) -> List[str]:
        """收发两份 spec 的差异清单。"""
        if self.tx is self.rx:
            return []
        return self.tx.diff(self.rx)

    def reset(self) -> None:
        """清掉接收侧未成帧的残留（重连时调用）。"""
        self.codec.reset()

    def __repr__(self) -> str:  # pragma: no cover - 调试展示
        return "<Protocol tx={} rx={} device={!r}>".format(
            self.tx.cmd_key, self.rx.cmd_key, self.builder.device_id
        )
