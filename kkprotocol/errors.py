# -*- coding: utf-8 -*-
"""异常定义。"""

from __future__ import annotations

__all__ = ["FrameCodecError", "FrameRuleError", "FrameBuildError"]


class FrameCodecError(Exception):
    """编解码器错误基类。"""


class FrameRuleError(FrameCodecError, ValueError):
    """规则/配置声明错误 —— 开发者写错了，属于代码缺陷，直接抛出不做重同步。

    典型场景：字段 key 重复、长度表达式引用前向字段、fmt 字节数与声明长度不一致、
    定界模式配置非法（定界符越界、转义字节与定界符冲突）。
    """


class FrameBuildError(FrameCodecError, ValueError):
    """组帧失败 —— 参数缺失/类型不符/长度越界/回填不收敛。

    与 :class:`FrameRuleError` 的区别：规则本身没错，是这次调用的入参或数据
    凑不出合法帧，属于调用方需要修的地方。
    """


class FrameInvalid(Exception):
    """内部信号：当前位置不是合法帧（脏数据 / 常量不符 / 校验失败 / 长度不符）。

    ``consumed > 0`` 表示该候选帧在流中占用的字节数已知（分隔符模式必然已知），
    重同步时可以直接跳过整段候选；``consumed == 0`` 表示只能逐字节/按锚点重试。
    """

    def __init__(
        self,
        reason: str,
        *,
        consumed: int = 0,
        crc_failed: bool = False,
        length_mismatch: bool = False,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.consumed = consumed
        self.crc_failed = crc_failed
        self.length_mismatch = length_mismatch
