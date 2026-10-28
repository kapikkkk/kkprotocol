# -*- coding: utf-8 -*-
"""长度表达式：``{len.val}-1-1-2-4-2`` 的编译与求值。

用 AST 白名单求值，**不使用 eval**，因此表达式无法执行任意代码。
编译期做常量折叠（``-1-1-2-4-2`` 折叠成 ``-10``），解析期只剩一次减法。
"""

from __future__ import annotations

import ast
import itertools
import re
from typing import Any, Dict, Tuple

from .errors import FrameInvalid, FrameRuleError

__all__ = ["LengthExpr"]

_REF_RE = re.compile(r"\{\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\}")
_GROUP_REF_RE = re.compile(r"\{\s*([A-Za-z_]\w*)\s*\}")
_LEN_ATTRS = frozenset({"len", "length", "bytes", "raw"})

_BIN_OPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
}


def _eval_ast(node: ast.AST, values: Dict[str, int]) -> int:
    if isinstance(node, ast.Constant):
        return int(node.value)
    if isinstance(node, ast.Name):
        return values[node.id]
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.USub):
            return -_eval_ast(node.operand, values)
        return _eval_ast(node.operand, values)
    if isinstance(node, ast.BinOp):
        op = _BIN_OPS[type(node.op)]
        try:
            return op(_eval_ast(node.left, values), _eval_ast(node.right, values))
        except ZeroDivisionError:
            raise FrameInvalid("长度表达式除零") from None
    raise FrameRuleError(  # pragma: no cover - 编译期已拦截
        "长度表达式含不支持的语法节点 {}".format(type(node).__name__)
    )


def _fold(node: ast.AST) -> ast.AST:
    """编译期常量折叠。"""
    if isinstance(node, ast.BinOp):
        left = _fold(node.left)
        right = _fold(node.right)
        if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
            return ast.Constant(value=_BIN_OPS[type(node.op)](left.value, right.value))
        return ast.BinOp(left=left, op=node.op, right=right)
    if isinstance(node, ast.UnaryOp) and isinstance(node.operand, ast.Constant):
        value = node.operand.value
        return ast.Constant(value=-value if isinstance(node.op, ast.USub) else value)
    return node


class LengthExpr:
    """一个已编译的长度表达式。"""

    __slots__ = ("source", "_tree", "_names", "_refs")

    def __init__(self, source: str) -> None:
        self.source = source
        names: Dict[str, Tuple[str, str]] = {}
        counter = itertools.count()

        def _replace(match: "re.Match[str]") -> str:
            token = "_v{}".format(next(counter))
            names[token] = (match.group(1), match.group(2))
            return token

        expr = _REF_RE.sub(_replace, source)
        if not names:
            raise FrameRuleError(
                "长度 {!r} 既不是整数也不是含 {{字段.属性}} 的表达式".format(source)
            )
        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError as exc:
            raise FrameRuleError("长度表达式 {!r} 语法错误: {}".format(source, exc.msg)) from exc
        self._check(tree)
        try:
            folded = _fold(tree.body)
        except ZeroDivisionError:
            raise FrameRuleError("长度表达式 {!r} 含常量除零".format(source)) from None
        self._tree = ast.Expression(body=folded)
        self._names = names
        self._refs = tuple((token, key, attr) for token, (key, attr) in names.items())

    # ------------------------------------------------------------------ 校验
    @property
    def refs(self) -> Tuple[Tuple[str, str], ...]:
        return tuple(self._names.values())

    @staticmethod
    def _check(node: ast.AST) -> None:
        if isinstance(node, ast.Expression):
            LengthExpr._check(node.body)
            return
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool) or not isinstance(node.value, int):
                raise FrameRuleError("长度表达式只允许整数常量，发现 {!r}".format(node.value))
            return
        if isinstance(node, ast.Name):
            return
        if isinstance(node, ast.UnaryOp):
            if not isinstance(node.op, (ast.USub, ast.UAdd)):
                raise FrameRuleError("长度表达式不支持的运算符 {}".format(type(node.op).__name__))
            LengthExpr._check(node.operand)
            return
        if isinstance(node, ast.BinOp):
            if type(node.op) not in _BIN_OPS:
                raise FrameRuleError(
                    "长度表达式不支持的运算符 {}（只允许 + - * // %，除法请用 //）".format(
                        type(node.op).__name__
                    )
                )
            LengthExpr._check(node.left)
            LengthExpr._check(node.right)
            return
        raise FrameRuleError("长度表达式含不支持的语法节点 {}".format(type(node).__name__))

    # ------------------------------------------------------------------ 求值
    def evaluate(self, fields: Dict[str, Any]) -> int:
        values: Dict[str, int] = {}
        for token, key, attr in self._refs:
            fv = fields.get(key)
            if fv is None:  # pragma: no cover - 编译期已保证只引用前置字段
                raise FrameInvalid("长度表达式引用了未解析字段 {!r}".format(key))
            if attr == "val":
                val = fv.val
                if isinstance(val, bool) or not isinstance(val, int):
                    raise FrameInvalid(
                        "长度表达式引用了字段 {!r} 的 val，但它不是整数".format(key)
                    )
                values[token] = int(val)
            else:
                values[token] = len(fv.raw)
        result = _eval_ast(self._tree.body, values)
        if isinstance(result, bool) or not isinstance(result, int):  # pragma: no cover
            raise FrameInvalid("长度表达式 {!r} 结果不是整数".format(self.source))
        return result
