# -*- coding: utf-8 -*-
"""贡献协议集（contrib）：从网上收集的真实通讯协议，用来压测 kkprotocol 的设计健壮性。

这些模块**不会**出现在 ``kkprotocol.__init__`` 顶层导出里，只是包内模块，
按需 ``from kkprotocol.contrib import dlt645`` 即可得到。每个模块都尽量用当前
的声明式 ``FrameSpec`` / ``Protocol`` / ``FrameBuilder`` 落地，并显式标注哪些地方
暴露了设计上的纰漏（见各模块 docstring 与 tests/test_contrib_protocols.py）。
"""
