# -*- coding: utf-8 -*-
"""示例磁致伸缩位移传感器（A）（RS485 / Modbus RTU）。

协议来自某设备通讯规格书第 6 章，逐字节核对过：

读保持寄存器（03H）—— 请求固定 8 字节::

    Addr | 03h | RegH RegL | CntH CntL | CRCL CRCH
    01     03     00    04     00    03     44   0A      ← 读 0004H 起 3 个寄存器

读保持寄存器（03H）—— 响应变长，第 3 字节是后续数据字节数::

    Addr | 03h | N | Data(N) | CRCL CRCH
    01     03    06   00 77 99 45 01 AC   EB   DA

写单寄存器（06H）—— 请求与响应同格式（响应是原样回显）::

    Addr | 06h | RegH RegL | ValH ValL | CRCL CRCH
    01     06     00    2C     00    00     48   03

* CRC 是 Modbus 标准的 CRC16（多项式 0xA001，初值 0xFFFF），**低字节在前**
* 寄存器都是 16 位、**高字节在前**
* 03H 响应里的 "N" 是**字节数**（读 3 个寄存器 = 6），不是寄存器个数

本模块用 ``kkprotocol`` 的声明式描述把上述三种帧写清楚：请求帧全定长所以不需要
长度字段，响应帧靠 ``N`` 切帧；收发结构不同，所以是**两份 spec**。

.. note::
   规格书的"返回"示例有两个笔误，用 CRC 能反推出来（详见 :func:`decode_read_result`
   与 README）：示例写 ``00 77 CE 95``，但按文档自己的公式 0xCE95/0xFFFF = 0.807，
   与文档写的 0.598 对不上；把小数换成 ``99 45``（=0.598）后 CRC 才等于报文里的
   ``EB DA``。所以那 6 字节应为 ``00 77 99 45 01 AC``，文档笔误。
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from .builder import FrameBuilder, Protocol
from .crc import crc16_modbus
from .fields import Field
from .spec import ChecksumRule, FrameSpec

__all__ = [
    "FUNC_READ",
    "FUNC_WRITE",
    "REGISTERS",
    "crc_bytes_le",
    "RY_REQ",
    "RY_RSP",
    "protocol",
    "build_read",
    "build_write",
    "decode_registers",
    "decode_read_result",
]

FUNC_READ = 0x03
FUNC_WRITE = 0x06

# 规格书表一：保持寄存器地址（16 位）
REGISTERS: Dict[str, int] = {
    "POS1": 0x0000,  # 位置1：0000H 整数 / 0001H 小数
    "POS2": 0x0002,  # 位置2：0002H 整数 / 0003H 小数
    "POS3": 0x0004,  # 位置3：0004H 整数 / 0005H 小数
    "TEMP1": 0x0006,
    "TEMP2": 0x0007,
    "TEMP3": 0x0008,
    "TEMP4": 0x0009,
    "TEMP5": 0x000A,
    "TEMP6": 0x000B,
    "TEMP7": 0x000C,
    "TEMP8": 0x000D,
    "ADDR": 0x000E,        # 从站地址
    "FULL_SCALE": 0x000F,  # 满量程：000FH 整数 / 0010H 小数
    "ZERO": 0x0011,        # 零点：0011H 整数 / 0012H 小数
    "SPEED": 0x0013,       # 速度：0013H 整数 / 0014H 小数
    "POS_TEMP": 0x0015,    # 位置温度系数
    "SET_ADDR": 0x0020,    # 修改从站地址
    "DIR": 0x002C,         # 正反向：00H 反向 / FFH 正向
    "FACTORY": 0x002E,     # 恢复工厂设置（写 FFH）
    "ZERO_SHIFT": 0x0034,  # 零点迁移值（0034H/0035H/0036H）
}


def crc_bytes_le(data: bytes) -> bytes:
    """Modbus 线上 CRC：低字节在前，与报文字节直接对照（不走 int 解包）。"""
    return crc16_modbus(data).to_bytes(2, "little")


# ---------------------------------------------------------------- 请求帧：8 字节定长
# 03H 读请求与 06H 写请求结构完全相同（只是第 5/6 字节语义不同），共用一份 spec。
RY_REQ = FrameSpec(
    fields=[
        Field.u8("addr", desc="从站地址"),
        Field.u8("func", desc="03h 读 / 06h 写"),
        Field.u16("reg", desc="寄存器地址"),
        Field.u16("value", desc="读=寄存器数量；写=写入值"),
        Field(key="crc", length=2, crc=True, desc="CRC16/MODBUS，低字节在前"),
    ],
    cmd="func",
    device="addr",
    checksum=ChecksumRule("crc", crc_bytes_le),
    max_frame_size=16,
    desc="Modbus RTU 请求（03H/06H），固定 8 字节",
)

# ---------------------------------------------------------------- 响应帧：靠 N 切帧
RY_RSP = FrameSpec(
    fields=[
        Field.u8("addr", desc="从站地址"),
        Field.u8("func", fixed=FUNC_READ, desc="03h"),
        Field.u8("n", desc="后续数据字节数（读 3 个寄存器 = 6）"),
        Field.raw("data", "{n.val}", desc="寄存器数据，高字节在前"),
        Field(key="crc", length=2, crc=True, desc="CRC16/MODBUS，低字节在前"),
    ],
    payload="data",
    device="addr",
    checksum=ChecksumRule("crc", crc_bytes_le),
    max_frame_size=256,
    desc="Modbus RTU 读保持寄存器响应",
)


def protocol(device_id: Any = None, enforce_device_id: bool = False) -> Protocol:
    """一台设备一个实例：发 8 字节请求、收变长 03 响应。"""
    return Protocol(
        tx=RY_REQ, rx=RY_RSP, device_id=device_id, enforce_device_id=enforce_device_id
    )


_REQ_BUILDER = FrameBuilder(RY_REQ)


def build_read(addr: int, reg: int = REGISTERS["POS3"], count: int = 3) -> bytes:
    """组一条 03H 读请求（默认读位置3 的整数/小数 + 温度，共 3 个寄存器）。"""
    return _REQ_BUILDER.build(FUNC_READ, addr=addr, reg=reg, value=count)


def build_write(addr: int, reg: int, value: int) -> bytes:
    """组一条 06H 写单寄存器请求（响应是同字节回显）。"""
    return _REQ_BUILDER.build(FUNC_WRITE, addr=addr, reg=reg, value=value)


# ---------------------------------------------------------------- 数据解析
def decode_registers(data: bytes) -> Tuple[int, ...]:
    """把 Data 区按 16 位大端切成寄存器值。"""
    if len(data) % 2:
        raise ValueError("寄存器数据字节数必须是偶数，实际 {}".format(len(data)))
    return tuple(
        int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)
    )


def decode_read_result(data: bytes) -> Dict[str, Any]:
    """按规格书公式解出物理量。

    * 位置 = 整数寄存器 + 小数寄存器 / 0xFFFF（单位 mm）
    * 温度 = 温度寄存器 / 16（单位 ℃）

    读 3 个寄存器（默认）时三者都在；读 2 个只解位置；读 1 个只回原始值。
    """
    regs = decode_registers(data)
    if not regs:
        raise ValueError("读响应里没有数据")
    if len(regs) == 1:
        return {"value": regs[0], "registers": regs}
    result: Dict[str, Any] = {
        "position_mm": regs[0] + regs[1] / 0xFFFF,
        "registers": regs,
    }
    if len(regs) >= 3:
        result["temperature_c"] = regs[2] / 16.0
    if len(regs) > 3:
        result["extra"] = regs[3:]
    return result
