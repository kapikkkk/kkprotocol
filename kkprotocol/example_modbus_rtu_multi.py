# -*- coding: utf-8 -*-
"""示例磁致伸缩位移传感器（B，RS485 / Modbus RTU，V8.0 协议）。

协议取自某设备 Modbus 通讯协议 V8.0第 2~4 章，逐字节核对过：

读输入寄存器（04H）/ 读保持寄存器（03H）—— 请求固定 8 字节，响应带"数据字节数 N"::

    Addr | 04h | RegH RegL | CntH CntL | CRCL CRCH        ← 请求
    Addr | 04h | N | Data(N) | CRCL CRCH                ← 响应（N = 字节数）

写单寄存器（06H）—— 请求/响应同结构（8 字节）::

    Addr | 06h | RegH RegL | ValH ValL | CRCL CRCH

写多寄存器（10H）—— 请求多一个"字节数"字段，响应不带数据::

    Addr | 10h | RegH RegL | CntH CntL | Bcnt | Data | CRCL CRCH   ← 请求
    Addr | 10h | RegH RegL | CntH CntL | CRCL CRCH                ← 响应

异常响应：Addr | (func|0x80) | ErrCode(1) | CRCL CRCH

* CRC 是 CRC16/MODBUS，低字节在前（与示例 A 一致）
* 寄存器 16 位，高字节在前
* 位移整数方式：4 字节 = 高 2 字节 int16（整数部分）+ 低 2 字节 uint16（小数部分 / 65535）
* 位移浮点方式：4 字节单精度浮点，但字节序是 **CDAB**（要重排成 ABCD 才是标准大端）
* 温度：2 字节 int16，/100 = ℃

这份协议比示例 A 麻烦的地方在于：读响应带 N、写响应不带 N，结构不同。解析引擎
``to_codec()`` 是把整份字段平铺成一条固定结构，没法在一个 spec 里同时表达两种
响应。所以这里把每类响应写成独立 ``FrameSpec``，再用 :class:`MultiFuncProtocol`
按功能码自动分派——同一段粘在一起的字节流里读/写/异常帧混着来也能正确切分。

.. note::
    文档里浮点位移的字节序是 CDAB（小端字序 + 字节交换），不是常见的 ABCD。
    反例：响应数据 ``02 24 42 9D`` 要重排成 ``42 9D 02 24`` 再按大端单精度解，
    才得到 78.5042 mm。
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

from .builder import FrameBuilder, Protocol
from .crc import crc16_modbus
from .fields import Field
from .spec import ChecksumRule, FrameSpec

__all__ = [
    "FUNC_READ_INPUT",
    "FUNC_READ_HOLDING",
    "FUNC_WRITE_SINGLE",
    "FUNC_WRITE_MULTI",
    "REGISTERS",
    "crc_bytes_le",
    "XW_READ_TX",
    "XW_MULTI_TX",
    "XW_READ_RSP",
    "XW_WRITE_SINGLE_RSP",
    "XW_WRITE_MULTI_RSP",
    "XW_ERROR_RSP",
    "build_read",
    "build_read_holding",
    "build_write_single",
    "build_write_multiple",
    "split_registers",
    "decode_displacement_int",
    "decode_displacement_float",
    "decode_temperature",
    "MultiFuncProtocol",
]


FUNC_READ_INPUT = 0x04
FUNC_READ_HOLDING = 0x03
FUNC_WRITE_SINGLE = 0x06
FUNC_WRITE_MULTI = 0x10

REGISTERS: Dict[str, int] = {
    "POS1_INT": 0x0000,       # 位移1 整数方式（0000H 整数 + 0001H 小数）
    "POS1_FLOAT": 0x0006,     # 位移1 浮点方式（0006H + 0007H）
    "TEMP1": 0x000C,          # 温度1
    "ADDR": 0x0030,           # 从机地址
    "BAUD": 0x0031,           # 波特率
    "PARITY": 0x0032,         # 奇偶校验
}

BAUD_CODES: Dict[int, int] = {
    1200: 0x00, 2400: 0x01, 4800: 0x02, 9600: 0x03, 19200: 0x04,
    38400: 0x05, 57600: 0x06, 115200: 0x07, 256000: 0x08, 460800: 0x09,
}
PARITY_CODES: Dict[str, int] = {"odd": 0x01, "even": 0x02, "none": 0x03}


def crc_bytes_le(data: bytes) -> bytes:
    """Modbus 线上 CRC：低字节在前，与报文字节直接对照。"""
    return crc16_modbus(data).to_bytes(2, "little")


# ---------------------------------------------------------------- 发送：03/04/06 三类同结构（8 字节定长）
XW_READ_TX = FrameSpec(
    fields=[
        Field.u8("addr", desc="从站地址"),
        Field.u8("func", desc="03h 读保持 / 04h 读输入 / 06h 写单"),
        Field.u16("reg", desc="寄存器地址"),
        Field.u16("value", desc="读=寄存器个数；写=写入值"),
        Field(key="crc", length=2, crc=True, desc="CRC16/MODBUS，低字节在前"),
    ],
    cmd="func",
    device="addr",
    checksum=ChecksumRule("crc", crc_bytes_le),
    max_frame_size=16,
    desc="Modbus 读/写单寄存器请求（03H/04H/06H），固定 8 字节",
)

# ---------------------------------------------------------------- 发送：10H 写多寄存器（变长）
XW_MULTI_TX = FrameSpec(
    fields=[
        Field.u8("addr", desc="从站地址"),
        Field.u8("func", fixed=FUNC_WRITE_MULTI, desc="10h"),
        Field.u16("reg", desc="起始寄存器地址"),
        Field.u16("count", desc="寄存器个数"),
        Field.u8("bytecount", desc="数据字节数 = count * 2"),
        Field.raw("data", "{bytecount.val}", desc="各寄存器大端拼接"),
        Field(key="crc", length=2, crc=True, desc="CRC16/MODBUS，低字节在前"),
    ],
    cmd="func",
    payload="data",
    device="addr",
    checksum=ChecksumRule("crc", crc_bytes_le),
    max_frame_size=256,
    desc="Modbus 写多寄存器请求（10H）",
)

# ---------------------------------------------------------------- 接收：读响应（03H/04H，带字节数 N）
XW_READ_RSP = FrameSpec(
    fields=[
        Field.u8("addr", desc="从站地址"),
        Field.u8("func", desc="03h / 04h"),
        Field.u8("n", desc="后续数据字节数"),
        Field.raw("data", "{n.val}", desc="寄存器数据，高字节在前"),
        Field(key="crc", length=2, crc=True, desc="CRC16/MODBUS，低字节在前"),
    ],
    payload="data",
    device="addr",
    checksum=ChecksumRule("crc", crc_bytes_le),
    max_frame_size=256,
    desc="Modbus 读响应（03H/04H）",
)

# ---------------------------------------------------------------- 接收：06H 写单寄存器响应（8 字节定长）
XW_WRITE_SINGLE_RSP = FrameSpec(
    fields=[
        Field.u8("addr", desc="从站地址"),
        Field.u8("func", fixed=FUNC_WRITE_SINGLE, desc="06h"),
        Field.u16("reg", desc="寄存器地址"),
        Field.u16("value", desc="写入值"),
        Field(key="crc", length=2, crc=True, desc="CRC16/MODBUS，低字节在前"),
    ],
    device="addr",
    checksum=ChecksumRule("crc", crc_bytes_le),
    max_frame_size=16,
    desc="Modbus 写单寄存器响应（06H）",
)

# ---------------------------------------------------------------- 接收：10H 写多寄存器响应（8 字节定长）
XW_WRITE_MULTI_RSP = FrameSpec(
    fields=[
        Field.u8("addr", desc="从站地址"),
        Field.u8("func", fixed=FUNC_WRITE_MULTI, desc="10h"),
        Field.u16("reg", desc="起始寄存器地址"),
        Field.u16("count", desc="寄存器个数"),
        Field(key="crc", length=2, crc=True, desc="CRC16/MODBUS，低字节在前"),
    ],
    device="addr",
    checksum=ChecksumRule("crc", crc_bytes_le),
    max_frame_size=16,
    desc="Modbus 写多寄存器响应（10H）",
)

# ---------------------------------------------------------------- 接收：异常响应（func | 0x80）
XW_ERROR_RSP = FrameSpec(
    fields=[
        Field.u8("addr", desc="从站地址"),
        Field.u8("func", desc="原功能码 | 0x80"),
        Field.u8("err", desc="异常码（01~04）"),
        Field(key="crc", length=2, crc=True, desc="CRC16/MODBUS，低字节在前"),
    ],
    device="addr",
    checksum=ChecksumRule("crc", crc_bytes_le),
    max_frame_size=16,
    desc="Modbus 异常响应",
)


# ---------------------------------------------------------------- 组指令
_READ_BUILDER = FrameBuilder(XW_READ_TX)
_MULTI_BUILDER = FrameBuilder(XW_MULTI_TX)


def build_read(addr: int, reg: int = REGISTERS["POS1_INT"], count: int = 2) -> bytes:
    """组一条 04H 读输入寄存器请求（默认读位置1 整数方式 2 个寄存器）。"""
    return _READ_BUILDER.build(FUNC_READ_INPUT, addr=addr, reg=reg, value=count)


def build_read_holding(addr: int, reg: int = REGISTERS["ADDR"], count: int = 1) -> bytes:
    """组一条 03H 读保持寄存器请求（例如读从机地址 0x0030）。"""
    return _READ_BUILDER.build(FUNC_READ_HOLDING, addr=addr, reg=reg, value=count)


def build_write_single(addr: int, reg: int, value: int) -> bytes:
    """组一条 06H 写单寄存器请求。"""
    return _READ_BUILDER.build(FUNC_WRITE_SINGLE, addr=addr, reg=reg, value=value)


def build_write_multiple(addr: int, reg: int, values: List[int]) -> bytes:
    """组一条 10H 写多寄存器请求（同时改地址/波特率/校验时用）。"""
    data = b"".join(v.to_bytes(2, "big") for v in values)
    return _MULTI_BUILDER.build_raw(
        FUNC_WRITE_MULTI, data, addr=addr, reg=reg,
        count=len(values), bytecount=len(data),
    )


# ---------------------------------------------------------------- 数据解析
def split_registers(data: bytes) -> Tuple[int, ...]:
    """把寄存器区按 16 位大端切成整数（无符号）。"""
    if len(data) % 2:
        raise ValueError("寄存器数据字节数必须是偶数，实际 {}".format(len(data)))
    return tuple(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))


def decode_displacement_int(data: bytes) -> float:
    """整数方式：高 2 字节 int16（整数）+ 低 2 字节 uint16（小数 / 65535）。"""
    if len(data) != 4:
        raise ValueError("整数位移必须是 4 字节，实际 {}".format(len(data)))
    integer = int.from_bytes(data[0:2], "big", signed=True)
    fraction = int.from_bytes(data[2:4], "big")
    return integer + fraction / 65535.0


def decode_displacement_float(data: bytes) -> List[float]:
    """浮点方式：每 4 字节一个单精度浮点，字节序 CDAB（重排成 ABCD 再解）。"""
    if len(data) % 4:
        raise ValueError("浮点位移必须 4 字节对齐，实际 {}".format(len(data)))
    out: List[float] = []
    for i in range(0, len(data), 4):
        chunk = data[i : i + 4]
        # CDAB → ABCD：交换前后两个 16 位字
        reordered = chunk[2:4] + chunk[0:2]
        out.append(struct.unpack(">f", reordered)[0])
    return out


def decode_temperature(data: bytes) -> float:
    """温度：2 字节 int16，/100 = ℃。"""
    if len(data) != 2:
        raise ValueError("温度数据必须是 2 字节，实际 {}".format(len(data)))
    return int.from_bytes(data, "big", signed=True) / 100.0


# ---------------------------------------------------------------- 组合收发：按功能码分派
class MultiFuncProtocol:
    """一台示例设备一个实例：能组指令、能解析响应、能处理黏包。

    响应有四类结构（读/写单/写多/异常），没法用一份解析规则表达，所以内部
    持有四份解析器，``feed`` 时按"哪份能凑出整帧且 CRC 过"来分派。字节流里
    读/写/异常帧混着来、或粘连/分片，都能正确切出。
    """

    def __init__(self, device_id: Any = None, enforce_device_id: bool = False) -> None:
        self._device_id = device_id
        self.enforce_device_id = enforce_device_id
        self._tx = FrameBuilder(XW_READ_TX)
        self._tx_multi = _MULTI_BUILDER
        self._response_codecs = self._make_codecs()
        self._buf = bytearray()
        for codec in self._response_codecs:
            codec.compile()
            if device_id is not None:
                codec.bind_device(device_id)
            codec.enforce_device_id = enforce_device_id

    # ------------------------------------------------------------------ 组指令
    def build_read(self, addr: int, reg: int = REGISTERS["POS1_INT"], count: int = 2) -> bytes:
        return self._tx.build(FUNC_READ_INPUT, addr=addr, reg=reg, value=count)

    def build_read_holding(self, addr: int, reg: int = REGISTERS["ADDR"], count: int = 1) -> bytes:
        return self._tx.build(FUNC_READ_HOLDING, addr=addr, reg=reg, value=count)

    def build_write_single(self, addr: int, reg: int, value: int) -> bytes:
        return self._tx.build(FUNC_WRITE_SINGLE, addr=addr, reg=reg, value=value)

    def build_write_multiple(self, addr: int, reg: int, values: List[int]) -> bytes:
        data = b"".join(v.to_bytes(2, "big") for v in values)
        return self._tx_multi.build_raw(
            FUNC_WRITE_MULTI, data, addr=addr, reg=reg,
            count=len(values), bytecount=len(data),
        )

    # ------------------------------------------------------------------ 解析
    @staticmethod
    def _make_codecs():
        from .codec import AbstractFrameCodec

        specs = [
            XW_READ_RSP,
            XW_WRITE_SINGLE_RSP,
            XW_WRITE_MULTI_RSP,
            XW_ERROR_RSP,
        ]

        codecs = []
        for spec in specs:
            impl = spec.checksum.impl
            # 把 spec/impl 通过默认参数"钉死"，避免闭包捕获到循环最后一个值
            def _make(spec=spec, impl=impl):
                class _Rsp(AbstractFrameCodec):
                    framing = spec.framing
                    device_field = spec.device
                    max_frame_size = spec.max_frame_size

                    def rules(self):
                        return spec.fields

                    def crc_imp(self, d: bytes):
                        return impl(d)

                return _Rsp()

            codecs.append(_make())
        return codecs

    def feed(self, chunk: Union[bytes, bytearray, memoryview]) -> List["Any"]:
        """喂入收到的字节，返回解析出的帧（可能为空）。"""
        if isinstance(chunk, memoryview):
            chunk = chunk.tobytes()
        self._buf += chunk
        out: List[Any] = []
        pos = 0
        size = len(self._buf)
        while pos < size:
            matched = False
            for codec in self._response_codecs:
                snapshot = codec._buf
                codec._buf = bytearray(self._buf[pos:])
                try:
                    parsed = codec._parse_at(0)
                except Exception:  # 任意解析异常都视为"这份规则不匹配"
                    parsed = None
                finally:
                    codec._buf = snapshot
                if parsed is not None:
                    frame, consumed = parsed
                    if frame is not None:
                        out.append(frame)
                        pos += consumed
                        matched = True
                        break
            if not matched:
                break
        if pos:
            del self._buf[:pos]
        return out

    def reset(self) -> None:
        self._buf = bytearray()

    @property
    def pending_bytes(self) -> bytes:
        return bytes(self._buf)

    # ------------------------------------------------------------------ 设备号
    @property
    def device_id(self) -> Any:
        return self._device_id

    @device_id.setter
    def device_id(self, value: Any) -> None:
        self._device_id = value
        for codec in self._response_codecs:
            if value is None:
                codec.forget_device()
            else:
                codec.bind_device(value)

    def feed_through_protocol(self, chunk) -> List["Any"]:
        """用通用 ``Protocol`` 单独走读路径，验证读响应也能被标准 Protocol 解析。"""
        proto = Protocol(XW_READ_TX, rx=XW_READ_RSP, device_id=self._device_id,
                         enforce_device_id=self.enforce_device_id)
        return proto.feed(chunk)
