# kkprotocol

**可声明、可组帧、可自愈的 TCP 流式自定义帧解析器。**

[English](https://github.com/kapikkkk/kkprotocol/blob/main/README.md) | 简体中文

`kkprotocol` 面向「私有二进制协议」场景：设备通过 TCP / 串口服务器吐出一串字节，
你只负责**声明帧长什么样**，剩下的黏包、半包、脏数据重同步、长度回填、校验计算
都交给它。

只有**一套字段语言**（`Field`），有**两条使用路线**：

| 路线 | 入口 | 能做什么 | 什么时候用 |
|---|---|---|---|
| **A. 声明式**（推荐） | `FrameSpec` + `Protocol` | 解析 **+** 组帧 | 默认走这条 |
| B. 继承式 | 继承 `AbstractFrameCodec`，写 `rules()` | 只解析 | 需要写代码逻辑时 |

两条路线可以混用：`FrameSpec.to_codec()` 就能把 A 的声明变成一个 B 式解析器。
**第 3 节**讲清楚怎么选，不看清后面容易两头懵。

- 纯 Python、零依赖，Python 3.9+
- 三种定界：长度前缀、分隔符（含字节转义/透明传输）、自适应
- 设备号未知 → 自动学习 → 当成同步锚点的完整生命周期
- 异步流式接口，直接对接 `asyncio.StreamReader`
- 声明式组帧：长度、校验、序列号、时间戳、设备号自动回填
- 内置 11 个公共协议示例（DL/T645、CJ/T188、M-Bus、Modbus ASCII、BACnet MS/TP、NMEA-0183 …）

---

## 目录

1. [为什么用它](#1-为什么用它)
2. [安装](#2-安装)
3. [两条路线，先选一条](#3-两条路线先选一条)
4. [30 秒上手](#4-30-秒上手)
5. [一帧怎么声明](#5-一帧怎么声明)
6. [三种定界方式](#6-三种定界方式)
7. [帧首是设备号（未知 → 学到 → 固定）](#7-帧首是设备号未知--学到--固定)
8. [异步与流式](#8-异步与流式)
9. [解析结果怎么用](#9-解析结果怎么用)
10. [出错、自愈与统计](#10-出错自愈与统计)
11. [组帧进阶](#11-组帧进阶)
12. [内置协议与示例](#12-内置协议与示例)
13. [常见坑](#13-常见坑)
14. [API 速查](#14-api-速查)
15. [测试与性能](#15-测试与性能)
16. [License](#16-license)

---

## 1. 为什么用它

处理 TCP 自定义协议时，真正烦人的从来不是「解析一帧」，而是：

- **黏包 / 半包**：一次 `recv` 可能拿到半帧、一帧半、或十几帧拼在一起；
- **脏数据重同步**：连接从帧中间接入，或线路抖动插入垃圾字节；
- **长度字段不可信**：长度被破坏时按错误长度等待，会把后面的真帧一起吞掉；
- **校验**：CRC16 / 累加和 / 异或 / LRC，各家不一样；
- **组帧**：长度要回填、校验要覆盖一段、序列号要自增、设备号要填。

`kkprotocol` 把这些收进一个**声明式**模型：你只写一份字段表，解析和组帧都从它派生。

```python
from kkprotocol import ChecksumRule, Field, FrameSpec, LengthRule, Protocol, crc16_modbus

# 声明一次：这一帧长什么样
AURORA = FrameSpec(
    fields=[
        Field.u8("header", fixed=0xAA),
        Field.u8("len"),
        Field.u8("cmd"),
        Field.raw("dev_id", 4),
        Field.raw("data", "{len.val}-7"),
        Field.checksum("crc", 2, group="{len}{cmd}{dev_id}{data}"),
    ],
    payload="data",
    length=LengthRule("len"),                  # 长度字段：组帧时自动算、自动回填
    checksum=ChecksumRule("crc", crc16_modbus),  # 校验字段：组帧时自动算
)

proto = Protocol(AURORA)                 # 收和发都从这一份声明来

for frame in proto.feed(chunk):          # chunk 可以是任意切分的字节
    print(frame.value("cmd"), frame.value("data"))

wire = proto.build_raw(0x03, b"hi", dev_id=b"\x00\x00\x00\x01")   # 发
```

---

## 2. 安装

```bash
pip install kkprotocol
```

从源码安装：

```bash
git clone <your-repo-url>
cd kkprotocol
pip install -e .
```

要求 Python 3.9+，无第三方运行时依赖。

---

## 3. 两条路线，先选一条

**默认走 A。只有需要自己写解析逻辑时，才落到 B。**

### 3.1 它们分别是什么

| | **A. 声明式** `FrameSpec` | **B. 继承式** `AbstractFrameCodec` |
|---|---|---|
| 你写的东西 | 一份 `FrameSpec(...)` 数据 | 一个类：`rules()` + `crc_imp()` |
| 解析（收） | ✅ `Protocol(spec).feed()` / `spec.to_codec().feed()` | ✅ `MyCodec().feed()` |
| 组帧（发） | ✅ `Protocol(spec).build()`，长度/校验自动回填 | ❌ 不支持，得自己拼字节 |
| 长度 / 校验 | 声明成 `LengthRule` / `ChecksumRule` | 长度靠字段表达式，校验靠 `crc_imp()` |
| 适合 | 绝大多数场景（**推荐默认**） | 需要写代码逻辑时 |

两者**共用同一套 `Field` 字段表**，所以互相切换成本很低——这也是为什么本 README
前半部分的字段语法对两条路线都成立。

### 3.2 同一帧的两种写法

用后面一直用的 `Aurora` 帧（`AA | len | type | cmd | seq(2) | dev(4) | data | crc(2)`）对照：

**路线 A**：声明一份 spec，收和发都归它管。

```python
AURORA = FrameSpec(
    fields=[...],                          # 帧结构，见第 4 节
    payload="data",                        # 哪段是净荷
    length=LengthRule("len"),              # 哪个字段是长度、怎么算
    checksum=ChecksumRule("crc", crc16_modbus),
    device="dev",                          # 哪个字段是设备号
)
proto = Protocol(AURORA, device_id=b"\x00\x00\x00\x07")
frame = proto.feed(wire)[0]                # 收
wire = proto.build("Read", ...)            # 发
```

**路线 B**：写一个类，只回答「字段表」和「校验怎么算」两个问题。

```python
class AuroraCodec(AbstractFrameCodec):
    device_field = "dev"                   # 类属性，对应 A 的 device=

    def rules(self):                       # 对应 A 的 fields=
        return [ ... 一模一样的字段表 ... ]

    def crc_imp(self, data):               # 对应 A 的 ChecksumRule
        return crc16_modbus(data)

frame = AuroraCodec().feed(wire)[0]        # 只能收，没有 build
```

差别只有三处：A 把 `payload / length / checksum / device` 写成**参数**，
B 写成**类属性**和方法；A 有 `build()`，B 没有。

### 3.3 混用：A 的声明也能当 B 用

```python
codec = AURORA.to_codec()      # FrameSpec → 一个普通解析器实例
frames = codec.feed(wire)
```

所以「先按 A 声明好了，后来某处就是想要一个 codec 对象」不用重写；
`Protocol` 内部收帧走的也是这条路。

### 3.4 什么时候确实该用 B

- 帧内要**按命令码换一套字段表**（动态规则）——见 `contrib/bacnet_mstp.py`（两种帧型）、
  `example_modbus_rtu_multi.py`（按功能码分派多份 spec）；
- 需要覆写重同步 / 设备号学习的具体行为；
- 已有代码继承了 `AbstractFrameCodec`，只想加两个字段。

除此之外都用 A：少写一个类，还白拿组帧能力。

> 本 README 第 5~7 节讲字段、定界、设备号的**通用规则**，两条路线都适用；
> 每节会注明在 A 里写成什么参数、在 B 里写成什么属性。

---

## 4. 30 秒上手

虚构一个 `Aurora` 传感器协议，后面全部用它举例：

```
AA | len | type | cmd | seq(2) | dev(4) | data(len-10) | crc(2, CRC16/MODBUS)
len = type..crc 的字节数
```

```python
from kkprotocol import ChecksumRule, Field, FrameSpec, LengthRule, Protocol, crc16_modbus

AURORA = FrameSpec(
    fields=[
        Field.u8("header", fixed=0xAA),
        Field.u8("len"),
        Field.u8("type"),
        Field.u8("cmd"),
        Field.u16("seq"),
        Field.raw("dev", 4),
        Field.raw("data", "{len.val}-10"),
        Field.checksum("crc", 2, group="{len}{type}{cmd}{seq}{dev}{data}"),
    ],
    payload="data",
    length=LengthRule("len"),
    checksum=ChecksumRule("crc", crc16_modbus),
    device="dev",
)

proto = Protocol(AURORA, device_id=b"\x00\x00\x00\x07")

#         ┌─ 第 1 个参数：目标指令，写进命令码字段 cmd
#         │        ┌─ 第 2 个参数：整段载荷，塞进 payload="data" 声明的 data 字段
#         │        │            ┌─ 其余字段按字段名传：type / seq 在声明里没有来源
wire = proto.build_raw(0x03, b"\x10\x20", type=0x01, seq=1)
print(wire.hex(" "))
# aa 0c 01 03 00 01 00 00 00 07 10 20 98 d1

# 收：同一个对象
frame = proto.feed(wire)[0]
print(frame.value("cmd"), frame.value("seq"), frame.value("data"))
# 3 1 b'\x10 '

# 自检：发出的字节必须能被自己的收帧规则完整解回来
proto.verify(wire)
```

**为什么只传 `type` 和 `seq`？** 把 `AURORA` 的 8 个字段逐一对照——每个字段的值只有
一个来源，凡是能推出来的都不用你管：

| 字段 | 值从哪来 | 要传吗 |
|---|---|---|
| `header` | `fixed=0xAA`，常量 | 不用，自动填 |
| `len` | `LengthRule("len")` 算出来回填 | **传了报错** |
| `type` | 没有来源 | ✅ `type=0x01` |
| `cmd` | 第 1 个位置参数 | ✅ 就是那个 `0x03` |
| `seq` | 没有来源（声明 `AutoField` 后自动） | ✅ `seq=1` |
| `dev` | `device="dev"` + `Protocol(device_id=...)` | 不用，可用 `dev=` 覆盖 |
| `data` | 第 2 个位置参数 | ✅ 就是那个 `b"\x10\x20"` |
| `crc` | `ChecksumRule("crc", ...)` 算出来回填 | **传了报错** |

记一条就够：**只有「算不出来、又不是常量」的字段才需要传**。

载荷那段有三种给法：**按 `Pdu.fields` 逐字段**、**用 `Data`/`pack` 内联构造**、
**直接给裸字节**——见 [11.5](#115-载荷怎么给三种方式)。

漏传不会被忽略——`FrameBuildError` 会明确告诉你缺哪个，并把**这帧能传的字段全列出来**：

```
缺少参数 ['type']；这帧可用: ['header', 'type', 'cmd', 'seq', 'dev', 'data']
```

忘了该传什么时，故意少传一个看报错清单，比翻文档快。

把 `wire` 换成任意切分的块逐次 `feed`，结果都一样——这就是「黏包 / 半包自动处理」。

> 只想先跑通、不想写声明？库自带一个现成的 `DeviceFrameCodec`（见第 12 节）。
> 但**写自己的协议时用 `FrameSpec`**。

---

## 5. 一帧怎么声明

`Field` 是两条路线的**共同语言**：路线 A 把它放进 `FrameSpec(fields=[...])`，
路线 B 从 `rules()` 里返回。本节所有字段写法两边通用。

### 5.1 字段工厂

`Field` 提供一组工厂方法，带完整 IDE 提示：

```python
from kkprotocol import Field

Field.u8("cmd")                       # 1 字节无符号整数
Field.u16("seq")                      # 2 字节无符号整数（默认大端）
Field.u16("seq", little_endian=True)  # 2 字节小端
Field.u32("ts")                       # 4 字节无符号整数
Field.raw("dev_id", 4)                # 原始字节（不解析成数值，值就是 bytes）
Field.rest("line")                    # “取到帧尾”（仅分隔符定界可用）
Field.checksum("crc", 2, group="{len}{cmd}{data}")   # 校验字段
```

也支持完整构造与旧式字典（兼容历史代码）：

```python
Field(key="header", length=1, fmt="B", fixed=0x55)
{"key": "header", "len": 1, "fmt": "B", "fixed": 0x55}
```

### 5.2 长度表达式

`length` 可以是整数、数字字符串、表达式或回调：

```python
Field.raw("data", 16)                 # 固定 16 字节
Field.raw("data", "{len.val}-8")      # len 字段的值减 8
Field.raw("data", "{len.val}")        # 正好等于 len 字段的值
Field.raw("line", None)               # 取到帧尾（分隔符定界）
```

表达式里 `{字段.属性}` 的属性只能是：

| 属性 | 含义 |
|---|---|
| `val` | 字段解析出的**值**（整数） |
| `len` / `length` / `bytes` / `raw` | 字段实际占用的**字节数** |

### 5.3 `fmt`：解成什么

`fmt` 是 `struct` 格式串，必须只解析出一个值。多字节数值请显式带字节序前缀
（`!` 大端 / `<` 小端），避免平台差异。

```python
Field.u16("seq")                   # 内部就是 fmt="!H"
Field.raw("payload", 4, fmt="!f")  # 4 字节大端单精度浮点
```

### 5.4 `group`：校验覆盖哪些字节

- 标记了 `group`（或 `crc=True`）的字段是**校验字段**；
- `group` 决定参与校验的字段：

```python
Field.checksum("crc", 2, group="{len}{cmd}{data}")   # 校验 len、cmd、data
Field.checksum("crc", 2)                             # 省略 group：校验它前面所有字段
```

**算法怎么给，两条路线不同**：

| | 路线 A（`FrameSpec`） | 路线 B（继承式） |
|---|---|---|
| 写在哪 | `checksum=ChecksumRule("crc", crc16_modbus)` | `def crc_imp(self, data)` |
| 返回值 | 与 `crc_imp` 同口径 | `int`（按字段 `fmt` 打包）或 `bytes`（直接用） |

推荐校验函数返回 `bytes`——跨字节序最稳，也不受 `fmt` 影响。

内置算法：`crc16_modbus`、`crc16_x25`、`crc16_ccitt`、`crc8`、`sum8`、`xor8`。

---

## 6. 三种定界方式

| 方式 | 适用 | 切帧依据 | 是否需要转义 |
|---|---|---|---|
| 长度定界 `LENGTH_FRAMING` | TCP 二进制协议（首选） | 长度字段 | 否 |
| 分隔符定界 `DelimiterFraming` | 串口 / 透传设备 / 文本协议 | 特殊字节 | 是 |
| 自适应 `AUTO_FRAMING` | 不确定时兜底探测 | 先长度后分隔符 | 视情况 |

写法上：路线 A 传 `FrameSpec(framing=...)`，路线 B 设类属性 `framing = ...`，取值相同。
下面示例都用路线 B 写，方便看清「定界是 codec 的属性」；换成 A 只需把同样的值塞进参数。

### 6.1 长度定界（默认）

```python
class DevCodec(AbstractFrameCodec):
    def rules(self):
        return [
            Field.u8("header", fixed=0x55),
            Field.u8("len"),
            Field.raw("data", "{len.val}-1"),
            Field.checksum("crc", 2, group="{len}{data}"),
        ]
    def crc_imp(self, data):
        return crc16_modbus(data)
```

长度字段一旦被破坏，协议本身无法自愈（会按错误长度等待）。用 `max_frame_size`
把「假长度」尽快判死，配合 `idle_timeout` / `drop_pending()` 兜底（见第 10 节）。

### 6.2 分隔符定界（含转义 / 透明传输）

PPP / HDLC 风格：首尾 `0x7E`，净荷里的 `0x7E` / `0x7D` 转义为 `0x7D 0x5E` / `0x7D 0x5D`。

```python
from kkprotocol import AbstractFrameCodec, DelimiterFraming, Field, crc16_x25

PPP = DelimiterFraming(end=0x7E, start=0x7E, escape=0x7D, escape_xor=0x20)

class PppCodec(AbstractFrameCodec):
    framing = PPP                      # 直接传 DelimiterFraming 实例
    def rules(self):
        return [
            Field.u8("addr", fixed=0xFF),
            Field.u8("ctrl", fixed=0x03),
            Field.u8("len"),
            Field.raw("data", "{len.val}"),
            Field.checksum("fcs", 2, group="{addr}{ctrl}{len}{data}"),
        ]
    def crc_imp(self, data):
        return crc16_x25(data)
```

要点：

- 分隔符模式下**长度字段不能用来切帧**（转义会让线上长度 ≠ 净荷长度），只能作校验项；
- `start == end` 表示首尾共用一个标志（PPP/HDLC）；两者不同时取两者之间；
- 转义支持两种方案：`escape_xor`（异或，PPP）与 `escape_map`（显式映射，SLIP）；
- `Field.rest("...")` 只能用于分隔符定界；若后面还跟着定长字段（如尾随 FCS），
  它会自动**预留**这些字节，不会被 `rest` 吞掉。

### 6.3 自适应 `AUTO_FRAMING`

先用长度定界试探，失败回退到分隔符定界，命中一次后锁定：

```python
class MixedCodec(AbstractFrameCodec):
    framing = AUTO_FRAMING
    delimiter = DelimiterFraming(end=0x0A)
    def rules(self):
        return [Field.u8("stx", fixed=0x02), Field.u8("n"), Field.raw("body", "{n.val}")]
    def crc_imp(self, data):
        return 0
```

---

## 7. 帧首是设备号（未知 → 学到 → 固定）

很多私有协议帧首不是固定帧头，而是**设备号**，且设备号在首帧未知。先声明「哪个字段
是设备号」——路线 A 写 `FrameSpec(device="dev_id")`，路线 B 写 `device_field = "dev_id"`
——库会：

1. 未知时先放行并**学习**设备号；
2. 学到后把它还原成字节，当作**同步锚点**（比固定帧头更有辨识度）；
3. 可选「学到即固定」——之后设备号不符的帧按脏数据丢掉。

```python
class HeadDeviceCodec(AbstractFrameCodec):
    device_field = "dev_id"
    sync_from_device = True         # 学到后拿设备号当同步字
    lock_device_after_learn = True  # 学到即固定
    max_frame_size = 300

    def rules(self):
        return [
            Field.raw("dev_id", 4),
            Field.u8("cmd"),
            Field.u8("n"),
            Field.raw("data", "{n.val}"),
            Field.checksum("crc", 2, group="{dev_id}{cmd}{n}{data}"),
        ]
    def crc_imp(self, data):
        return crc16_modbus(data)
```

多设备挂在同一条总线上时，请关掉 `lock_device_after_learn`，改为观察
`frame.device_mismatch` 自行分派。

路线 A 里只有 `device=` 是 spec 参数，其余策略落在底层解析器上，通过 `Protocol.codec`
设置（`codec` 是懒加载属性，第一次访问才创建）：

```python
proto = Protocol(AURORA, device_id=b"\x00\x00\x00\x07")
proto.codec.sync_from_device = True
proto.codec.lock_device_after_learn = True
```

| 属性 | 作用 |
|---|---|
| `device_field`（A 侧：`device=`） | 哪个字段是设备号 |
| `auto_learn_device` | 未知时自动学习（默认开） |
| `enforce_device_id` | 不匹配直接拒绝（默认关，只标记 `device_mismatch`） |
| `lock_device_after_learn` | 学到即固定 |
| `sync_from_device` | 设备号兼作重同步锚点 |
| `preempt_on_sync` | 候选帧被假长度堵住时，用锚点切断（启发式，默认关） |
| `device_id_provider` | 设备号未知时从注册表/DB 拉取一次 |

---

## 8. 异步与流式

```python
import asyncio
from kkprotocol import DeviceFrameCodec

async def main():
    reader, writer = await asyncio.open_connection("127.0.0.1", 9000)
    codec = DeviceFrameCodec()
    codec.idle_timeout = 5.0            # 空闲 5 秒丢弃半包
    async for frame in codec.read_frames(reader):
        print(frame.value("cmd"), frame.value("data"))

asyncio.run(main())
```

- `feed(chunk)`：同步、纯内存，最快路径；
- `feed_async(chunk)`：超过 `offload_threshold`（默认 256KB）才丢线程池，避免阻塞事件循环；
- `read_frames(reader)` / `iter_frames(chunks)`：直接对接 asyncio 流；
- **一个连接一个 codec 实例**（缓冲区互不共享）。

---

## 9. 解析结果怎么用

`feed()` 返回 `Frame` 列表：

```python
frame = codec.feed(wire)[0]

frame.value("cmd")          # 字段值
frame["cmd"].raw            # 字段原始字节
frame.raw_of("cmd")         # 同上
frame.device_id             # 设备号（由 device_field 得出）
frame.device_mismatch       # 与已绑定设备号不一致
frame.learned_device        # 本帧触发了设备号学习
frame.framing               # "length" / "delimiter"
frame.to_bytes(wire=True)   # 这一帧在流里的实际字节（含定界符/转义）
frame.to_hex()              # "55 0C 01 03 ..."
frame.as_dict()             # {字段名: 值}
```

`FieldValue` 同时保留 `raw`（反转义后的原始字节）与 `val`（按 `fmt` 解出的值）；
`fmt` 为空时 `val` 就是 `raw`。

---

## 10. 出错、自愈与统计

内部把「半包」与「脏数据」分开处理：

- **半包** → 返回空列表，等下一次 `feed`（不丢数据）；
- **脏数据** → 靠同步锚点（帧头 / 设备号）跳到下一个候选位置重新对齐；
- **校验失败** → 整帧丢弃并重同步（`on_crc_error="resync"`），或跳过整帧（`"skip_frame"`）；
- **长度与结构矛盾** → 计入 `length_mismatches`，整段候选丢弃。

```python
codec.stats.bytes_in             # 累计输入字节
codec.stats.frames               # 成功解析帧数
codec.stats.resyncs              # 重同步次数
codec.stats.crc_errors           # 校验失败次数
codec.stats.length_mismatches    # 长度不一致次数
codec.stats.device_mismatches    # 设备号不匹配次数
codec.stats.rejected_frames      # 被 on_frame 钩子拒绝的帧
codec.stats.dropped_bytes        # 丢弃字节数
codec.stats.overflow_drops       # 缓冲超限丢弃次数
```

兜底手段：

```python
codec.reset()            # 丢弃半包（重连时）
codec.drop_pending()     # 主动丢弃当前未成帧的字节
codec.reset_framing()    # auto 模式重新探测
```

---

## 11. 组帧进阶

第 4 节已经跑通了「收 + 发」。这节讲组帧的机制和进阶用法。

先澄清一个容易误解的点：**同一份 `FrameSpec` 既用来发（`build`）也用来收（`feed`）**，
并不是「组帧规则不能复用解析规则」。`Protocol` 收帧时就是调用 `rx.to_codec()`，
把同一份声明变成一个解析器。只有**收发格式确实不同**时才写第二份 spec
（应答少几个字段、命令码差 `0x80`），交给 `Protocol(tx=..., rx=...)`。

真正不对称的只有三处，由 builder 自动处理：

| 声明里写的 | 收（解析）时 | 发（组帧）时 |
|---|---|---|
| 长度字段 | 读出来 | **算出来**并回填 |
| 校验字段 | 验一遍 | **算一遍** |
| 常量字段 `fixed=` | 对一下 | 自动填 |

### 11.1 长度怎么回填：不动点循环

长度依赖帧体、帧体又包含长度字段，所以走**不动点循环**：假设 `len=0/crc=0` 拼一帧
→ 量长度、算校验 → 与「帧里写的」比对 → 一致即收敛。通常 2~3 轮收敛。

两种口径：

- `LengthRule("len")`（默认 `span=None`）：长度字段**之后到帧尾**的全部字节，**含校验字段**；
- `LengthRule("len", span=("a", "b"))`：按字段名左闭右闭取一段，需要排除校验字段时用。

### 11.2 `Pdu`：一条指令怎么声明

```python
from kkprotocol import Pdu

AURORA_WITH_PDU = FrameSpec(
    fields=[...],                       # 同上
    pdus={
        0x03: Pdu("Read", [Field.u8("addr"), Field.u8("count")]),
        0x06: Pdu("Write", [Field.u8("addr"), Field.u16("value")]),
    },
)
proto = Protocol(AURORA_WITH_PDU, device_id=b"\x00\x00\x00\x07")
wire = proto.build("Read", type=0x01, seq=1, addr=0x00, count=2)
# AA 0C 01 03 00 01 00 00 00 07 00 02 41 5C
wire = proto.build(0x06, type=0x01, seq=2, addr=0x2C, value=250)
# AA 0D 01 06 00 02 00 00 00 07 2C 00 FA 15 AC
```

命令码不用写两遍：`pdus` 的键就是命令码，声明时自动回填进 `Pdu.cmd`。上面等价于
`Pdu("Read", 0x03, [...])`——显式写法也仍然支持，两者不一致会在声明期直接报错
（**不允许**键和 `Pdu.cmd` 打架）。第二位置参数直接给字段表即可，命令码只会是标量，
不可能是序列，所以不存在歧义。

`Pdu.resp` 用来显式指定应答命令码（默认 `cmd | 0x80`）：`Pdu("Read", resp=0x83)`。

### 11.3 设备号与自动填值字段

除了长度、校验、设备号，其余「每帧自己变」的字段用 `AutoField` 声明，可 0..N 个：

```python
import time
from kkprotocol import AutoField

TIME_AND_SEQ = FrameSpec(
    fields=[...],
    auto=[
        AutoField("seq", start=0, step=1, wrap=0x10000),               # 自增计数器
        AutoField("ts", provider=lambda: int(time.time()) & 0xFFFF),   # 时间戳
    ],
)
```

- `provider=None`：自增计数器；
- `provider=callable`：每次组帧调用取值；
- `echo=True`：`build_ack()` 回显请求帧里的同名字段（应答通常要带回 SEQ）。

### 11.4 发出去之前先自检

```python
proto = Protocol(AURORA, device_id=b"\x00\x00\x00\x07")
wire = proto.build_raw(0x03, b"\x10\x20", type=1, seq=1)
frame = proto.verify(wire)      # 用收帧规则回环解析，必须一帧一字节不剩
proto.diff()                    # 收发两份 spec 的差异（tx/rx 不同时）
```

### 11.5 载荷怎么给：三种方式

按「这段数据有没有被声明过结构」来选：

| 方式 | 写法 | 适用 |
|---|---|---|
| ① 按 `Pdu.fields` 逐字段 | `build("Read", addr=0, count=2)` | 报文结构固定，字段有名有类型 |
| ② `Data` + `pack` 内联构造 | `build_raw(0x03, [Data.u8(0), Data.bool(True), Data.str("test", count=24)])` | 一次性/临时结构，不值得为它写 `Pdu` |
| ③ 手写整段 bytes | `build_raw(0x03, b"\x00\x02")` | 载荷本身就是裸字节，或从别处拿到 |

**① 逐字段**：先声明 `Pdu`（见 11.2），一个关键字一个字段。

```python
proto.build("Read", type=1, seq=1, addr=0x00, count=2)
```

**② `Data` + `pack`**：不用声明 Pdu，直接把值列出来，库负责编码。

```python
from kkprotocol import Data, pack

body = pack(
    Data.u8(0x00),                              # 1 字节
    Data.u8(0x00),                              # 1 字节
    Data.bool(True),                            # 0x01
    Data.str("test", count=24, fill=b"\x00"),   # 定长 24，不足补 \0
)
proto.build_raw(0x03, body, type=1, seq=1)

# 列表可以直接当载荷传，不必先 pack
proto.build_raw(0x03, [Data.u8(0), Data.u8(0), Data.bool(True), Data.str("test", count=24)], type=1, seq=1)
```

`Data.xxx(值)` 返回「已编码的值」，`pack()` 按顺序拼成 `bytes`。可用的构造器：

| 调用 | 字节数 | 结果 |
|---|---|---|
| `Data.u8(0x12)` | 1 | `12` |
| `Data.u16(0x1234)` | 2 | `12 34` |
| `Data.u16(0x1234, little_endian=True)` | 2 | `34 12` |
| `Data.u32(...)` / `Data.u64(...)` | 4 / 8 | 大端 |
| `Data.i8(-1)` / `Data.i16` / `Data.i32` / `Data.i64` | 1/2/4/8 | 有符号 |
| `Data.f32(1.5)` / `Data.f64(1.5)` | 4 / 8 | IEEE754，`3f c0 00 00` |
| `Data.bool(True)` | 1 | `01` |
| `Data.str("test", count=8)` | 8 | `74 65 73 74 00 00 00 00`，超长截断 |
| `Data.char(...)` | — | `Data.str` 的别名 |
| `Data.raw(b"\x01\x02")` | 2 | 原样字节 |
| `Data.zeros(3)` | 3 | `00 00 00` |

> **为什么 `Field` 和 `Data` 是两个类？** 两者签名的第一个参数含义不同：
> `Field.u8("cmd")` 给的是**字段名**，声明一次、收发两边都靠它取值；
> `Data.u8(0x12)` 给的是**值**，编完就丢。
> 合并成一个类会让 `Field.u8(0)` 产生歧义（字段名叫 0 还是值等于 0？），
> 所以刻意分开：**`Field` 描述结构，`Data` 填值，`pack` 把它们拼起来。**

**③ 手写 bytes**：

```python
proto.build_raw(0x03, b"\x00\x02", type=1, seq=1)
```

三种方式产出的帧**逐字节相同**——③ 是手工拼字节，② 只是它的类型化写法（`Data.u8(1)` 就是
`b"\x01"`，但字节序不用你自己算），① 由 `Pdu.fields` 代劳：

```python
proto.build("Write", type=1, seq=1, a=0x01, b=0x0203)      # ① 逐字段
proto.build_raw(0x03, [Data.u8(0x01), Data.u16(0x0203)], ...)    # ② Data 列表
proto.build_raw(0x03, b"\x01\x02\x03", ...)                # ③ 裸字节
```

三者组出来的是同一帧：

```
aa 0d 01 03 00 01 00 00 00 07 01 02 03 3b ad
```

`build_raw(target, payload)` 也等价于 `build(target, data=payload)`——payload 字段叫什么名，
就用什么当关键字，两种调用出来的字节一样。

**① 与 ②③ 互斥**：声明了 `pdus` 就不能再整段给，反之亦然。用错了立刻报错，而且报错会
列出当前模式下能传哪些字段：

| 情况 | 报错 |
|---|---|
| 有 pdus 还想整段给 `data=` | `不认识的参数 ['data']；这帧可用: ['header','type','cmd','seq','dev','addr','count']` |
| 用 `build_raw` 还想逐字段给 `addr=` | `不认识的参数 ['addr']；这帧可用: ['header','type','cmd','seq','dev','data']` |

所以判断「这帧该传什么」最简单的办法还是看那句「这帧可用」。

> 载荷字段**不传就是空载荷**，不报错：`build(0x03, type=1, seq=1)` 组出 `aa 0a ...`
> （`len=10`，data 部分 0 字节）。有些协议的空帧正是这样，所以这里不做强制校验。

另外三点：

- 目标 `target` 可以是命令码 `0x03`、指令名 `"Read"`，或 `Pdu` 对象——三者等价；
- `Pdu.fields` 里的字段顺序就是线上顺序，不用在调用处关心偏移；
- 逐字段给时，字段的 `fmt` 决定打包宽度（`Field.u16("value")` 自动按 `!H` 打包），
  比手算 `b"\x00\xfa"` 可靠。

三个容易踩的点：

| 现象 | 原因 | 怎么办 |
|---|---|---|
| `缺少参数 ['type']` | 该字段在声明里没有来源 | 按字段名补上，报错里会列出全部可用字段 |
| `字段 'len' 由 builder 自动计算` | 长度/校验字段不接受手动值 | 删掉 `len=` / `crc=`，让它自己算 |
| 传了 `header=0xBB` 却还是 `AA` | `fixed=` 字段以声明为准，手动值被**静默忽略** | 改声明里的 `fixed=`，别在调用处传 |

最后一个尤其隐蔽：它不报错也不生效。想改固定的帧头/版本号，改 `Field.u8(..., fixed=...)`。

> `AutoField` 声明的字段（如自增 `seq`）**可以**手动传：本次就用你给的值，之后计数器
> 从该值往后继续。`seq=5` 之后下一帧自然是 `6`。

---

## 12. 内置协议与示例

### 12.1 开箱可跑的示例帧

`kkprotocol.example_device` 里有三个现成的**路线 B** 解析器，也是写自己协议时的模板：

- `DeviceFrameCodec`：长度定界 + 设备号；
- `PppFrameCodec`：`0x7E` 定界 + `0x7D` 转义；
- `HeadDeviceFrameCodec`：帧首即设备号（首帧未知）。

`DeviceFrameCodec` 的帧格式是
`55 | len | ver | cmd | ser(2) | dev_id(4) | data(len-10) | crc(2, CRC16/MODBUS)`：

```python
from kkprotocol import DeviceFrameCodec, build_device_frame

wire = build_device_frame(
    ver=1, cmd=0x03, ser=1, dev_id=b"\x00\x00\x00\x01", payload=b"\x01\x02"
)
print(wire.hex(" "))
# 55 0c 01 03 00 01 00 00 00 01 01 02 d0 bd

codec = DeviceFrameCodec()
frame = codec.feed(wire)[0]
print(frame.value("cmd"), frame.value("ser"), frame.value("data"), frame.device_id)
# 3 1 b'\x01\x02' b'\x00\x00\x00\x01'
```

跑一遍就有手感；换成自己的协议时，把第 4 节那份 `FrameSpec` 的字段改掉即可。

### 12.2 公共标准协议（contrib）

`kkprotocol.contrib` 里是一批**公共标准协议**的落地示例（仅作压测与参考，**不进顶层
导出**，按需 `import`）：

| 协议 | 定界 | 校验 | 模块 |
|---|---|---|---|
| DL/T645-2007（电能表） | 长度 + `0x68` | 累加和 | `contrib.dlt645` |
| CJ/T188-2004（水/气/热表） | 长度 + `0x68` | 累加和 | `contrib.cjt188` |
| M-Bus（EN 13757） | 长度，双长度字节 | 累加和 | `contrib.mbus` |
| ccTalk（货币外设） | 长度，无帧头 | 零和 | `contrib.cctalk` |
| XModem / YModem | 固定帧长 | CRC-16/CCITT | `contrib.xmodem` |
| SLIP（RFC 1055） | 分隔符 `0xC0` | 无 | `contrib.slip` |
| HDLC / PPP | 分隔符 `0x7E` + 转义 | CRC-16 | `contrib.hdlc` |
| Art-Net | 长度 + 多字节 magic | 无 | `contrib.artnet` |
| Modbus ASCII | 分隔符 `:`…`\n`，ASCII-Hex | LRC | `contrib.modbus_ascii` |
| NMEA-0183 | 分隔符 `$`…`\n`，文本 | 内联 XOR | `contrib.nmea` |
| BACnet MS/TP | 长度 + `55 FF`，双 CRC | 头 CRC8 + 体 CRC16 | `contrib.bacnet_mstp` |

```python
from kkprotocol.contrib import dlt645

wire = dlt645.build_request(b"\x01\x00\x00\x00\x00\x00", ctrl=0x11, data=b"\x10\x01")
frame = dlt645.protocol(b"\x01\x00\x00\x00\x00\x00").feed(wire)[0]
print(dlt645.decode_data(frame.value("data")))   # b'\x10\x01'
```

> 一帧多校验和（如 BACnet 的头 CRC + 体 CRC）解析侧已完整支持：`FrameSpec.checksum`
> 接受 `ChecksumRule` 列表，每个校验字段按各自算法独立校验。组帧侧仍只回填第一个。

---

## 13. 常见坑

1. **把可变字段写成 `fixed`**：序列号、时间戳写死就整帧报废。
2. **`{n.val}` 与 `{n.len}` 用混**：前者是字段**值**，后者是字段**占几字节**。
   按长度字段算净荷要 `{len.val}`，写成 `{len.len}` 会永远只跳过 1~2 字节。
3. **长度表达式里写 `{n}`（不带属性）**：编译期报错；`{n}` 只能出现在校验 `group` 里。
4. **对 `fmt=""` 的字段用 `.val`**：`Field.raw("dev", 4)` 的值是 `bytes`，要用 `{dev.len}`。
5. **`Field.checksum` 的 `fmt` 与 `length` 不一致**：`fmt` 会按 `length` 自动选，
   手写 `fmt="!H"` 却声明 `length=1` 会编译期报错。
6. **`max_frame_size` 用默认 64KB**：假长度声称 65535 时会长时间等待，按真实最大值收紧。
7. **分隔符定界忘了转义**：净荷里出现定界字节会切断帧，且 CRC 未必能救。
8. **`crc_imp` 返回 `int` 但 `fmt` 字节序写反**：校验永远不过且不报错，只是不断重同步；
   优先返回 `bytes`。
9. **`Field.rest()` 用在长度定界**：编译期报错（长度定界没有「帧尾」概念）。
10. **长度表达式引用后面的字段**：编译期报错（只能前向引用）。
11. **多个连接复用同一个 codec 实例**：缓冲区会串，一个连接一个实例。
12. **组帧时手动传 `len`/`crc`**：会被拒绝，这两个字段由 builder 计算。
13. **`ChecksumRule.impl` 每次返回不同结果**：不动点循环无法收敛，报「来回震荡」。
14. **收发复用一份 spec 却格式不同**：发得出、收不回。写两份交给 `Protocol(tx=..., rx=...)`。
15. **载荷长度表达式偏移写错**：组帧末尾的一致性核对会拦下来，提示「对面按同一规则解析会错位」。
16. **在调用处给 `fixed=` 字段传值**（如 `build(..., header=0xBB)`）：不报错也不生效，
    值以声明为准——要改就改 `Field.u8("header", fixed=...)`。
17. **以为 `AutoField` 字段不能手动给**：可以，传了就是覆盖本次值，计数器从该值往后走。

---

## 14. API 速查

分成三块：**两条路线共用**的 `Field` / 异常 → **路线 A** → **路线 B**。

```python
# ============ 共用：Field 工厂（A 放进 FrameSpec.fields，B 从 rules() 返回）============
Field.u8 / u16 / u32 / u64 / raw / rest / checksum
Field(key=..., length=..., fmt=..., fixed=..., group=..., crc=..., desc=...)
#   length: int | "10" | "{len.val}-8" | callable(fields) | None(取到帧尾)
#   fmt:    ""(bytes) | "B" | "!H" | "<H" | "!I" | "!Q" | "!f" | "4s" ...
#   group:  "{n}{cmd}{body}"（只写 {字段}，不带属性）

# 共用：载荷值构造（给值、要字节，不需要字段名；见 11.5）
Data.u8 / i8 / u16 / i16 / u32 / i32 / u64 / i64 / f32 / f64
Data.bool(v) / Data.str(s, count=, fill=) / Data.char(...) / Data.raw(b) / Data.zeros(n)
pack(*items) -> bytes        # 也接受单个列表；build_raw 的载荷可直接传这些

# 共用：异常
FrameRuleError     # 规则写错，启动期就该暴露
FrameBuildError    # 这次的参数/数据凑不出合法帧

# ============ 路线 A：声明式（FrameSpec + Protocol）============
FrameSpec(fields, framing, payload, cmd, length, checksum, pdus, device, seq, auto, max_frame_size)
  .to_codec() -> AbstractFrameCodec   # 转成一个普通解析器实例
  .pdu(target) / .field(key) / .field_keys() / .group_keys(key)
  .diff(other) -> List[str]
LengthRule(key, span=None)          # span=None：长度字段之后到帧尾（含校验）
ChecksumRule(key, impl)             # impl 返回 int（按 fmt 打包）或 bytes（直接用）
                                    #   一帧多校验和：checksum=[ChecksumRule(...), ChecksumRule(...)]
SeqPolicy(key, enabled=False, start=0, step=1, wrap=0x10000)   # 单个计数器
AutoField(key, start=0, step=1, wrap=0x10000, provider=None, echo=True)  # 可 0..N 个
Pdu(name, cmd=None, fields=(), resp=None)   # cmd 可省略：pdus 的键回填

Protocol(tx=SPEC, rx=SPEC2, device_id=..., enforce_device_id=False, max_rounds=8)
  .build(target, **fields)             # 指令名 / 命令码 / Pdu → 线上字节
  .build_frame(target, **fields)       # 返回 BuildResult(轨迹/字段/body/rounds)
  .build_raw(target, payload, **shell) # 载荷整段给，不按 Pdu.fields 打包
  .build_ack(frame, **fields)          # 应答：cmd|0x80（或 Pdu.resp），seq/device 回显
  .feed(data) / .verify(wire) / .diff()
  .codec                               # 底层解析器（设 sync_from_device 等策略用）

FrameBuilder(spec, device_id=..., max_rounds=8)      # 只要组帧时的轻量入口
  .build / .build_frame / .build_raw / .device_id / .seq / .auto_keys

# ============ 路线 B：继承式（AbstractFrameCodec）============
# 必须实现
rules() -> Sequence[Field]          # 帧结构
crc_imp(data: bytes) -> int|bytes   # 校验算法

# 类属性：定界与策略
framing / delimiter / sync / lock_framing
max_frame_size / max_buffer / on_crc_error
device_field / auto_learn_device / enforce_device_id / device_id_provider
lock_device_after_learn / sync_from_device / preempt_on_sync
offload_threshold / idle_timeout / drop_pending_on_idle

# 数据入口
feed(data) / filter(data) / feed_async(data) / read_frames(reader) / iter_frames(chunks)

# 生命周期
compile() / reset() / reset_framing() / drop_pending()
bind_device(x) / forget_device()
pending_bytes / framing_mode / device_id / stats

# 钩子
on_frame(frame) -> bool
on_device_learned(device_id, frame)
```

内置 CRC：`crc16_modbus`、`crc16_x25`、`crc16_ccitt`、`crc8`、`sum8`、`xor8`。

---

## 15. 测试与性能

```bash
python -m unittest discover -s tests -p "test_*.py"
python -m coverage run --source=kkprotocol -m unittest discover -s tests -p "test_*.py"
python -m coverage report -m
```

- **591 个用例全部通过**（下面的命令可复现，用的是标准库 `unittest`，无需装 pytest）；
- 覆盖：黏包 / 逐字节分片 / 脏前缀 / 坏校验 / 设备号学习 / 多帧分派 / 异步 /
  长度回填收敛 / 分隔符转义 / 一帧多校验和 / `rest` 尾字段预留；
- 另有 11 个真实公共协议的批量回归（`tests/test_contrib_protocols.py`）。

参考量级（纯 Python 校验，200 字节/帧）：单连接 2~4 万帧/s；单连接 200Hz × 8 通道
（约 1600 帧/s）绰绰有余。瓶颈通常在对端与业务处理，不在解析器。

---

## 16. License

MIT License. 详见仓库中的 `LICENSE` 文件。
