# kkprotocol

**Declarative, self-resynchronizing frame codec for streaming custom protocols.**

English | [简体中文](README.zh-CN.md)

`kkprotocol` targets *private binary protocols*: a device dumps bytes onto TCP or a
serial-to-Ethernet converter, and all you do is **declare what a frame looks like** —
sticky packets, half frames, garbage-prefix resync, length backfill and checksum
computation are handled for you.

There is **one field language** (`Field`) and **two ways to use it**:

| Approach | Entry point | Can do | When to use |
|---|---|---|---|
| **A. Declarative** (recommended) | `FrameSpec` + `Protocol` | parse **and** build | the default |
| B. Subclassing | subclass `AbstractFrameCodec`, implement `rules()` | parse only | when you need custom logic |

The two mix freely: `FrameSpec.to_codec()` turns an A declaration into a B-style codec.
**Section 3** explains how to choose — read it first, or the rest will feel ambiguous.

- Pure Python, zero dependencies, Python 3.9+
- Three framing modes: length prefix, delimiter (with byte escaping), auto-detect
- Full device-id lifecycle: unknown → learned → used as a sync anchor
- Async streaming API, plugs straight into `asyncio.StreamReader`
- Declarative building: length, checksum, sequence, timestamp, device id all backfilled
- 11 real-world public protocol examples (DL/T645, CJ/T188, M-Bus, Modbus ASCII, BACnet MS/TP, NMEA 0183 …)

---

## Contents

1. [Why this library](#1-why-this-library)
2. [Install](#2-install)
3. [Two APIs, pick one](#3-two-apis-pick-one)
4. [Quick start](#4-quick-start)
5. [Declaring a frame](#5-declaring-a-frame)
6. [Three framing modes](#6-three-framing-modes)
7. [Device id at the frame head](#7-device-id-at-the-frame-head)
8. [Async and streaming](#8-async-and-streaming)
9. [Working with parsed frames](#9-working-with-parsed-frames)
10. [Errors, resync and stats](#10-errors-resync-and-stats)
11. [Building frames in depth](#11-building-frames-in-depth)
12. [Bundled protocols and examples](#12-bundled-protocols-and-examples)
13. [Pitfalls](#13-pitfalls)
14. [API cheat sheet](#14-api-cheat-sheet)
15. [Tests and performance](#15-tests-and-performance)
16. [License](#16-license)

---

## 1. Why this library

The hard part of a TCP custom protocol is never "parse one frame". It is:

- **Sticky / partial packets** — one `recv` may give you half a frame, one and a half,
  or a dozen frames glued together;
- **Resync after garbage** — the connection joins mid-frame, or line noise injects bytes;
- **Untrustworthy length fields** — a corrupted length makes you wait forever and
  swallow the real frames behind it;
- **Checksums** — CRC16 / sum / XOR / LRC, and every vendor picks differently;
- **Building** — length must be backfilled, checksums cover a range, sequence numbers
  increment, device ids get filled in.

`kkprotocol` folds all of that into a **declarative** model: you write one field table,
and both parsing and building derive from it.

```python
from kkprotocol import ChecksumRule, Field, FrameSpec, LengthRule, Protocol, crc16_modbus

# Declare once: what does a frame look like?
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
    length=LengthRule("len"),                    # length field: computed and backfilled
    checksum=ChecksumRule("crc", crc16_modbus),  # checksum field: computed for you
)

proto = Protocol(AURORA)                 # parse and build from the same declaration

for frame in proto.feed(chunk):          # chunk can be split at any byte
    print(frame.value("cmd"), frame.value("data"))

wire = proto.build_raw(0x03, b"hi", dev_id=b"\x00\x00\x00\x01")   # build
```

---

## 2. Install

```bash
pip install kkprotocol
```

From source:

```bash
git clone <your-repo-url>
cd kkprotocol
pip install -e .
```

Python 3.9+, no third-party runtime dependencies.

---

## 3. Two APIs, pick one

**Use A by default. Only drop to B when you need to write parsing logic yourself.**

### 3.1 What they are

| | **A. Declarative** `FrameSpec` | **B. Subclassing** `AbstractFrameCodec` |
|---|---|---|
| What you write | one `FrameSpec(...)` value | a class with `rules()` + `crc_imp()` |
| Parsing | ✅ `Protocol(spec).feed()` / `spec.to_codec().feed()` | ✅ `MyCodec().feed()` |
| Building | ✅ `Protocol(spec).build()`, length/checksum backfilled | ❌ not supported, assemble bytes yourself |
| Length / checksum | `LengthRule` / `ChecksumRule` | length via field expressions, checksum via `crc_imp()` |
| Good for | almost everything (**the default**) | when custom code is genuinely needed |

Both share the **same `Field` table**, so switching costs almost nothing — that is why
the field syntax in the first half of this README applies to both routes.

### 3.2 The same frame, written both ways

Using the `Aurora` frame that the rest of the README uses
(`AA | len | type | cmd | seq(2) | dev(4) | data | crc(2)`):

**Route A** — one spec handles both directions.

```python
AURORA = FrameSpec(
    fields=[...],                          # frame layout, see section 4
    payload="data",                        # which segment is the payload
    length=LengthRule("len"),              # which field is the length, and how to compute it
    checksum=ChecksumRule("crc", crc16_modbus),
    device="dev",                          # which field is the device id
)
proto = Protocol(AURORA, device_id=b"\x00\x00\x00\x07")
frame = proto.feed(wire)[0]                # parse
wire = proto.build("Read", ...)            # build
```

**Route B** — a class that answers only two questions: what are the fields, and how is
the checksum computed.

```python
class AuroraCodec(AbstractFrameCodec):
    device_field = "dev"                   # class attr; A's device=

    def rules(self):                       # A's fields=
        return [ ... the exact same field table ... ]

    def crc_imp(self, data):               # A's ChecksumRule
        return crc16_modbus(data)

frame = AuroraCodec().feed(wire)[0]        # parse only; no build()
```

Only three things differ: A takes `payload / length / checksum / device` as **arguments**,
B takes them as **class attributes** and a method; and A gives you `build()`.

### 3.3 Mixing: an A declaration is also a B codec

```python
codec = AURORA.to_codec()      # FrameSpec -> a plain codec instance
frames = codec.feed(wire)
```

So "I declared it with A, but here I really want a codec object" needs no rewrite.
`Protocol` itself parses through this very path.

### 3.4 When B is actually the right call

- The field table must **change with the command code** (dynamic rules) — see
  `contrib/bacnet_mstp.py` (two frame types) and `example_modbus_rtu_multi.py`
  (dispatch over several specs by function code);
- You need to override resync or device-learning behaviour;
- Existing code already subclasses `AbstractFrameCodec` and you just want to add fields.

Everything else is A: one class less to write, and you get building for free.

> Sections 5–7 cover the **shared rules** (fields, framing, device id) that apply to both
> routes. Each section notes how it is written in A (argument) vs B (attribute).

---

## 4. Quick start

A made-up `Aurora` sensor protocol, used throughout this README:

```
AA | len | type | cmd | seq(2) | dev(4) | data(len-10) | crc(2, CRC16/MODBUS)
len = number of bytes from type through crc
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

#        ┌─ 1st argument: target command, written into the cmd field
#        │        ┌─ 2nd argument: whole payload, goes into the field named by payload="data"
#        │        │            ┌─ everything else by field name: type / seq have no source
wire = proto.build_raw(0x03, b"\x10\x20", type=0x01, seq=1)
print(wire.hex(" "))
# aa 0c 01 03 00 01 00 00 00 07 10 20 98 d1

# Parse: same object
frame = proto.feed(wire)[0]
print(frame.value("cmd"), frame.value("seq"), frame.value("data"))
# 3 1 b'\x10 '

# Self-check: the bytes we emit must parse back with our own receive rules
proto.verify(wire)
```

**Why only `type` and `seq`?** Walk the 8 fields of `AURORA` — each value has exactly one
source, and anything derivable is not your business:

| Field | Where its value comes from | Pass it? |
|---|---|---|
| `header` | `fixed=0xAA`, a constant | no, filled in automatically |
| `len` | computed by `LengthRule("len")` and backfilled | **passing it raises** |
| `type` | no source | ✅ `type=0x01` |
| `cmd` | 1st positional argument | ✅ that `0x03` |
| `seq` | no source (automatic once declared as `AutoField`) | ✅ `seq=1` |
| `dev` | `device="dev"` + `Protocol(device_id=...)` | no, `dev=` may override |
| `data` | 2nd positional argument | ✅ that `b"\x10\x20"` |
| `crc` | computed by `ChecksumRule("crc", ...)` and backfilled | **passing it raises** |

One rule covers all of it: **pass a field only when it can neither be derived nor is a
constant.**

The payload can be supplied in three ways — **per `Pdu.fields`**, **inline with
`Data`/`pack`**, or as **raw bytes** — see
[11.5](#115-supplying-the-payload-three-ways).

A missing field is never silently ignored — `FrameBuildError` names it and lists every
field this frame accepts:

```
缺少参数 ['type']；这帧可用: ['header', 'type', 'cmd', 'seq', 'dev', 'data']
```

(Error messages are currently Chinese-only.) When unsure what to pass, omit something on
purpose and read the list — faster than re-reading docs.

Feed `wire` in blocks split at arbitrary positions and the result is identical — that is
"sticky / partial packets handled".

> Just want to see it run without writing a declaration? There is a ready-made
> `DeviceFrameCodec` (section 12). For your own protocol, use `FrameSpec`.

---

## 5. Declaring a frame

`Field` is the **shared language** of both routes: route A puts the list in
`FrameSpec(fields=[...])`, route B returns it from `rules()`. Every field form below
works in both.

### 5.1 Field factories

`Field` offers a set of factory methods with full IDE hints:

```python
from kkprotocol import Field

Field.u8("cmd")                       # 1-byte unsigned int
Field.u16("seq")                      # 2-byte unsigned int (big-endian by default)
Field.u16("seq", little_endian=True)  # 2-byte little-endian
Field.u32("ts")                       # 4-byte unsigned int
Field.raw("dev_id", 4)                # raw bytes (value is bytes, not a number)
Field.rest("line")                    # "to end of frame" (delimiter framing only)
Field.checksum("crc", 2, group="{len}{cmd}{data}")   # checksum field
```

The full constructor and the legacy dict form are also accepted:

```python
Field(key="header", length=1, fmt="B", fixed=0x55)
{"key": "header", "len": 1, "fmt": "B", "fixed": 0x55}
```

### 5.2 Length expressions

`length` can be an int, a numeric string, an expression, or a callable:

```python
Field.raw("data", 16)                 # fixed 16 bytes
Field.raw("data", "{len.val}-8")      # value of field len, minus 8
Field.raw("data", "{len.val}")        # exactly the value of field len
Field.raw("line", None)               # to end of frame (delimiter framing)
```

Inside an expression `{field.attr}` the attribute can only be:

| Attribute | Meaning |
|---|---|
| `val` | the parsed **value** of the field (integer) |
| `len` / `length` / `bytes` / `raw` | how many **bytes** the field occupies |

### 5.3 `fmt`: what it decodes into

`fmt` is a `struct` format string and must yield exactly one value. Always give an
explicit byte-order prefix for multi-byte values (`!` big-endian / `<` little-endian).

```python
Field.u16("seq")                   # internally fmt="!H"
Field.raw("payload", 4, fmt="!f")  # 4-byte big-endian float
```

### 5.4 `group`: which bytes the checksum covers

- A field with `group` (or `crc=True`) is a **checksum field**;
- `group` decides which fields take part:

```python
Field.checksum("crc", 2, group="{len}{cmd}{data}")   # checksum over len, cmd, data
Field.checksum("crc", 2)                             # no group: everything before it
```

**How to supply the algorithm differs between routes:**

| | Route A (`FrameSpec`) | Route B (subclass) |
|---|---|---|
| Where | `checksum=ChecksumRule("crc", crc16_modbus)` | `def crc_imp(self, data)` |
| Returns | same contract as `crc_imp` | `int` (packed per field `fmt`) or `bytes` (used as-is) |

Returning `bytes` is recommended — it is byte-order safe and independent of `fmt`.

Built-in algorithms: `crc16_modbus`, `crc16_x25`, `crc16_ccitt`, `crc8`, `sum8`, `xor8`.

---

## 6. Three framing modes

| Mode | Use for | Frame boundary | Escaping needed |
|---|---|---|---|
| Length `LENGTH_FRAMING` | binary TCP protocols (first choice) | length field | no |
| Delimiter `DelimiterFraming` | serial / transparent links / text protocols | special byte | yes |
| Auto `AUTO_FRAMING` | probing when unsure | length first, then delimiter | depends |

How to set it: route A passes `FrameSpec(framing=...)`, route B sets the class attribute
`framing = ...` — same values. The examples below use route B so you can see that framing
is a property of the codec; for A, pass the same value as an argument.

### 6.1 Length framing (default)

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

Once a length field is corrupted, the protocol cannot heal itself (it waits for the wrong
number of bytes). Use `max_frame_size` to kill bogus lengths early, plus `idle_timeout` /
`drop_pending()` as a safety net (see section 10).

### 6.2 Delimiter framing (with escaping / transparency)

PPP / HDLC style: `0x7E` at both ends, with `0x7E` / `0x7D` inside the payload escaped to
`0x7D 0x5E` / `0x7D 0x5D`.

```python
from kkprotocol import AbstractFrameCodec, DelimiterFraming, Field, crc16_x25

PPP = DelimiterFraming(end=0x7E, start=0x7E, escape=0x7D, escape_xor=0x20)

class PppCodec(AbstractFrameCodec):
    framing = PPP                      # accepts a DelimiterFraming instance
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

Notes:

- In delimiter mode a length field **must not** be used to cut frames (escaping makes the
  on-wire length differ from the payload length); it is only a checksum input;
- `start == end` means one shared flag (PPP/HDLC); different values mean "between them";
- Two escaping schemes are supported: `escape_xor` (PPP) and `escape_map` (SLIP);
- `Field.rest("...")` only works in delimiter framing; if fixed-length fields follow
  (a trailing FCS, say), the reserved bytes are **excluded** from `rest` automatically.

### 6.3 Auto `AUTO_FRAMING`

Probe length framing first, fall back to delimiter framing, then lock onto whichever hit:

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

## 7. Device id at the frame head

Many private protocols lead with a **device id** instead of a fixed header, and that id is
unknown for the very first frame. Declare which field it is — route A:
`FrameSpec(device="dev_id")`, route B: `device_field = "dev_id"` — and the codec will:

1. let the first frame through and **learn** the id;
2. once learned, use its bytes as a **sync anchor** (far more distinctive than a fixed header);
3. optionally "lock after learn" — later frames with a different id are treated as garbage.

```python
class HeadDeviceCodec(AbstractFrameCodec):
    device_field = "dev_id"
    sync_from_device = True         # use the learned id as the resync token
    lock_device_after_learn = True  # lock once learned
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

With several devices on one bus, turn `lock_device_after_learn` off and dispatch on
`frame.device_mismatch` yourself.

In route A only `device=` is a spec argument; the other policies live on the codec and are
set through `Protocol.codec` (`codec` is a lazily created property):

```python
proto = Protocol(AURORA, device_id=b"\x00\x00\x00\x07")
proto.codec.sync_from_device = True
proto.codec.lock_device_after_learn = True
```

| Attribute | Effect |
|---|---|
| `device_field` (A: `device=`) | which field holds the device id |
| `auto_learn_device` | learn when unknown (on by default) |
| `enforce_device_id` | reject mismatches outright (off by default; only sets `device_mismatch`) |
| `lock_device_after_learn` | lock the id once learned |
| `sync_from_device` | use the device id as a resync anchor |
| `preempt_on_sync` | cut a candidate frame blocked by a bogus length (heuristic, off by default) |
| `device_id_provider` | fetch an unknown id from a registry/DB once |

---

## 8. Async and streaming

```python
import asyncio
from kkprotocol import DeviceFrameCodec

async def main():
    reader, writer = await asyncio.open_connection("127.0.0.1", 9000)
    codec = DeviceFrameCodec()
    codec.idle_timeout = 5.0            # drop a half frame after 5s idle
    async for frame in codec.read_frames(reader):
        print(frame.value("cmd"), frame.value("data"))

asyncio.run(main())
```

- `feed(chunk)`: synchronous, pure in-memory, the fast path;
- `feed_async(chunk)`: only offloads to a thread pool above `offload_threshold`
  (256 KB default), so the event loop stays responsive;
- `read_frames(reader)` / `iter_frames(chunks)`: turn asyncio streams into frame iterators;
- **One codec instance per connection** (buffers are never shared).

---

## 9. Working with parsed frames

`feed()` returns a list of `Frame`:

```python
frame = codec.feed(wire)[0]

frame.value("cmd")          # decoded value
frame["cmd"].raw            # raw bytes of that field
frame.raw_of("cmd")         # same thing
frame.device_id             # device id (from device_field)
frame.device_mismatch       # differs from the bound device id
frame.learned_device        # this frame triggered device learning
frame.framing               # "length" / "delimiter"
frame.to_bytes(wire=True)   # the exact bytes as they appeared on the wire (incl. framing/escapes)
frame.to_hex()              # "55 0C 01 03 ..."
frame.as_dict()             # {field name: value}
```

`FieldValue` keeps both `raw` (bytes after unescaping) and `val` (decoded per `fmt`);
when `fmt` is empty, `val` is `raw`.

---

## 10. Errors, resync and stats

Internally "half frame" and "garbage" are handled separately:

- **Half frame** → returns an empty list, waits for the next `feed` (no data lost);
- **Garbage** → jump to the next candidate position using the sync anchor (header / device id);
- **Checksum failure** → drop the whole frame and resync (`on_crc_error="resync"`),
  or skip it entirely (`"skip_frame"`);
- **Length vs structure contradiction** → counted in `length_mismatches`, candidate dropped.

```python
codec.stats.bytes_in             # total bytes received
codec.stats.frames               # frames parsed successfully
codec.stats.resyncs              # resync count
codec.stats.crc_errors           # checksum failures
codec.stats.length_mismatches    # length inconsistencies
codec.stats.device_mismatches    # device id mismatches
codec.stats.rejected_frames      # frames rejected by the on_frame hook
codec.stats.dropped_bytes        # bytes discarded
codec.stats.overflow_drops       # buffer overflow drops
```

Escape hatches:

```python
codec.reset()            # drop pending bytes (on reconnect)
codec.drop_pending()     # drop whatever has not formed a frame
codec.reset_framing()    # re-probe in auto mode
```

---

## 11. Building frames in depth

Section 4 already showed build-and-parse end to end. This section covers the mechanics.

One common misunderstanding first: **a single `FrameSpec` serves both building (`build`)
and parsing (`feed`)** — building does *not* need a different rule set. `Protocol` parses
by calling `rx.to_codec()`, turning the same declaration into a codec. You only write a
second spec when the two directions genuinely differ (an ack that omits fields, a command
code offset by `0x80`), and hand it to `Protocol(tx=..., rx=...)`.

Only three things are actually asymmetric, and the builder handles them:

| Declared as | When parsing | When building |
|---|---|---|
| length field | read it | **compute** and backfill |
| checksum field | verify it | **compute** it |
| constant field `fixed=` | compare it | fill it in |

### 11.1 Length backfill: a fixed-point loop

The length depends on the body, which contains the length field, so the builder runs a
**fixed-point loop**: assume `len=0/crc=0`, assemble a frame, measure it and compute the
checksum, compare with what the frame says, and repeat. Typically 2–3 rounds.

Two conventions:

- `LengthRule("len")` (`span=None`, default): everything **after the length field to the
  end of the frame**, **including** the checksum;
- `LengthRule("len", span=("a", "b"))`: a field-name range, both ends inclusive — use it
  when the checksum must be excluded.

### 11.2 `Pdu`: declaring one command

```python
from kkprotocol import Pdu

AURORA_WITH_PDU = FrameSpec(
    fields=[...],                       # same as above
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

The command code is never written twice: the key of `pdus` *is* the command code and is
backfilled into `Pdu.cmd`. The explicit form `Pdu("Read", 0x03, [...])` also works; if the
two disagree, declaration raises immediately (key and `Pdu.cmd` may not fight). The second
positional argument may be the field list directly — a command code is always a scalar,
never a sequence, so there is no ambiguity.

`Pdu.resp` pins the ack command code explicitly (default `cmd | 0x80`):
`Pdu("Read", resp=0x83)`.

### 11.3 Device id and auto fields

Besides length, checksum and device id, any field that changes every frame is declared as
an `AutoField`; 0..N of them are allowed:

```python
import time
from kkprotocol import AutoField

TIME_AND_SEQ = FrameSpec(
    fields=[...],
    auto=[
        AutoField("seq", start=0, step=1, wrap=0x10000),               # auto-increment counter
        AutoField("ts", provider=lambda: int(time.time()) & 0xFFFF),   # timestamp
    ],
)
```

- `provider=None`: an incrementing counter;
- `provider=callable`: called once per build;
- `echo=True`: `build_ack()` echoes the same field from the request (acks usually carry
  the sequence number back).

### 11.4 Self-check before sending

```python
proto = Protocol(AURORA, device_id=b"\x00\x00\x00\x07")
wire = proto.build_raw(0x03, b"\x10\x20", type=1, seq=1)
frame = proto.verify(wire)      # parse with the receive rules: exactly one frame, no leftovers
proto.diff()                    # differences between the tx and rx specs (when they differ)
```

### 11.5 Supplying the payload: three ways

Pick by whether this data has a declared structure:

| Way | Form | Good for |
|---|---|---|
| ① per `Pdu.fields` | `build("Read", addr=0, count=2)` | fixed request layout, fields have names and types |
| ② `Data` + `pack` inline | `build_raw(0x03, [Data.u8(0), Data.bool(True), Data.str("test", count=24)])` | one-off layouts not worth a `Pdu` |
| ③ hand-written bytes | `build_raw(0x03, b"\x00\x02")` | the payload already is raw bytes |

**① field by field** — declare the `Pdu` first (section 11.2), one keyword per field.

```python
proto.build("Read", type=1, seq=1, addr=0x00, count=2)
```

**② `Data` + `pack`** — no `Pdu` needed; list the values and let the library encode them.

```python
from kkprotocol import Data, pack

body = pack(
    Data.u8(0x00),                              # 1 byte
    Data.u8(0x00),                              # 1 byte
    Data.bool(True),                            # 0x01
    Data.str("test", count=24, fill=b"\x00"),    # fixed 24, padded with \0
)
proto.build_raw(0x03, body, type=1, seq=1)

# a list can be passed as the payload directly, no pack() call needed
proto.build_raw(0x03, [Data.u8(0), Data.u8(0), Data.bool(True), Data.str("test", count=24)], type=1, seq=1)
```

`Data.xxx(value)` returns an encoded value; `pack()` concatenates them into `bytes`.
The available constructors:

| Call | Bytes | Result |
|---|---|---|
| `Data.u8(0x12)` | 1 | `12` |
| `Data.u16(0x1234)` | 2 | `12 34` |
| `Data.u16(0x1234, little_endian=True)` | 2 | `34 12` |
| `Data.u32(...)` / `Data.u64(...)` | 4 / 8 | big-endian |
| `Data.i8(-1)` / `Data.i16` / `Data.i32` / `Data.i64` | 1/2/4/8 | signed |
| `Data.f32(1.5)` / `Data.f64(1.5)` | 4 / 8 | IEEE754, `3f c0 00 00` |
| `Data.bool(True)` | 1 | `01` |
| `Data.str("test", count=8)` | 8 | `74 65 73 74 00 00 00 00`, truncated if longer |
| `Data.char(...)` | — | alias of `Data.str` |
| `Data.raw(b"\x01\x02")` | 2 | bytes as-is |
| `Data.zeros(3)` | 3 | `00 00 00` |

> **Why are `Field` and `Data` two separate classes?** Their first argument means
> different things: `Field.u8("cmd")` takes a **field name** — declare once, then read
> values back by that name in both directions; `Data.u8(0x12)` takes a **value** and is
> thrown away once encoded. Merging them would make `Field.u8(0)` ambiguous (is `0` a
> field name or a value?), so they stay separate: **`Field` describes structure, `Data`
> fills in values, `pack` joins them.**

**③ hand-written bytes**:

```python
proto.build_raw(0x03, b"\x00\x02", type=1, seq=1)
```

All three produce **byte-identical** frames — ③ assembles bytes by hand, ② is just its
typed spelling (`Data.u8(1)` *is* `b"\x01"`, minus the byte-order arithmetic), and ① is
done for you by `Pdu.fields`:

```python
proto.build("Write", type=1, seq=1, a=0x01, b=0x0203)      # ① per field
proto.build_raw(0x03, [Data.u8(0x01), Data.u16(0x0203)], ...)    # ② Data list
proto.build_raw(0x03, b"\x01\x02\x03", ...)                # ③ raw bytes
```

All three build the very same frame:

```
aa 0d 01 03 00 01 00 00 00 07 01 02 03 3b ad
```

`build_raw(target, payload)` is also equivalent to `build(target, data=payload)` —
whatever the payload field is called, that is the keyword; the bytes come out the same.

**① and ②③ are mutually exclusive**: once `pdus` is declared you cannot hand over the
whole segment, and vice versa. Using the wrong one fails immediately, and the error lists
the fields that mode accepts:

| Case | Error |
|---|---|
| pdus declared, still passing `data=` | `不认识的参数 ['data']；这帧可用: [... 'addr', 'count']` |
| `build_raw` but passing `addr=` | `不认识的参数 ['addr']；这帧可用: [... 'data']` |

Which is why "read the 这帧可用 list" remains the fastest way to learn a frame's signature.

> Omitting the payload field means an **empty payload**, not an error:
> `build(0x03, type=1, seq=1)` yields `aa 0a ...` (`len=10`, zero data bytes). Some
> protocols have exactly such empty frames, so this is deliberately not enforced.

Also:

- `target` may be a command code `0x03`, a command name `"Read"`, or a `Pdu` — all equivalent;
- field order in `Pdu.fields` is the on-wire order; you never compute offsets by hand;
- going field by field, `fmt` decides the packing width (`Field.u16("value")` packs as
  `!H`), which beats hand-writing `b"\x00\xfa"`.

Three things that bite:

| Symptom | Cause | Fix |
|---|---|---|
| `缺少参数 ['type']` | that field has no source in the declaration | pass it by name; the error lists every accepted field |
| `字段 'len' 由 builder 自动计算` | length/checksum fields reject manual values | drop `len=` / `crc=`, they are computed |
| `header=0xBB` is passed but the frame still says `AA` | `fixed=` fields trust the declaration; manual values are **silently ignored** | change `fixed=` in the declaration instead |

The last one is the sneaky one: no error, no effect. To change a fixed header or version
byte, edit `Field.u8(..., fixed=...)`.

> Fields declared as `AutoField` (an incrementing `seq`, say) **can** be passed manually:
> this frame uses your value, and the counter continues from it afterwards. `seq=5` means
> the next frame gets `6`.

---

## 12. Bundled protocols and examples

### 12.1 A ready-to-run example frame

`kkprotocol.example_device` ships three **route B** codecs that double as templates:

- `DeviceFrameCodec`: length framing + device id;
- `PppFrameCodec`: `0x7E` delimiter + `0x7D` escaping;
- `HeadDeviceFrameCodec`: device id at the frame head (unknown at first).

`DeviceFrameCodec` uses
`55 | len | ver | cmd | ser(2) | dev_id(4) | data(len-10) | crc(2, CRC16/MODBUS)`:

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

Run it once to get a feel; for your own protocol, change the fields of the `FrameSpec`
from section 4.

### 12.2 Public protocols (contrib)

`kkprotocol.contrib` contains implementations of **public standards** (regression and
reference only — **not exported at the top level**, import as needed):

| Protocol | Framing | Checksum | Module |
|---|---|---|---|
| DL/T645-2007 (electricity meter) | length + `0x68` | byte sum | `contrib.dlt645` |
| CJ/T188-2004 (water/gas/heat meter) | length + `0x68` | byte sum | `contrib.cjt188` |
| M-Bus (EN 13757) | length, two length bytes | byte sum | `contrib.mbus` |
| ccTalk (currency peripherals) | length, no header | zero-sum | `contrib.cctalk` |
| XModem / YModem | fixed frame size | CRC-16/CCITT | `contrib.xmodem` |
| SLIP (RFC 1055) | delimiter `0xC0` | none | `contrib.slip` |
| HDLC / PPP | delimiter `0x7E` + escaping | CRC-16 | `contrib.hdlc` |
| Art-Net | length + multi-byte magic | none | `contrib.artnet` |
| Modbus ASCII | delimiter `:`…`\n`, ASCII-hex | LRC | `contrib.modbus_ascii` |
| NMEA 0183 | delimiter `$`…`\n`, text | inline XOR | `contrib.nmea` |
| BACnet MS/TP | length + `55 FF`, two CRCs | header CRC8 + body CRC16 | `contrib.bacnet_mstp` |

```python
from kkprotocol.contrib import dlt645

wire = dlt645.build_request(b"\x01\x00\x00\x00\x00\x00", ctrl=0x11, data=b"\x10\x01")
frame = dlt645.protocol(b"\x01\x00\x00\x00\x00\x00").feed(wire)[0]
print(dlt645.decode_data(frame.value("data")))   # b'\x10\x01'
```

> Frames with more than one checksum (BACnet's header CRC + body CRC, for example) are
> fully supported when parsing: `FrameSpec.checksum` accepts a list of `ChecksumRule`, and
> each checksum field is verified with its own algorithm. When building, only the first
> one is backfilled.

---

## 13. Pitfalls

1. **Marking a variable field `fixed`**: a hard-coded sequence number or timestamp kills
   every frame.
2. **Mixing up `{n.val}` and `{n.len}`**: the former is the field's **value**, the latter
   is how many **bytes** it occupies. Payload size from a length field is `{len.val}`;
   `{len.len}` always skips 1–2 bytes.
3. **Writing `{n}` (no attribute) in a length expression**: compile-time error; `{n}` is
   only valid inside a checksum `group`.
4. **Using `.val` on an `fmt=""` field**: `Field.raw("dev", 4)` yields `bytes`; use `{dev.len}`.
5. **`fmt` inconsistent with `length` in `Field.checksum`**: `fmt` is derived from
   `length`; writing `fmt="!H"` while declaring `length=1` fails at compile time.
6. **Leaving `max_frame_size` at its 64 KB default**: a bogus length claiming 65535 keeps
   you waiting; tighten it to the real maximum.
7. **Forgetting escaping in delimiter framing**: a delimiter byte inside the payload cuts
   the frame, and the CRC may not save you.
8. **`crc_imp` returning `int` with a wrong `fmt` byte order**: checksums never pass and
   nothing errors — you just keep resyncing. Prefer returning `bytes`.
9. **`Field.rest()` in length framing**: compile-time error (length framing has no
   "end of frame").
10. **A length expression referencing a later field**: compile-time error (forward
    references only).
11. **Sharing one codec instance across connections**: buffers interleave. One instance
    per connection.
12. **Passing `len`/`crc` by hand when building**: rejected — the builder computes both.
13. **`ChecksumRule.impl` returning a different value each call**: the fixed-point loop
    cannot converge and reports oscillation.
14. **Reusing one spec when tx and rx differ**: it builds but will not parse. Write two
    specs and pass `Protocol(tx=..., rx=...)`.
15. **A wrong offset in the payload length expression**: the end-of-build consistency
    check catches it and warns that the peer will misalign under the same rule.
16. **Passing a value for a `fixed=` field at the call site** (e.g. `build(..., header=0xBB)`):
    no error and no effect — the declaration wins. Edit `Field.u8("header", fixed=...)`.
17. **Assuming `AutoField` fields cannot be given manually**: they can. The value you pass
    is used for this frame and the counter continues from it.

---

## 14. API cheat sheet

Three blocks: what **both routes share** (`Field` / exceptions), then **route A**, then
**route B**.

```python
# ============ Shared: Field factories (A: FrameSpec.fields, B: return from rules()) ============
Field.u8 / u16 / u32 / u64 / raw / rest / checksum
Field(key=..., length=..., fmt=..., fixed=..., group=..., crc=..., desc=...)
#   length: int | "10" | "{len.val}-8" | callable(fields) | None (to end of frame)
#   fmt:    ""(bytes) | "B" | "!H" | "<H" | "!I" | "!Q" | "!f" | "4s" ...
#   group:  "{n}{cmd}{body}"  (field names only, no attributes)

# Shared: payload value constructors (value in, bytes out, no field name; see 11.5)
Data.u8 / i8 / u16 / i16 / u32 / i32 / u64 / i64 / f32 / f64
Data.bool(v) / Data.str(s, count=, fill=) / Data.char(...) / Data.raw(b) / Data.zeros(n)
pack(*items) -> bytes        # also accepts a single list; build_raw takes them directly

# Shared: exceptions
FrameRuleError     # bad rule, should surface at startup
FrameBuildError    # these arguments/data cannot produce a valid frame

# ============ Route A: declarative (FrameSpec + Protocol) ============
FrameSpec(fields, framing, payload, cmd, length, checksum, pdus, device, seq, auto, max_frame_size)
  .to_codec() -> AbstractFrameCodec   # turn it into a plain codec instance
  .pdu(target) / .field(key) / .field_keys() / .group_keys(key)
  .diff(other) -> List[str]
LengthRule(key, span=None)          # span=None: after the length field to end of frame (incl. checksum)
ChecksumRule(key, impl)             # impl returns int (packed per fmt) or bytes (used as-is)
                                    #   multiple checksums: checksum=[ChecksumRule(...), ChecksumRule(...)]
SeqPolicy(key, enabled=False, start=0, step=1, wrap=0x10000)   # one counter
AutoField(key, start=0, step=1, wrap=0x10000, provider=None, echo=True)  # 0..N of them
Pdu(name, cmd=None, fields=(), resp=None)   # cmd optional: backfilled from the pdus key

Protocol(tx=SPEC, rx=SPEC2, device_id=..., enforce_device_id=False, max_rounds=8)
  .build(target, **fields)             # command name / code / Pdu -> wire bytes
  .build_frame(target, **fields)       # returns BuildResult(trace/values/body/rounds)
  .build_raw(target, payload, **shell) # whole payload at once, no Pdu.fields packing
  .build_ack(frame, **fields)          # ack: cmd|0x80 (or Pdu.resp), seq/device echoed
  .feed(data) / .verify(wire) / .diff()
  .codec                               # underlying codec (for sync_from_device etc.)

FrameBuilder(spec, device_id=..., max_rounds=8)      # lightweight build-only entry point
  .build / .build_frame / .build_raw / .device_id / .seq / .auto_keys

# ============ Route B: subclassing (AbstractFrameCodec) ============
# Must implement
rules() -> Sequence[Field]          # frame layout
crc_imp(data: bytes) -> int|bytes   # checksum algorithm

# Class attributes: framing and policies
framing / delimiter / sync / lock_framing
max_frame_size / max_buffer / on_crc_error
device_field / auto_learn_device / enforce_device_id / device_id_provider
lock_device_after_learn / sync_from_device / preempt_on_sync
offload_threshold / idle_timeout / drop_pending_on_idle

# Data entry points
feed(data) / filter(data) / feed_async(data) / read_frames(reader) / iter_frames(chunks)

# Lifecycle
compile() / reset() / reset_framing() / drop_pending()
bind_device(x) / forget_device()
pending_bytes / framing_mode / device_id / stats

# Hooks
on_frame(frame) -> bool
on_device_learned(device_id, frame)
```

Built-in CRCs: `crc16_modbus`, `crc16_x25`, `crc16_ccitt`, `crc8`, `sum8`, `xor8`.

---

## 15. Tests and performance

```bash
python -m unittest discover -s tests -p "test_*.py"
python -m coverage run --source=kkprotocol -m unittest discover -s tests -p "test_*.py"
python -m coverage report -m
```

- **591 tests, all passing** (reproducible with the commands above; stdlib `unittest`
  only, no pytest needed);
- Coverage: sticky packets / byte-by-byte splits / garbage prefixes / bad checksums /
  device learning / multi-frame dispatch / async / fixed-point convergence / delimiter
  escaping / multiple checksums per frame / `rest` tail reservation;
- Plus a batch regression over 11 real public protocols (`tests/test_contrib_protocols.py`).

Rough numbers (pure-Python checksum, 200-byte frames): 20k–40k frames/s per connection;
200 Hz × 8 channels (about 1600 frames/s) is comfortably within budget. The bottleneck is
usually the peer or your business logic, not the parser.

---

## 16. License

MIT License. See the `LICENSE` file in this repository.
