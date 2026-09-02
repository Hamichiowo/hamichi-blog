---
title: "FLARE On Challenges 1 wp"
date: 2026-09-2 00:00:00 +0800
last_modified_at: 2026-09-2 00:00:00 +0800
categories: [CTF]
tags: [Rev, FLARE-On]
description: "FLARE-On wp"
media_subpath: /assets/img/posts/FLARE-On-Challenges-1-wp
image:
  path: FLARE-On-Challenges.png
  alt: FLARE On Challenges
---

## 前言
> 題目：https://flare-on.com/

## 解題
先查看執行檔是用甚麼寫的
```
┌──(hamichi㉿Hamichi)-[/mnt/c/Users/Hamic/Desktop/CTF/2014_FLAREOn_Challenges]
└─$ file Challenge1.exe
Challenge1.exe: PE32 executable for MS Windows 4.00 (GUI), Intel i386 Mono/.Net assembly, 3 sections
```

知道是 .Net 寫的，所以決定使用 dnSpy 進行逆向（也可以動態），但在那以前先跑起來看看

- 初始狀態
![](/assets/img/posts/FLARE-On-Challenges-1-wp/file-20260612034744036.png)

- 按完 DECODE 後

![](/assets/img/posts/FLARE-On-Challenges-1-wp/file-20260612034744035.png)

猜測這裡進行了 `DECODE` 再進行了一次 `ENCODE`，所以嘗試找到可疑 Function 設 break point 讀變數
直接用 dnSpy 把檔案開起來，看到以下架構：
![](/assets/img/posts/FLARE-On-Challenges-1-wp/file-20260612034744034.png)

架構說明：

| 節點                                     | 內容              | 用途                              |
| -------------------------------------- | --------------- | ------------------------------- |
| `XXXXXXXXXXXXXXX (1.0.0.0)`            | Assembly 本體     | 最外層容器                           |
| `PE`                                   | Windows PE 檔案結構 | 查看底層檔案格式、section、CLR header     |
| `Type References`                      | 外部型別引用          | 看程式用了哪些 .NET 類別                 |
| `References`                           | 外部 Assembly 引用  | 看用了哪些 DLL                       |
| `Resources`                            | 內嵌資源            | 圖片、文字等                          |
| `XXXXXXXXXXXXXXX` namespace            | 主程式命名空間         | 通常放 `Program`、`Form1`、主要邏輯      |
| `XXXXXXXXXXXXXXX.Properties` namespace | 專案屬性命名空間        | 放自動產生的 `Resources`、`Settings` 等 |

了解基礎架構後我們應該先去看 `XXXXXXXXXXXXXXX` namespace 裡面放了什麼
![](/assets/img/posts/FLARE-On-Challenges-1-wp/file-20260612034744028.png)

發現 `btnDecode_Click` 很可疑，看一下寫了什麼
```c
// XXXXXXXXXXXXXXX.Form1
// Token: 0x06000002 RID: 2 RVA: 0x00002060 File Offset: 0x00000260
private void btnDecode_Click(object sender, EventArgs e)
{
	this.pbRoge.Image = Resources.bob_roge;
	byte[] dat_secret = Resources.dat_secret;
	string text = "";
	foreach (byte b in dat_secret)
	{
		text += (char)((b >> 4 | ((int)b << 4 & 240)) ^ 41);
	}
	text += "\0";
	string text2 = "";
	for (int j = 0; j < text.Length; j += 2)
	{
		text2 += text[j + 1];
		text2 += text[j];
	}
	string text3 = "";
	for (int k = 0; k < text2.Length; k++)
	{
		char c = text2[k];
		text3 += (char)((byte)text2[k] ^ 102);
	}
	this.lbl_title.Text = text3;
}
```

可以看出從 dat_secret 取出並逐 byte 處理加密資料，然後把 byte 的高 4 bits 和低 4 bits 交換，也就是 nibble swap，再跟 `0x29` 做 XOR，並把結果放進`text`

我這裡應該就是把加密資料先解密，然後進行二次加密在顯示，所以我設了break point 在 `string text2 = "";` 並讀變數`text`，並成功發現FLAG
![](/assets/img/posts/FLARE-On-Challenges-1-wp/file-20260612034744022.png)

這題其實也可以直接 dump  `Resources.dat_secret` 並寫 decode 的程式去解密，因為我們有完整的加密流程

`solve.py`：
```python
#!/usr/bin/env python3

from pathlib import Path

data = Path("Resources.dat_secret").read_bytes()

# text
text = ""
for b in data:
    value = ((b >> 4) | ((b << 4) & 0xF0)) ^ 41
    text += chr(value)

text += "\0"

# text2
text2 = ""
for j in range(0, len(text), 2):
    text2 += text[j + 1]
    text2 += text[j]

# text3
text3 = ""
for k in range(len(text2)):
    text3 += chr(ord(text2[k]) ^ 102)

print("[text]")
print(repr(text))
print()

print("[text2]")
print(repr(text2))
print()

print("[text3]")
print(repr(text3))
print()

print("[text3 clean]")
print(text3.replace("\x00", ""))
```

`output`：
```text
[text]
'3rmahg3rd.b0b.d0ge@flare-on.com\x00'

[text2]
'r3amghr3.d0b.b0degf@alero-.noc\x00m'

[text3]
'\x14U\x07\x0b\x01\x0e\x14UH\x02V\x04H\x04V\x02\x03\x01\x00&\x07\n\x03\x14\tKH\x08\t\x05f\x0b'

[text3 clean]
U
 UHVHV&
        KH      f


```


