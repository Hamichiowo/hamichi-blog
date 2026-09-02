---
title: "FLARE On Challenges 3 wp"
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


裡面有個執行檔，檢查一下格式
```
┌──(hamichi㉿Hamichi)-[/mnt/c/Users/Hamic/Desktop/CTF/2014_FLAREOn_Challenges/C3]
└─$ file such_evil
such_evil: PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 2 sections
```

 丟進 Binary Ninja 看看，發現在 `sub_401000`有段很怪的code，寫入了很多都東西進stack，而且是分開一個一個寫，最後還透過`(&var_205)()`跳回最上面
```
00401000    int32_t sub_401000()

0040100f        char var_205 = 0xe8
0040101a        char var_204 = 0
00401025        char var_203 = 0
00401030        char var_202 = 0
0040103b        char var_201 = 0
00401046        char var_200 = 0x8b
00401051        char var_1ff = 0x34
0040105c        char var_1fe = 0x24
00401067        char var_1fd = 0x83
00401072        char var_1fc = 0xc6
0040107d        char var_1fb = 0x1c
00401088        char var_1fa = 0xb9
00401093        char var_1f9 = 0xdf
0040109e        char var_1f8 = 1
004010a9        char var_1f7 = 0
004010b4        char var_1f6 = 0
004010bf        char var_1f5 = 0x83
004010ca        char var_1f4 = 0xf9
004010d5        char var_1f3 = 0
004010e0        char var_1f2 = 0x74
004010eb        char var_1f1 = 7
004010f6        char var_1f0 = 0x80
00401101        char var_1ef
00401101        __builtin_strncpy(dest: &var_1ef, src: "6fFI", count: 4)
0040112d        char var_1eb = 0xeb
00401138        char var_1ea = 0xf4
00401143        char var_1e9 = 0xe9
0040114e        char var_1e8 = 0x10
00401159        char var_1e7 = 0
00401164        char var_1e6 = 0
0040116f        char var_1e5 = 0
0040117a        char var_1e4
0040117a        __builtin_memcpy(dest: &var_1e4, 
0040117a            src: "\x07\x08\x02\x46\x15\x09\x46\x0f\x12\x46\x04\x03\x01\x0f\x08\x15\x0e\x13\x15\x"
0040117a        "66\x66\x0e\x15\x07\x13\x14\x0e\x08\x09\x16\x07\xef\x85\x8e", 
0040117a            count: 0x22)
004012f0        char var_1c2
004012f0        __builtin_strncpy(dest: &var_1c2, src: "ffff", count: 4)
0040131c        char var_1be
0040131c        __builtin_memcpy(dest: &var_1be, 
0040131c            src: "\xed\x52\x42\xe5\xa0\x4b\xef\x97\xe7\xa7\xea\x67\x66\x66\xef\xbe\xe5\xa6\x6c\x"
0040131c        "5f\xbe\x13\x63\xef\x85\xe5\xa5\x62\x5f\xa8\x12\x6e\xec", 
0040131c            count: 0x21)
00401487        char var_19d
00401487        __builtin_strncpy(dest: &var_19d, src: "uVp% ", count: 5)
004014be        char var_198 = 0x8d
004014c9        char var_197 = 0x8d
004014d4        char var_196 = 0x8f
004014df        char var_195
004014df        __builtin_strncpy(dest: &var_195, 
004014df            src: "Wfffolb\'gbrpj5|f6`ps3z|e/lr\'fh3prxf)~fgc3}}5|as\'efzzg", count: 0x35)
00401726        char var_160
00401726        __builtin_memcpy(dest: &var_160, 
00401726            src: "\xfd\x08\x09\x16\x07\x9e\x33\x37\x97\xd5\x0b\xb1\x31\x17\x07\x15\x84\xea\x14\x"
00401726        "6d\x1b\x89", 
00401726            count: 0x16)
00401818        char var_14a
00401818        __builtin_strncpy(dest: &var_14a, src: "?tHy@", count: 5)
0040184f        char var_145 = 0x90
0040185a        char var_144 = 0xd2
00401865        char var_143 = 0x17
00401870        char var_142 = 0x96
0040187b        char var_141 = 0xe1
00401886        char var_140 = 0xd
00401891        char var_13f = 0xfd
0040189c        char var_13e = 0xea
004018a7        char var_13d = 0xfa
004018b2        char var_13c = 0xc8
004018bd        char var_13b
004018bd        __builtin_strncpy(dest: &var_13b, src: "\x7fSqZ", count: 4)
004018e9        char var_137 = 0xe9
004018f4        char var_136 = 0xce
004018ff        char var_135
004018ff        __builtin_strncpy(dest: &var_135, src: "tHy@", count: 4)
0040192b        char var_131 = 0xe1
00401936        char var_130 = 0xcb
00401941        char var_12f = 0xef
0040194c        char var_12e = 0xc2
00401957        char var_12d = 2
00401962        char var_12c
00401962        __builtin_strncpy(dest: &var_12c, src: "4EaH _<", count: 7)
004019af        char var_125
004019af        __builtin_memcpy(dest: &var_125, 
004019af            src: "\x07\x3f\x0c\x23\x1b\x3b\x0d\x28\x05\x7b\x1e\x3e\x02\x2f\x09\x60\x1e\x20\x10\x"
004019af        "3e\x16\x7a\xed\xad\x9c", 
004019af            count: 0x19)
00401ac2        char var_10c
00401ac2        __builtin_strncpy(dest: &var_10c, src: "Hy@q", count: 4)
00401aee        char var_108
00401aee        __builtin_memcpy(dest: &var_108, 
00401aee            src: "\xd0\x4b\x76\xe9\x80\x57\xc9\x86\xc9\xbe\x85\x71\x5a\x64\xc7\xac\xcb\xb9\x58\x"
00401aee        "48\x83\x0a\x57\xe3\xa5\xf9\x83\x73\x71\xb1\x27\x79\xd0\x77\x7e\x62\x0b\x3f\xab\x9a"
00401aee        "b2", 
00401aee            count: 0x29)
00401cb1        char var_df
00401cb1        __builtin_memcpy(dest: &var_df, src: "bRjFfXs", count: 0xdb)
0040249b        (&var_205)()
004024a8        return 0

```

現在我們要來分析他都做了些甚麼，看起來是在寫 shellcode 然後跳回去執行，這裡有兩個解法，一個是利用 `WinDbg` 進行動態分析，把 break point 設在 `0x0040249b` ，看 0x205 寫了什麼並dump出來。另一個方式就是利用 Binary Ninja 內建 python 腳本跑。

```
0:000> bp 0040249b
0:000> g
Breakpoint 0 hit
eax=001afd33 ebx=003f1000 ecx=001aff50 edx=00000000 esi=004024c0 edi=004024c0
eip=0040249b esp=001afd30 ebp=001aff34 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
such_evil+0x249b:
0040249b ffd0            call    eax {001afd33}
0:000> r ebp
ebp=001aff34
0:000> db @ebp-205 L40
001afd2f  00 00 00 00 e8 00 00 00-00 8b 34 24 83 c6 1c b9  ..........4$....
001afd3f  df 01 00 00 83 f9 00 74-07 80 36 66 46 49 eb f4  .......t..6fFI..
001afd4f  e9 10 00 00 00 07 08 02-46 15 09 46 0f 12 46 04  ........F..F..F.
001afd5f  03 01 0f 08 15 0e 13 15-66 66 0e 15 07 13 14 0e  ........ff......
0:000> .writemem C:\Users\Hamic\Desktop\sc.bin @ebp-205 @ebp
Writing 206 bytes.
```

成功透過`WinDbg` dump出來寫入的內容，並存成`sc.bin`，再透過 Binary Ninja 進行分析，直接打開會發現沒有funtion，需要手動將其設定為funtion才能進行分析

```
00000000    int32_t __convention("regparm") sub_0(int32_t arg1, int32_t arg2, int32_t arg3 @ edi)

00000008        char* esi = &data_21
0000000b        char* ecx = &data_1df
00000010        bool c_1
00000010        
00000010        while (true)
00000010            c_1 = ecx u< 0
00000010            
00000013            if (ecx == 0)
00000013                break
00000013            
00000015            *esi ^= 0x66
00000018            esi = &esi[1]
00000019            ecx -= 1
00000019        
00000031        int16_t cs
00000031        uint32_t var_8 = zx.d(cs)
00000032        int32_t temp2 = *0x150e6666
00000039        int32_t edx_1 = adc.d(adc.d(arg2, temp2, c_1), *(esi + ecx), 
00000039            adc.d(arg2, temp2, c_1) u< arg2 || (c_1 && adc.d(arg2, temp2, c_1) == arg2))
0000003c        *ecx |= ecx.b
0000003e        int16_t ss
0000003e        int16_t var_a = ss
00000040        int32_t eflags
00000040        __out_dx_oeax(edx_1.w, arg1, eflags)
00000041        *(esi + 0x66666666)
00000047        __in_oeax_dx(edx_1.w, eflags)
00000048        int32_t var_c = edx_1
0000004d        __out_dx_oeax(edx_1.w + 1, __in_oeax_immb(0xa0, eflags), eflags)
0000004f        __out_immb_oeax(0xa7, arg3, eflags)
00000051        undefined

```

分析後發現這裡在對`data_21`進行解密，將`data_21`的內容取出並與`0x66`做XOR，可以透過Binary Ninja 的 python 進行解密
```python
data = bytearray(bv.read(0, 0x201))  
  
for i in range(0x21, 0x21 + 0x1df):  
data[i] ^= 0x66  
  
open(r"C:\Users\Hamic\Desktop\sc_layer1.bin", "wb").write(data)
print(data[0x21:0x21+32])
  
```

繼續分析 `sc_layer1.bin`
```
00000008        char* esi = "and so it beginshus"
00000008        
00000013        for (int32_t i = 0x1df; i != 0; i -= 1)
00000015            *esi ^= 0x66
00000018            esi = &esi[1]
00000018        
0000003b        int32_t var_10
0000003b        __builtin_strncpy(dest: &var_10, src: "nopasaurus", count: 0xc)
00000040        int32_t* ebx = &var_10
00000042        void* const var_14 = &data_47
00000042        void* const* esp = &var_14
0000004a        char* esi_2 = var_14 + 0x2d  {"ginshus"}
0000004f        void* ecx_1 = &esi_2[0x18c]
00000057        int32_t var_8
00000057        void* result = &var_8:2
0000005c        bool o_1
0000005c        
0000005c        while (true)
0000005c            if (&var_8:2 == ebx)
00000060                ebx = &var_10
00000060            
00000063            o_1 = add_overflow(esi_2, neg.d(ecx_1))
00000063            
00000065            if (esi_2 == ecx_1)
00000065                break
00000065            
00000067            arg2.b = *ebx
00000069            *esi_2 ^= arg2.b
0000006b            ebx += 1
0000006c            esi_2 = &esi_2[1]
0000006c        
000000a6        int32_t eflags
000000a6        
❓️000000a6        while (true)
000000a6            uint16_t* esi_3 = __outsb(arg2.w, *esi_2, esi_2, eflags)
000000a7            esi_2 = __outsd(arg2.w, *esi_3, esi_3, eflags)
000000a7            
000000a8            if (o_1)
000000a8                break
000000a8            
000000ab            *(esp - 4) = arg3
000000ac            *(esp - 8) = ecx_1
000000ad            __int1()
000000ae            ebx.b = 0x6d
000000b0            result.b = *(ebx + result)
000000b1            *(esp - 0xc) = arg4
000000b1            
000000b2            if (not(o_1))
00000115                return result
00000115            
00000098            *(esp - 0x10) = arg3
🚫🚫00000099            ebx = sbb.d(ebx, *ebx, false)
00000099            bool c_1 = unimplemented  {sbb ebx, dword [ebx]}
0000009b            *(esp - 0x14) = ebx
0000009b            esp -= 0x14
🚫🚫0000009c            result.b = sbb.b(result.b, *arg4, c_1)
0000009c            bool c_2 = unimplemented  {sbb al, byte [edi]}
🚫🚫000000a3            result.b = sbb.b(adc.d(result, 0x1c000341, c_2).b, 1, 
000000a3                adc.d(result, 0x1c000341, c_2) u< result
000000a3                    || (c_2 && adc.d(result, 0x1c000341, c_2) == result))
000000a3            o_1 = unimplemented  {sbb al, 0x1}
000000a3        
0000010b        *0x3edfadca
00000110        int32_t eax_1 = __in_oeax_immb(0x6c, eflags)
00000113        *(arg3 + 0x15e59fc3)
00000113        *(arg3 + 0x15e59fc3) ^= eax_1
00000119        *esp
0000011a        eax_1.b = *(ebx + eax_1)
0000011c        *(esp + 2)
0000011d        arg2:1.b = 0x11
0000011f        *((arg3 << 1) + 0xd4fccd59) = sbb.b(*((arg3 << 1) + 0xd4fccd59), eax_1.b, false)
00000126        eax_1.b += 0x34
00000128        eax_1.b |= 0x20
0000012a        char temp1 = *esi_2
0000012a        *esi_2 += ebx:1.b
0000012c        int32_t eax_2 = adc.d(eax_1, 0x5f735e66, temp1 + ebx:1.b u< temp1)
00000131        arg4.w += 1
00000131        
00000137        if (arg2 + 1 s< 0)
0000012d            esi_2.w = esp[1].w
0000012d            
0000012f            if (*(ebx + 0x73) u>= eax_2)
0000012f                jump(0x190)
0000012f            
0000012f            jump(0x131)
0000012f        
00000139        if (arg2 + 1 s>= 0)
🚫🚫00000140            bool c_6 = unimplemented  {sbb eax, 0x1376187e}
00000140            
00000145            if (not(c_6))
00000145                jump(0x14d)
00000145            
00000145            jump(0x147)
00000145        
000001b5        int32_t esi_4 = esp[1]
000001b6        int32_t eflags_1
000001b6        char temp0_1
000001b6        temp0_1, eflags_1 = __das(eax_2.b, eflags)
000001b6        eax_2.b = temp0_1
000001b6        
000001b7        if (arg2 + 1 s>= 0)
000001b7            jump(0x14f)
000001b7        
000001b7        return sub_1b9(eax_2, arg3, esi_4) __tailcall

```

發現可疑程式，這段式將`nopasaurus`當key進行加密(重複 XOR)
```
0000003b        int32_t var_10
0000003b        __builtin_strncpy(dest: &var_10, src: "nopasaurus", count: 0xc)
00000040        int32_t* ebx = &var_10
00000042        void* const var_14 = &data_47
00000042        void* const* esp = &var_14
0000004a        char* esi_2 = var_14 + 0x2d  {"ginshus"}
0000004f        void* ecx_1 = &esi_2[0x18c]
00000057        int32_t var_8
00000057        void* result = &var_8:2
0000005c        bool o_1
0000005c        
0000005c        while (true)
0000005c            if (&var_8:2 == ebx)
00000060                ebx = &var_10
00000060            
00000063            o_1 = add_overflow(esi_2, neg.d(ecx_1))
00000063            
00000065            if (esi_2 == ecx_1)
00000065                break
00000065            
00000067            arg2.b = *ebx
00000069            *esi_2 ^= arg2.b
0000006b            ebx += 1
0000006c            esi_2 = &esi_2[1]
0000006c        
```

解密腳本
```python 
data = bytearray(bv.read(0, 0x201))  
  
key = b"nopasaurus"  
  
for j, i in enumerate(range(0x74, 0x74 + 0x18c)):  
	data[i] ^= key[j % len(key)]  
  
open(r"C:\Users\Hamic\Desktop\sc_layer2.bin", "wb").write(data)
```

繼續分析解出來的`sc_layer2.bin`
```
00000000    int32_t __convention("regparm") sub_0(int32_t arg1, uint16_t arg2)

00000008        char* esi = "and so it beginshus"
00000008        
00000013        for (int32_t i = 0x1df; i != 0; i -= 1)
00000015            *esi ^= 0x66
00000018            esi = &esi[1]
00000018        
0000003b        int32_t var_10
0000003b        __builtin_strncpy(dest: &var_10, src: "nopasaurus", count: 0xc)
00000040        int32_t* ebx = &var_10
0000004a        char* esi_2 = &data_47 + 0x2d  {"ginshus"}
0000005c        int32_t var_8
0000005c        
0000005c        while (true)
0000005c            if (&var_8:2 == ebx)
00000060                ebx = &var_10
00000060            
00000065            if (esi_2 == &esi_2[0x18c])
00000065                break
00000065            
00000067            arg2.b = *ebx
00000069            *esi_2 ^= arg2.b
0000006b            ebx += 1
0000006c            esi_2 = &esi_2[1]
0000006c        
000000ad        int32_t* esi_3 = &data_c8
000000ad        
000000b8        for (int32_t i_1 = 0x138; i_1 s> 0; i_1 -= 4)
000000ba            *esi_3 ^= 0x476c4f62
000000c0            esi_3 = &esi_3[1]
000000c0        
000000c8        int32_t eflags
000000c8        __out_dx_oeax(arg2, &var_8:2, eflags)
000000c9        undefined

```

加密程序如下，還可以查到`*esi_3 ^= 0x476c4f62`也就是`bOlG`
```
000000ad        int32_t* esi_3 = &data_c8
000000ad        
000000b8        for (int32_t i_1 = 0x138; i_1 s> 0; i_1 -= 4)
000000ba            *esi_3 ^= 0x476c4f62
000000c0            esi_3 = &esi_3[1]
000000c0        
   
```

解密程序
```python
data = bytearray(bv.read(0, 0x201))

key = b"bOlG"

for j, i in enumerate(range(0xc8, 0xc8 + 0x138)):  
	data[i] ^= key[j % len(key)]
	
open(r"C:\Users\Hamic\Desktop\sc_layer3.bin", "wb").write(data)
```

需要解密的片段，key是`omg is it almost over?!?`，一樣進行 XOR
```
000000f1        __builtin_strncpy(dest: &var_30, src: "omg is it almost over?!?", count: 0x18)
000000f6        int32_t* ebx_1 = &var_30
000000f8        void* const var_34 = &data_fd
00000100        char* esi_6 = var_34 + 0x2d  {"ginshus"}
00000105        void* ecx_3 = &esi_6[0xd6]
00000105        
00000112        while (true)
00000112            if (&var_18 == ebx_1)
00000116                ebx_1 = &var_30
00000116            
0000011b            if (esi_6 == ecx_3)
0000011b                break
0000011b            
0000011d            arg2.b = *ebx_1
0000011f            *esi_6 ^= arg2.b
00000121            ebx_1 += 1
00000122            esi_6 = &esi_6[1]
00000122        

```

解密腳本
```python
data = bytearray(bv.read(0, 0x201))

key = b"omg is it almost over?!?"

for j, i in enumerate(range(0x12a, 0x12a + 0xd6)):  
	data[i] ^= key[j % len(key)]
	
open(r"C:\Users\Hamic\Desktop\sc_layer4.bin", "wb").write(data)
```

解完後就找到`FLAG`
```
such.5h311010101@flare-on.com
```
