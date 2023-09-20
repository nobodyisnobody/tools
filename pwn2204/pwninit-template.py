#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=-1', '--geometry=128x98+2900+0', '-e']
#context.terminal = ["tmux","neww"]
context.log_level = 'info'

{bindings}

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]
#onegadgets = one_gadget(libc.path, libc.address)

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)
def sl(line): return p.sendline(line)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)


rop = ROP(exe)

host, port = "127.0.0.1", "1337"

if args.REMOTE:
  p = remote(host,port)
else:
  if args.GDB:
    p = gdb.debug([exe.path], gdbscript = '''
#    source ~/gdb.plugins/pwndbg/gdbinit.py  # or use init-pwndbg with context.terminal tmux
#    init-pwndbg
    init-gef
    decompiler connect ida --host 127.0.0.1 --port 3662
    si
    c
     ''')
  else:
    p = process({proc_args})


p.interactive()

