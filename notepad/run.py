#!/usr/bin/env python3
"""Script for hosting a binary on a port."""
import subprocess

PRELOAD = ""
LD = ""
BINARY = "./notepad"

PORT = 2222
PORT_DBG = 2223
PORT_DBG_GDB = 2224

def main():
    """Starts two socat instances for hosting the binary."""

    print("Staring binary <{}>.".format(BINARY))
    print("Use ^C for termination.")

    socat = "socat"

    socat_config = "tcp-l:{},fork,reuseaddr".format(PORT)
    socat_config_dbg = "tcp-l:{},fork,reuseaddr".format(PORT_DBG)

    if LD:
        socat_exec = './{} ./{}'.format(LD, BINARY)
        socat_exec_dbg = './{} ./{}'.format(LD, BINARY)
    else:
        socat_exec = './{}'.format(BINARY)
        socat_exec_dbg = './{}'.format(BINARY)

    if PRELOAD:
        socat_exec = 'EXEC:"stdbuf -o0 sh -c \\"LD_PRELOAD=./{} {}\\""'.format(PRELOAD, socat_exec)
        socat_exec_dbg = 'EXEC:"stdbuf -o0 gdbserver --wrapper env \'LD_PRELOAD=./{}\' -- :{} {}"'.format(PRELOAD, PORT_DBG_GDB, socat_exec_dbg)
    else:
        socat_exec = 'EXEC:"{}"'.format(socat_exec)
        socat_exec_dbg = 'EXEC:"gdbserver :{} {}"'.format(PORT_DBG_GDB, socat_exec_dbg)

    try:
        p_socat = subprocess.Popen([socat, socat_config, socat_exec])
        p_socat_dbg = subprocess.Popen([socat, socat_config_dbg, socat_exec_dbg])
        p_socat.wait()
        p_socat_dbg.wait()
    except KeyboardInterrupt:
        print("\nShutting down.")

if __name__ == '__main__':

    main()
