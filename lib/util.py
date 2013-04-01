# lib/util.py -- utility functions & classes

import fcntl
import os
import termios

def build_flags_ssh(oldterm):
    """
    Adapted from enter_raw_mode in sshtty.c in OpenSSH

    Maybe SSH's magical quality (or the fact that it works at all with
    my terminal emulator) will make my program work too.
    """
    oldterm[0] |= termios.IGNPAR
    oldterm[0] |= termios.ICRNL
    oldterm[0] &= ~(termios.ISTRIP | termios.INLCR | termios.IGNCR |\
                    termios.IXON | termios.IXANY |\
                    termios.IXOFF | termios.IUCLC)

    oldterm[3] &= ~(termios.ISIG | termios.ICANON | termios.ECHO |\
                    termios.ECHOE | termios.ECHOK | termios.ECHONL)
    oldterm[3] &= ~termios.IEXTEN

    oldterm[6][termios.VMIN] = 1
    oldterm[6][termios.VTIME] = 0

    return oldterm

def build_flags_cfmakeraw(oldterm):
    """
    Build termios settings based on our implementation of the cfmakeraw
    function.
    """
    # this is essentially cfmakeraw

    # input modes
    oldterm[0] = oldterm[0] & ~(termios.IGNBRK | termios.BRKINT | \
                                termios.PARMRK | termios.ISTRIP | \
                                termios.IGNCR | termios.ICRNL | \
                                termios.IXON)
    # output modes
    oldterm[1] = oldterm[1] & ~termios.OPOST

    # local modes
    oldterm[3] = oldterm[3] & ~(termios.ECHO | termios.ECHONL | \
                                termios.ICANON | termios.IEXTEN | termios.ISIG)
    # special characters
    oldterm[2] = oldterm[2] & ~(termios.CSIZE | termios.PARENB)
    oldterm[2] = oldterm[2] | termios.CS8

    return oldterm

def prepare_terminal(fd):
    """
    Prepare a terminal for interactive operation. Take a file
    descriptor-like object as an argument, return the original terminal
    state (oldterm & oldflags)
    """
    oldterm = termios.tcgetattr(fd.fileno())
    newattr = oldterm[:]

    newattr = build_flags_ssh(newattr)

    termios.tcsetattr(fd.fileno(), termios.TCSANOW, newattr)

    oldflags = fcntl.fcntl(fd.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(fd.fileno(), fcntl.F_SETFL, oldflags | os.O_NONBLOCK)

    return (oldterm, oldflags)

def restore_terminal(fd, oldterm, oldflags):
    termios.tcsetattr(fd.fileno(), termios.TCSAFLUSH, oldterm)
    fcntl.fcntl(fd.fileno(), fcntl.F_SETFL, oldflags)

def string_dump(s):
    """
    Translate a string into ASCII character codes & split with spaces.
    """
    return " ".join(map(lambda x: str(ord(x)), list(s)))
