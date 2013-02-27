# lib/util.py -- utility functions & classes

import fcntl
import os
import termios

def prepare_terminal(fd):
    """
    Prepare a terminal for interactive operation. Take a file
    descriptor-like object as an argument, return the original terminal
    state (oldterm & oldflags)
    """
    oldterm = termios.tcgetattr(fd)
    newattr = oldterm[:]
    # this is essentially cfmakeraw

    # input modes
    newattr[0] = newattr[0] & ~(termios.IGNBRK | termios.BRKINT | \
                                termios.PARMRK | termios.ISTRIP | \
                                termios.IGNCR | termios.ICRNL | \
                                termios.IXON)
    # output modes
    newattr[1] = newattr[1] & ~termios.OPOST
    # local modes
    newattr[3] = newattr[3] & ~(termios.ECHO | termios.ECHONL | \
                                termios.ICANON | termios.IEXTEN | termios.ISIG)
    # special characters
    newattr[2] = newattr[2] & ~(termios.CSIZE | termios.PARENB)
    newattr[2] = newattr[2] | termios.CS8

    termios.tcsetattr(fd, termios.TCSANOW, newattr)

    oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)

    return (oldterm, oldflags)

def restore_terminal(fd, oldterm, oldflags):
    termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
    fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)

def string_dump(s):
    """
    Translate a string into ASCII character codes & split with spaces.
    """
    return " ".join(map(lambda x: str(ord(x)), list(s)))
