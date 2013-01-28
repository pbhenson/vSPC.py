#!/usr/bin/python -u

# Copyright 2011 Isilon Systems LLC. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY ISILON SYSTEMS LLC. ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those of the
# authors and should not be interpreted as representing official policies, either expressed
# or implied, of <copyright holder>.

"""
vSPC.py - A Virtual Serial Port Concentrator for VMware

Run 'vSPC.py -h' for full help.

This server is based on publicly available documentation:
  http://www.vmware.com/support/developer/vc-sdk/visdk41pubs/vsp41_usingproxy_virtual_serial_ports.pdf
"""

from __future__ import with_statement

__author__ = "Zachary M. Loafman"
__copyright__ = "Copyright (C) 2011 Isilon Systems LLC."
__revision__ = "$Id$"

import getopt
import fcntl
import logging
import os
import pickle
import select
import socket
import ssl
import struct
import sys
import termios
import threading
import time
import traceback
import Queue
from telnetlib import *
from telnetlib import IAC,DO,DONT,WILL,WONT,BINARY,ECHO,SGA,SB,SE,NOOPT,theNULL

from lib.poll import Poller, Selector
from lib.telnet import TelnetServer, VMTelnetServer, VMExtHandler, hexdump
from lib.backend import vSPCBackendMemory, vSPCBackendFile, vSPCBackendLogging
from lib.admin import AdminProtocolClient
from lib.server import vSPC

LISTEN_BACKLOG = 5

def get_backend_type(shortname):
    name = "vSPCBackend" + shortname
    if globals().has_key(name):
        backend_type = globals()[name]
    else:
        try:
            module = __import__(name)
        except ImportError:
            print "No builtin backend type %s found, no appropriate class " \
                "file found (looking for %s.py)" % (shortname, name)
            sys.exit(1)

        try:
            backend_type = getattr(module, name)
        except AttributeError:
            print "Backend module %s loaded, but class %s not found" % (name, name)
            sys.exit(1)

    return backend_type
