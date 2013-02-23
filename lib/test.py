#!/usr/bin/env python
# lib/test.py -- functionality that's useful for testing parts of the
# project.

import socket
import sys
import time

from poll import Poller
from telnet import VMTelnetProxyClient

class FakeVMClient(Poller):
    def __init__(self, src, dst, vm_name, vm_uuid):
        Poller.__init__(self)
        assert hasattr(src, 'fileno')
        self.command_src    = src
        self.destination    = dst
        self.vm_name        = vm_name
        self.vm_uuid        = vm_uuid

    def connect(self, hostname, port):
        """
        Connect to vSPC instance on hostname:port, register as a VM,
        then prepare to relay traffic.
        """
        # steps:
        # - Establish socket connection to VM server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, port))
        # - Establish telnet client connection to vSPC server.
        self.tc = VMTelnetProxyClient(s, self.vm_name, self.vm_uuid)

        self.add_reader(self.tc, self.new_proxy_data)
        self.add_reader(self.command_src, self.new_client_data)
        self.run_forever()

    def new_proxy_data(self, server):
        print "in new proxy data"
        neg_done = False
        try:
            neg_done = server.negotiation_done()
        except (EOFError, IOError, socket.error):
            self.quit()
        if not neg_done:
            return

        print "reading data from client"

    def quit(self):
        self.tc.close()
        sys.exit(0)
