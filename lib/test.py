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

        s = None
        try:
            s = server.read_very_lazy()
        except (EOFError, IOError, socket.error):
            self.quit()

        if not s:
            # Could be option data, or something else that gets eaten by
            # a lower level layer.
            return

        while s:
            c = s[:100]
            s = s[100:]
            self.destination.write(c)

    def new_client_data(self, client):
        data = client.read()
        self.send_buffered(self.tc, data)

    def send_buffered(self, conn, data):
        if conn.send_buffered(data):
            self.add_writer(conn, self.send_buffered)
        else:
            self.del_writer(conn)

    def prepare_terminal(self):
        (oldterm, oldflags) = prepare_terminal(self.command_src)

    def restore_terminal(self):
        restore_terminal(self.command_src, self.oldterm, self.oldflags)

    def quit(self):
        self.tc.close()
        sys.exit(0)
