#!/usr/bin/env python
# lib/test.py -- functionality that's useful for testing parts of the
# project.

import logging
import socket
import sys
import time

from poll import Poller
from telnet import VMTelnetProxyClient
from util import prepare_terminal, restore_terminal, string_dump

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

        self.prepare_terminal()
        self.add_reader(self.tc, self.new_proxy_data)
        self.add_reader(self.command_src, self.new_client_data)
        self.run_forever()

    def new_proxy_data(self, server):
        logging.debug("got new proxy data, processing")
        neg_done = False
        try:
            neg_done = server.negotiation_done()
        except (EOFError, IOError, socket.error):
            self.quit()
        if not neg_done:
            logging.debug("negotiation not yet done, skipping proxy data")
            return

        s = None
        try:
            s = server.read_very_lazy()
        except (EOFError, IOError, socket.error):
            self.quit()

        logging.debug("got data from proxy: %s\n" % string_dump(s))

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
        logging.debug("got client data %s, sending to proxy" % string_dump(data))
        self.send_buffered(self.tc, data)

    def send_buffered(self, conn, data = ''):
        logging.debug("sending data to proxy: %s" % string_dump(data))
        if conn.send_buffered(data):
            self.add_writer(conn, self.send_buffered)
        else:
            self.del_writer(conn)

    def prepare_terminal(self):
        (oldterm, oldflags) = prepare_terminal(self.command_src)

    def restore_terminal(self):
        restore_terminal(self.command_src, self.oldterm, self.oldflags)

    def quit(self):
        self.restore_terminal()
        self.tc.close()
        sys.exit(0)
