#!/usr/bin/env python
# vSPC/test.py -- functionality that's useful for testing parts of the
# project.

import logging
import socket
import sys
import termios
import time

from poll import Poller
from telnet import VMTelnetProxyClient
from util import prepare_terminal_with_flags, restore_terminal, string_dump, build_flags_ssh

CLIENT_ESCAPE_CHAR = chr(29)

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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, port))
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

        logging.debug("got data from proxy: %s\n", string_dump(s))

        if not s:
            # Could be option data, or something else that gets eaten by
            # a lower level layer.
            return

        # echo back to server
        self.send_buffered(self.tc, s)
        while s:
            c = s[:100]
            s = s[100:]
            self.destination.write(c)

        self.destination.flush()

    def new_client_data(self, client):
        data = client.read()
        if CLIENT_ESCAPE_CHAR in data:
            loc = data.index(CLIENT_ESCAPE_CHAR)
            pre_data = data[:loc]
            post_data = data[loc+1:]
            data = pre_data + self.process_escape_character() + post_data

        logging.debug("got client data %s, sending to proxy", string_dump(data))
        self.send_buffered(self.tc, data)

    def process_escape_character(self):
        self.restore_terminal()
        ret = ""
        self.destination.write("\n")
        while True:
            self.destination.write("vm> ")
            c = self.command_src.readline()
            if c == "":
                c = "quit"
            c = c.strip()
            if c == "quit" or c == "q":
                self.quit()
            elif c == "continue" or c == "" or c == "c":
                break
            elif c == "print-escape":
                ret = CLIENT_ESCAPE_CHAR
                break
            else:
                help = ("quit:          terminate the VM\n"
                        "continue:      exit this menu\n"
                        "print-escape:  send the escape sequence to the client\n")
                self.destination.write(help)
        self.prepare_terminal()
        return ret

    def send_buffered(self, conn, data = ''):
        logging.debug("sending data to proxy: %s", string_dump(data))
        if conn.send_buffered(data):
            self.add_writer(conn, self.send_buffered)
        else:
            self.del_writer(conn)

    def prepare_terminal(self):
        def flag_builder(newattr):
            newattr = build_flags_ssh(newattr)
            newattr[3] |= termios.ECHO
            return newattr

        (oldterm, oldflags) = prepare_terminal_with_flags(self.command_src, flag_builder)

        self.oldterm    = oldterm
        self.oldflags   = oldflags

    def restore_terminal(self):
        restore_terminal(self.command_src, self.oldterm, self.oldflags)

    def quit(self):
        self.restore_terminal()
        self.tc.close()
        sys.exit(0)
