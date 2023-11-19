# vSPC/admin.py -- things related to the implementation of the admin query protocol

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

import pickle
import socket
import sys
import traceback

from telnetlib import BINARY, SGA

from vSPC.telnet import TelnetServer
from vSPC.poll import Poller
from vSPC.util import prepare_terminal, restore_terminal

# Query protocol
Q_VERS        = 4
Q_NAME        = 'name'
Q_UUID        = 'uuid'
Q_PORT        = 'port'
Q_UNSUPPORTED_CMD = 'cmd_not_supported'
Q_CMD_QUERY_VM = 'cmd_query_vm'
Q_CMD_CLEAR_PORT = 'cmd_clear_port'
Q_OK = 'ok'
Q_FAIL    = 'fail'
Q_VM_FOUND          = 'vm_found'
Q_VM_NOTFOUND = 'vm_not_found'
# Exclusive write and read access; no other clients have any access to the VM.
Q_LOCK_EXCL   = "exclusive"
# Exclusive write access; other clients can watch the session
Q_LOCK_WRITE  = "write"
# Nonexclusive write access; other clients may watch and interact with the VM.
Q_LOCK_FFA    = "free_for_all"
# Same as FFA, but with a fallback to read access if the VM is locked in
# nonexclusive mode.
Q_LOCK_FFAR   = "free_for_all_or_readonly"
Q_LOCK_BAD    = "lock_invalid"
Q_LOCK_FAILED = "lock_failed"

ALL_COMMANDS = {Q_CMD_QUERY_VM, Q_CMD_CLEAR_PORT}

CLIENT_ESCAPE_CHAR = chr(29)

class AdminProtocolClient(Poller):
    def __init__(self, host, admin_port, vm_name, port_to_clear, src, dst, lock_mode):
        Poller.__init__(self)
        self.admin_port = admin_port
        self.host       = host
        self.vm_name    = vm_name
        self.port_to_clear = port_to_clear
        # needed for the poller to work
        assert hasattr(src, "fileno")
        self.command_source = src
        self.destination    = dst
        self.lock_mode      = lock_mode

    class Client(TelnetServer):
        def __init__(self, sock,
                     server_opts = (BINARY, SGA),
                     client_opts = (BINARY, SGA)):
            TelnetServer.__init__(self, sock, server_opts, client_opts)
            self.uuid = None

    def do_vm_query(self, sock, sockfile, unpickler):
        pickle.dump(Q_CMD_QUERY_VM, sockfile)
        sockfile.flush()
        status = unpickler.load()
        if status != Q_OK:
            sys.stderr.write(f"Error. Asked server to do {Q_CMD_QUERY_VM}. "
                             f"Expected status of {Q_OK}. Got {status}\n")
            return False

        pickle.dump(self.vm_name, sockfile)
        pickle.dump(self.lock_mode, sockfile)
        sockfile.flush()
        status = unpickler.load()

        if status == Q_VM_NOTFOUND:
            if self.vm_name is not None:
                sys.stderr.write("The host '%s' couldn't find the vm '%s'. "
                                    "The host knows about the following VMs:\n" % (self.host, self.vm_name))
            vm_count = unpickler.load()
            vm_list = [ ]
            while vm_count > 0:
                vm_list.append(unpickler.load())
                vm_count -= 1
            self.process_noninteractive(vm_list)
            return False
        elif status == Q_LOCK_BAD:
            sys.stderr.write("The host doesn't understand how to give me a write lock\n")
            return False
        elif status == Q_LOCK_FAILED:
            sys.stderr.write("Someone else has a write lock on the VM\n")
            return False

        assert status == Q_VM_FOUND
        applied_lock_mode = unpickler.load()
        if applied_lock_mode == Q_LOCK_FFAR:
            self.destination.write("Someone else has an exclusive write lock; operating in read-only mode\n")
        seed_data = unpickler.load()

        for entry in seed_data:
            self.destination.write(entry)

        return sock

    def do_clear_port(self, sock, sockfile, unpickler):
        pickle.dump(Q_CMD_CLEAR_PORT, sockfile)
        sockfile.flush()
        status = unpickler.load()
        if status != Q_OK:
            sys.stderr.write(f"Error. Asked server to do {Q_CMD_CLEAR_PORT}. "
                             f"Expected status of {Q_OK}. Got {status}\n")
            return False
        pickle.dump(self.port_to_clear, sockfile)
        sockfile.flush()
        status = unpickler.load()
        if status != Q_OK:
            sys.stderr.write(f"{Q_CMD_CLEAR_PORT} failed (status {status})\n")
            return False
        else:
            sys.stderr.write(f"{Q_CMD_CLEAR_PORT} succeeded (status {status})\n")
            return True

    def run_cmd(self, cmd):
        if cmd not in ALL_COMMANDS:
            sys.stderr.write(f"{cmd} is not a supported command\n")
            return None

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.admin_port))
        sockfile = s.makefile("rwb")

        unpickler = pickle.Unpickler(sockfile)

        # trade protocol versions
        pickle.dump(Q_VERS, sockfile)
        sockfile.flush()
        server_vers = int(unpickler.load())
        if server_vers != 4:
            sys.stderr.write("Server sent us a version %d response, "
                             "which we don't understand. Bad!\n" % server_vers)
            return None

        if self.port_to_clear is not None:
            return self.do_clear_port(s, sockfile, unpickler)
        else:
            return self.do_vm_query(s, sockfile, unpickler)

    def new_client_data(self, listener):
        """
        I'm called when we have new data to send to the vSPC.
        """
        data = listener.read()
        if CLIENT_ESCAPE_CHAR in data:
            loc = data.index(CLIENT_ESCAPE_CHAR)
            pre_data = data[:loc]
            self.send_buffered(self.vspc_socket, pre_data.encode())
            post_data = data[loc+1:]
            data = self.process_escape_character() + post_data

        self.send_buffered(self.vspc_socket, data.encode())

    def send_buffered(self, ts, s = b''):
        if ts.send_buffered(s):
            self.add_writer(ts, self.send_buffered)
        else:
            self.del_writer(ts)

    def new_server_data(self, client):
        """
        I'm called when the AdminProtocolClient gets new data from the vSPC.
        """
        neg_done = False
        try:
            neg_done = client.negotiation_done()
        except (EOFError, IOError, socket.error):
            self.quit()

        if not neg_done:
            return

        s = None
        try:
            s = client.read_very_lazy()
        except (EOFError, IOError, socket.error):
            self.quit()
        if not s: # May only be option data, or exception
            return

        while s:
            c = s[:100]
            s = s[100:]
            self.destination.write(c.decode("utf-8", errors='replace'))

        self.destination.flush()

    def process_escape_character(self):
        self.restore_terminal()
        ret = ""
        # make sure the prompt shows up on its own line.
        self.destination.write("\n")
        while True:
            self.destination.write("vspc> ")
            c = self.command_source.readline()
            if c == "": # EOF
                c = "quit"
            c = c.strip()
            if c == "quit" or c == "q":
                self.quit()
            # treat enter/return as continue
            elif c == "continue" or c == "" or c == "c":
                break
            elif c == "print-escape":
                ret = CLIENT_ESCAPE_CHAR
                break
            else:
                help = ("quit:         exit the client\n"
                        "continue:     exit this menu\n"
                        "print-escape: send the escape sequence to the VM\n")
                self.destination.write(help)
        self.prepare_terminal()
        return ret

    def process_noninteractive(self, listing):
        if type(listing) == type(Exception()):
            sys.stderr.write("Server complained: %s\n" % str(listing))
            return

        assert isinstance(listing, list)
        # sort vms by name
        listing.sort(key=lambda x: x[Q_NAME])

        for vm in listing:
            out = "%s:%s" % (vm[Q_NAME], vm[Q_UUID])
            if vm[Q_PORT] is not None:
                out += ":%d" % vm[Q_PORT]
            self.destination.write(out)
            self.destination.write("\n")

    def prepare_terminal(self):
        (oldterm, oldflags) = prepare_terminal(self.command_source)
        self.oldterm = oldterm
        self.oldflags = oldflags

    def restore_terminal(self):
        restore_terminal(self.command_source, self.oldterm, self.oldflags)

    def quit(self):
        self.restore_terminal()
        self.destination.write("\n")
        self.vspc_socket.close()
        sys.exit(0)

    def run(self, cmd=Q_CMD_QUERY_VM):
        sock = self.run_cmd(cmd)
        if cmd == Q_CMD_QUERY_VM and isinstance(sock, socket.socket):
            try:
                s = self.Client(sock = sock)
                self.prepare_terminal()
                self.vspc_socket = s

                self.add_reader(self.vspc_socket, self.new_server_data)
                self.add_reader(self.command_source, self.new_client_data)
                self.run_forever()
            except (BrokenPipeError, ConnectionResetError):
                sys.stderr.write("Connection was closed!")
            except Exception as e:
                sys.stderr.write("".join(traceback.TracebackException.from_exception(e).format()))
            finally:
                self.quit()
