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

BASENAME='vSPC.py'

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

# Default for --proxy-port, the port to send VMs to.
PROXY_PORT = 13370

# Default for --admin-port, the port to hit vSPC-query with
ADMIN_PORT = 13371

# Default for --port-range-start, start of port range to assign VMs.
# Ports may be reallocated within the range, based on active connections
# and --expire.
VM_PORT_START = 50000

# Default for --expire, number of seconds a VM (based on uuid) holds a
# port number / listener open with no VMware or client connections
VM_EXPIRE_TIME = 24*3600

# Query protocol
Q_VERS        = 2
Q_NAME        = 'name'
Q_UUID        = 'uuid'
Q_PORT        = 'port'
Q_OK          = 'vm_found'
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

# Persistence fields
P_UUID = 'uuid'
P_NAME = 'name'
P_PORT = 'port'

# How long to wait for an option response. Any option response resets
# the counter. This is mainly to deal with "raw" connections (like
# gdb) that don't negotiate telnet options at all.
UNACK_TIMEOUT=0.5

LISTEN_BACKLOG = 5

CLIENT_ESCAPE_CHAR = chr(29)

VMWARE_EXT = chr(232) # VMWARE-TELNET-EXT

KNOWN_SUBOPTIONS_1 = chr(0) # + suboptions
KNOWN_SUBOPTIONS_2 = chr(1) # + suboptions
UNKNOWN_SUBOPTION_RCVD_1 = chr(2) # + code
UNKNOWN_SUBOPTION_RCVD_2 = chr(3) # + code
VMOTION_BEGIN = chr(40) # + sequence
VMOTION_GOAHEAD = chr(41) # + sequence + secret
VMOTION_NOTNOW = chr(43) # + sequence + secret
VMOTION_PEER = chr(44) # + sequence + secret
VMOTION_PEER_OK = chr(45) # + sequence + secret
VMOTION_COMPLETE = chr(46) # + sequence
VMOTION_ABORT = chr(48) # <EOM> (?)
DO_PROXY = chr(70) # + [CS] + URI
WILL_PROXY = chr(71) # <EOM>
WONT_PROXY = chr(73) # <EOM>
VM_VC_UUID = chr(80) # + uuid
GET_VM_VC_UUID = chr(81) # <EOM>
VM_NAME = chr(82) # + name
GET_VM_NAME = chr(83) # <EOM>
VM_BIOS_UUID = chr(84) # + bios uuid
GET_VM_BIOS_UUID = chr(85) # <EOM>
VM_LOCATION_UUID = chr(86) # + location uuid
GET_VM_LOCATION_UUID = chr(87) # <EOM>

EXT_SUPPORTED = {
    KNOWN_SUBOPTIONS_1 : 'known_options', # VM->Proxy
    KNOWN_SUBOPTIONS_2 : 'known_options_resp', # Proxy->VM
    UNKNOWN_SUBOPTION_RCVD_1 : 'unknown_option', # VM->Proxy
    UNKNOWN_SUBOPTION_RCVD_2 : 'unknown_option_resp', # Proxy->VM
    VMOTION_BEGIN : 'vmotion_begin', # VM->Proxy
    VMOTION_GOAHEAD : 'vmotion_goahead', # Proxy->VM
    VMOTION_NOTNOW : 'vmotion_notnow', # Proxy->VM
    VMOTION_PEER : 'vmotion_peer', # VM (Peer)>Proxy
    VMOTION_PEER_OK : 'vmotion_peer_ok', # Proxy->VM (Peer)
    VMOTION_COMPLETE : 'vmotion_complete', # VM (Peer)->Proxy
    VMOTION_ABORT : 'vmotion_abort', # VM (original)->Proxy
    DO_PROXY : 'do_proxy', # VM->Proxy
    WILL_PROXY : 'do_proxy_will', # Proxy->VM
    WONT_PROXY : 'do_proxy_wont', # Proxy->VM
    VM_VC_UUID : 'vc_uuid', # VM->Proxy
    GET_VM_VC_UUID : 'get_vc_uuid', # Proxy->VM
    VM_NAME : 'vm_name', # VM->Proxy
    GET_VM_NAME : 'get_vm_name', # Proxy->VM
}

NOT_VMWARE = '''\
\r
You are trying to connect to the vSPC.py proxy port with a normal\r
telnet client. This port is intended for VMware connections only.\r
\r
'''

def hexdump(data):
    return reduce(lambda x,y: x + ('%x' % ord(y)), data, '')

class FixedTelnet(Telnet):
    '''
    FixedTelnet is a bug-fix override of the base Telnet class. In
    particular, base Telnet does not properly handle NULL characters,
    and in general is a little sloppy for BINARY mode.

    LICENSING: The code for this class was based on the base Telnet
    class definition from Python 2.6, and as such is covered by that
    GPLv2 compatible license:
    http://www.python.org/download/releases/2.6/license/
    '''
    def process_rawq(self):
        """Transfer from raw queue to cooked queue.

        Set self.eof when connection is closed.  Don't block unless in
        the midst of an IAC sequence.

        XXX - Sigh, this is a cut and paste from telnetlib to fix a
        bug in the processing of NULL suring an SB..SE sequence. -ZML
        """
        buf = ['', '']
        try:
            while self.rawq:
                c = self.rawq_getchar()
                if not self.iacseq:
                    if self.sb == 0 and c == theNULL:
                        continue
                    if self.sb == 0 and c == "\021":
                        continue
                    if c != IAC:
                        buf[self.sb] = buf[self.sb] + c
                        continue
                    else:
                        self.iacseq += c
                elif len(self.iacseq) == 1:
                    # 'IAC: IAC CMD [OPTION only for WILL/WONT/DO/DONT]'
                    if c in (DO, DONT, WILL, WONT):
                        self.iacseq += c
                        continue

                    self.iacseq = ''
                    if c == IAC:
                        buf[self.sb] = buf[self.sb] + c
                    else:
                        if c == SB: # SB ... SE start.
                            self.sb = 1
                            self.sbdataq = ''
                        elif c == SE:
                            self.sb = 0
                            self.sbdataq = self.sbdataq + buf[1]
                            buf[1] = ''
                        if self.option_callback:
                            # Callback is supposed to look into
                            # the sbdataq
                            self.option_callback(self.sock, c, NOOPT)
                        else:
                            # We can't offer automatic processing of
                            # suboptions. Alas, we should not get any
                            # unless we did a WILL/DO before.
                            self.msg('IAC %d not recognized' % ord(c))
                elif len(self.iacseq) == 2:
                    cmd = self.iacseq[1]
                    self.iacseq = ''
                    opt = c
                    if cmd in (DO, DONT):
                        self.msg('IAC %s %d',
                            cmd == DO and 'DO' or 'DONT', ord(opt))
                        if self.option_callback:
                            self.option_callback(self.sock, cmd, opt)
                        else:
                            self.sock.sendall(IAC + WONT + opt)
                    elif cmd in (WILL, WONT):
                        self.msg('IAC %s %d',
                            cmd == WILL and 'WILL' or 'WONT', ord(opt))
                        if self.option_callback:
                            self.option_callback(self.sock, cmd, opt)
                        else:
                            self.sock.sendall(IAC + DONT + opt)
        except EOFError: # raised by self.rawq_getchar()
            self.iacseq = '' # Reset on EOF
            self.sb = 0
            pass
        self.cookedq = self.cookedq + buf[0]
        self.sbdataq = self.sbdataq + buf[1]

class TelnetServer(FixedTelnet):
    def __init__(self, sock, server_opts = (), client_opts = ()):
        Telnet.__init__(self)
        self.set_option_negotiation_callback(self._option_callback)
        self.sock = sock
        self.server_opts = list(server_opts) # What do WE do?
        self.server_opts_accepted = list(server_opts)
        self.client_opts = list(client_opts) # What do THEY do?
        self.client_opts_accepted = list(client_opts)
        self.unacked = []
        self.last_ack = time.time()
        self.send_buffer = ''

        for opt in self.server_opts:
            logging.debug("sending WILL %d" % ord(opt))
            self._send_cmd(WILL + opt)
            self.unacked.append((WILL, opt))
        for opt in self.client_opts:
            logging.debug("sending DO %d" % ord(opt))
            self._send_cmd(DO + opt)
            self.unacked.append((DO, opt))

    def _send_cmd(self, s):
        self.sock.sendall(IAC + s)

    def _option_callback(self, sock, cmd, opt):
        if cmd in (DO, DONT):
            if opt not in self.server_opts:
                logging.debug("client wants us to %d, sending WONT" % ord(opt))
                self._send_cmd(WONT + opt)
                return

            msg_is_reply = False
            if (WILL, opt) in self.unacked:
                msg_is_reply = True
                self.last_ack = time.time()
                self.unacked.remove((WILL, opt))

            if cmd == DONT:
                logging.debug("client doesn't want us to %d" % ord(opt))
                try:
                    self.server_opts_accepted.remove(opt)
                except ValueError:
                    pass
            else:
                logging.debug("client says we should %d" % ord(opt))

            if not msg_is_reply:
                # Remind client that we want this option
                self._send_cmd(WILL + opt)
        elif cmd in (WILL, WONT):
            if opt not in self.client_opts:
                logging.debug("client wants to %d, sending DONT" % ord(opt))
                self._send_cmd(DONT + opt)
                return

            msg_is_reply = False
            if (DO, opt) in self.unacked:
                msg_is_reply = True
                self.last_ack = time.time()
                self.unacked.remove((DO, opt))

            if cmd == WONT:
                logging.debug("client won't %d" % ord(opt))
                try:
                    self.client_opts_accepted.remove(opt)
                except ValueError:
                    pass
            else:
                logging.debug("client will %d" % ord(opt))

            if not msg_is_reply:
                # Remind client that we want this option
                self._send_cmd(DO + opt)
        elif cmd == SB:
            pass # Don't log this, caller is processing
        else:
            logging.debug("cmd %d %s" % (ord(cmd), opt))

    def process_available(self):
        """Process all data, but don't take anything off the cooked queue.
        Do not block. Use for buffering data during options negotation.
        """
        self.process_rawq()
        while not self.eof and self.sock_avail():
            self.fill_rawq()
            self.process_rawq()

    def negotiation_done(self):
        self.process_available()
        if self.unacked:
            desc = map(lambda (x,y): (ord(x), ord(y)), self.unacked)
            if time.time() > self.last_ack + UNACK_TIMEOUT:
                logging.debug("timeout waiting for commands %s" % desc)
                self.unacked = []
            else:
                logging.debug("still waiting for %s" % desc)

        return not self.unacked

    def read_after_negotiate(self):
        if not self.negotiation_done():
            return ''
        return self.read_very_lazy()

    def send_buffered(self, s = ''):
        self.send_buffer += s
        nbytes = self.sock.send(self.send_buffer)
        self.send_buffer = self.send_buffer[nbytes:]
        return len(self.send_buffer) > 0

class VMExtHandler:
    def handle_vmotion_begin(self, ts, data):
        return False

    def handle_vmotion_peer(self, ts, data):
        return False

    def handle_vmotion_complete(self, ts):
        pass

    def handle_vmotion_abort(self, ts):
        pass

    def handle_vc_uuid(self, ts):
        pass

    def handle_vm_name(self, ts):
        pass

class VMTelnetServer(TelnetServer):
    def __init__(self, sock,
                 server_opts = (BINARY, SGA, ECHO),
                 client_opts = (BINARY, SGA, VMWARE_EXT),
                 handler = None):
        TelnetServer.__init__(self, sock, server_opts, client_opts)
        self.handler = handler or VMExtHandler()
        self.name = None
        self.uuid = None

    def _send_vmware(self, s):
        self.sock.sendall(IAC + SB + VMWARE_EXT + s + IAC + SE)

    def _handle_known_options(self, data):
        logging.debug("client knows VM commands: %s" % map(ord, data))

    def _handle_unknown_option(self, data):
        logging.debug("client doesn't know VM command %d, dropping" % hexdump(data))

    def _handle_do_proxy(self, data):
        dir = 'client' if data[:1] == "C" else 'server'
        uri = data[1:]
        logging.debug("client wants to proxy %s to %s" % (dir, uri))
        if dir == 'server' and uri == BASENAME:
            self._send_vmware(WILL_PROXY)
        else:
            self._send_vmware(WONT_PROXY)

    def _handle_vmotion_begin(self, data):
        cookie = data + struct.pack("i", hash(self) & 0xFFFFFFFF)

        if self.handler.handle_vmotion_begin(self, cookie):
            logging.debug("vMotion initiated: %s" % hexdump(cookie))
            self._send_vmware(VMOTION_GOAHEAD + cookie)
        else:
            logging.debug("vMotion denied: %s" % hexdump(cookie))
            self._send_vmware(VMOTION_NOTNOW + cookie)

    def _handle_vmotion_peer(self, cookie):
        if self.handler.handle_vmotion_peer(self, cookie):
            logging.debug("vMotion peer: %s" % hexdump(cookie))
            self._send_vmware(VMOTION_PEER_OK + cookie)
        else:
            # There's no clear spec on rejecting this
            logging.debug("vMotion peer rejected: %s" % hexdump(cookie))
            self._send_vmware(UNKNOWN_SUBOPTION_RCVD_2 + VMOTION_PEER)

    def _handle_vmotion_complete(self, data):
        self.handler.handle_vmotion_complete(self)

    def _handle_vmotion_abort(self, data):
        self.handler.handle_vmotion_abort(self)

    def _handle_vc_uuid(self, data):
        data = data.replace(' ', '')
        if not self.uuid:
            self.uuid = data
            self.handler.handle_vc_uuid(self)
        elif self.uuid != data:
            logging.warn("conflicting uuids? "
                         "old: %s, new: %s" % (self.uuid, data))
            self.close()

    def _handle_vm_name(self, data):
        self.name = data
        self.handler.handle_vm_name(self)

    def _send_vmware_initial(self):
        self._send_vmware(KNOWN_SUBOPTIONS_2 + \
                              reduce(lambda s,c: s+c,
                                     sorted(EXT_SUPPORTED.keys())))
        self._send_vmware(GET_VM_VC_UUID)
        self._send_vmware(GET_VM_NAME)

        self.unacked.append((VMWARE_EXT, KNOWN_SUBOPTIONS_1))
        self.unacked.append((VMWARE_EXT, VM_VC_UUID))
        self.unacked.append((VMWARE_EXT, VM_NAME))

    def _option_callback(self, sock, cmd, opt):
        if cmd == WILL and opt == VMWARE_EXT:
            self._send_vmware_initial()
            # Fall through so VMWARE_EXT will get removed from unacked
        elif cmd == WONT and opt == VMWARE_EXT:
            self.sock.sendall(NOT_VMWARE)
            self.close()

        if not cmd == SE or not self.sbdataq[:1] == VMWARE_EXT:
            TelnetServer._option_callback(self, sock, cmd, opt)
            return

        data = self.read_sb_data()
        subcmd = data[1:2]
        data = data[2:]

        handled = False
        if EXT_SUPPORTED.has_key(subcmd):
            meth = '_handle_%s' % EXT_SUPPORTED[subcmd]
            if hasattr(self, meth):
                getattr(self, meth)(data)
                handled = True
            if (VMWARE_EXT, subcmd) in self.unacked:
                self.unacked.remove((VMWARE_EXT, subcmd))

        if not handled:
            logging.debug('VMware command %d (data %s) not handled' \
                              % (ord(subcmd), hexdump(data)))
            self._send_vmware(UNKNOWN_SUBOPTION_RCVD_2 + subcmd)

def openport(port, use_ssl=False, ssl_cert=None, ssl_key=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if use_ssl:
        sock = ssl.wrap_socket(sock, keyfile=ssl_key, certfile=ssl_cert)
    sock.setblocking(0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
    sock.bind(("", port))
    sock.listen(LISTEN_BACKLOG)
    return sock

class Poller:
    def __init__(self):
        # stream => func
        self.read_handlers = {}
        self.write_handlers = {}

        # fileno => stream
        self.fds = {}
        # stream => epoll mask
        self.fd_mask = {}

        self.lock = threading.Lock()

        self.epoll = select.epoll()

    def add_stream(self, stream):
        # called with self.lock
        self.fds[stream.fileno()] = stream
        self.fd_mask[stream] = 0
        self.epoll.register(stream, self.fd_mask[stream])

    def add_reader(self, stream, func):
        with self.lock:
            if stream.fileno() not in self.fds:
                self.add_stream(stream)

            self.read_handlers[stream] = func

            assert stream in self.fd_mask
            self.fd_mask[stream] |= select.EPOLLIN

            self.epoll.modify(stream, self.fd_mask[stream])

    def del_reader(self, stream):
        with self.lock:
            try:
                self.fd_mask[stream] &= ~select.EPOLLIN
                self.epoll.modify(stream, self.fd_mask[stream])
            except KeyError:
                pass

    def add_writer(self, stream, func):
        with self.lock:
            if stream.fileno() not in self.fds:
                self.add_stream(stream)

            self.write_handlers[stream] = func

            assert stream in self.fd_mask
            self.fd_mask[stream] |= select.EPOLLOUT

            self.epoll.modify(stream, self.fd_mask[stream])

    def del_writer(self, stream):
        with self.lock:
            try:
                self.fd_mask[stream] &= ~select.EPOLLOUT
                self.epoll.modify(stream, self.fd_mask[stream])
            except KeyError:
                pass

    def del_all(self, stream):
        self.del_reader(stream)
        self.del_writer(stream)

    def remove_fd(self, fd):
        self.epoll.unregister(fd)
        del self.fds[fd.fileno()]
        del self.fd_mask[fd]

    def run_once(self, timeout = -1):
        try:
            events = self.epoll.poll(timeout)
        except IOError, e:
            # interrupted syscall
            return False
        for (fileno, event) in events:
            if event == select.EPOLLIN:
                # read event
                with self.lock:
                    fd = self.fds[fileno]
                    handler = self.read_handlers[fd]
                handler(fd)
            elif event == select.EPOLLOUT:
                # write event
                with self.lock:
                    fd = self.fds[fileno]
                    handler = self.write_handlers[fd]
                handler(fd)
            else:
                # Event that we don't know how to handle.
                logging.debug("I was asked to handle an unsupported event (%d) "
                              "for fd %d. I'm removing fd %d" % (event, fileno, fileno))
                with self.lock:
                    self.remove_fd(fd)

    def run_forever(self):
        while True:
            self.run_once()

class Selector:
    def __init__(self):
        self.read_handlers = {}
        self.write_handlers = {}

    def add_reader(self, stream, func):
        self.read_handlers[stream] = func

    def del_reader(self, stream):
        try:
            del self.read_handlers[stream]
        except KeyError:
            pass

    def add_writer(self, stream, func):
        self.write_handlers[stream] = func

    def del_writer(self, stream):
        try:
            del self.write_handlers[stream]
        except KeyError:
            pass

    def del_all(self, stream):
        self.del_reader(stream)
        self.del_writer(stream)

    def run_once(self, timeout = None):
        try:
            (readers, writers, exceptions) = \
                select.select(self.read_handlers.keys(), [], [], timeout)
        except select.error, e:
            # interrupted syscall
            return False
        for reader in readers:
            try:
                self.read_handlers[reader](reader)
            except KeyError:
                # deleted by the worker thread in vSPC
                pass
        for writer in writers:
            try:
                self.write_handlers[writer](writer)
            except KeyError:
                # deleted by the worker thread in vSPC
                pass

    def run_forever(self):
        while True:
            self.run_once(timeout=1.5)

class vSPCBackendMemory:
    ADMIN_THREADS = 4
    ADMIN_CONN_TIMEOUT = 0.2

    class OVm:
        def __init__(self, uuid = None, port = None, name = None):
            self.uuid = uuid
            self.port = port
            self.name = name

            self.modification_lock = threading.Lock()
            self.writers = []
            self.readers = []
            self.lockholder = None
            self.lock_mode = None
            self.lock = threading.Lock()

    def __init__(self):
        self.admin_queue = Queue.Queue()
        self.admin_threads = []

        self.observer_queue = Queue.Queue()
        self.observed_vms_lock = threading.Lock()
        self.observed_vms = {}
        self.observed_vms_loaded = False

        self.hook_queue = Queue.Queue()

    def setup(self, args):
        if args != '':
            print "%s takes no arguments" % str(self.__class__)
            sys.exit(1)

    def _start_thread(self, f):
        th = threading.Thread(target = f)
        th.daemon = True
        th.start()

        return th

    def start(self):
        for i in range(0, self.ADMIN_THREADS):
            self.admin_threads.append(self._start_thread(self.admin_run))

        self.observer_thread = self._start_thread(self.observer_run)
        self.hook_thread = self._start_thread(self.hook_run)

    def _queue_run(self, queue):
        while True:
            try:
                queue.get()()
            except Exception, e:
                logging.exception("Worker exception caught")

    def admin_run(self):
        self._queue_run(self.admin_queue)

    def observer_run(self):
        self._queue_run(self.observer_queue)

    def hook_run(self):
        self._queue_run(self.hook_queue)

    def load_vms(self):
        return {}

    def get_seed_data(self, uuid):
        """
        Return a list of things to give a newly connected client to seed
        their session with.
        """
        return []

    def get_observed_vms(self):
        if not self.observed_vms_loaded:
            vms = self.load_vms()
            with self.observed_vms_lock:
                if not self.observed_vms_loaded:
                    self.observed_vms = vms
                    self.observed_vms_loaded = True

        with self.observed_vms_lock:
            vms = self.observed_vms.copy()

        return vms.values()

    def notify_vm(self, uuid, name, port):
        self.observer_queue.put(lambda: self.vm(uuid, name, port))

    def vm(self, uuid, name, port):
        with self.observed_vms_lock:
            vm = self.observed_vms.setdefault(uuid, self.OVm())
            vm.uuid = uuid
            vm.name = name
            vm.port = port
            data = (vm.uuid, vm.name, vm.port)

        self.hook_queue.put(lambda: self.vm_hook(*data))

    def vm_hook(self, uuid, name, port):
        logging.debug("vm_hook: uuid: %s, name: %s, port: %s" %
                      (uuid, name, port))

    def notify_vm_msg(self, uuid, name, s):
        self.hook_queue.put(lambda: self.vm_msg_hook(uuid, name, s))

    def vm_msg_hook(self, uuid, name, s):
        logging.debug("vm_msg_hook: uuid: %s, name: %s, msg: %s" %
                      (uuid, name, s))

    def notify_client_del(self, sock, uuid):
        self.hook_queue.put(lambda: self.client_del(sock, uuid))

    def client_del(self, sock, uuid):
        logging.debug("client_del: uuid %s, client %s" % (uuid, sock))
        vm = None
        with self.observed_vms_lock:
            if uuid in self.observed_vms: vm = self.observed_vms[uuid]
        if vm is not None:
            with vm.modification_lock:
                self.maybe_unlock_vm(vm, sock)

    def notify_vm_del(self, uuid):
        self.observer_queue.put(lambda: self.vm_del(uuid))

    def vm_del(self, uuid):
        with self.observed_vms_lock:
            if self.observed_vms.has_key(uuid):
                del self.observed_vms[uuid]

        self.hook_queue.put(lambda: self.vm_del_hook(uuid))

    def vm_del_hook(self, uuid):
        logging.debug("vm_del_hook: uuid: %s" % uuid)

    def notify_query_socket(self, sock, vspc):
        self.admin_queue.put(lambda: self.handle_query_socket(sock, vspc))

    def handle_query_socket(self, sock, vspc):
        sock.settimeout(self.ADMIN_CONN_TIMEOUT)
        sockfile = sock.makefile()

        # Trade versions
        pickle.dump(Q_VERS, sockfile)
        sockfile.flush()

        try:
            client_vers = int(pickle.load(sockfile))
        except:
            try:
                pickle.dump(Exception("I don't understand"), sockfile)
                sockfile.flush()
            except:
                pass
            finally:
                return

        vers = min(Q_VERS, client_vers)
        logging.debug("version %d query", vers)

        try:
            if vers == 2:
                vm_name = pickle.load(sockfile)
                lock_mode = pickle.load(sockfile)
                vm = self.observed_vm_for_name(vm_name)

                if vm is not None and \
                   lock_mode in (Q_LOCK_EXCL, Q_LOCK_WRITE, Q_LOCK_FFA, Q_LOCK_FFAR):
                    status = Q_LOCK_FAILED
                    with vm.modification_lock:
                        lock_result = self.try_to_lock_vm(vm, sock, lock_mode)
                        if lock_result: status = Q_OK
                elif vm is None:
                    status = Q_VM_NOTFOUND
                else:
                    status = Q_LOCK_BAD
                pickle.dump(status, sockfile)

                if status == Q_OK:
                    pickle.dump(lock_result, sockfile)
                    pickle.dump(self.get_seed_data(vm.uuid), sockfile)
                    sockfile.flush()
                    readonly = False
                    if lock_result == Q_LOCK_FFAR:
                        readonly = True
                    vspc.queue_new_admin_client_connection(sock, vm.uuid, readonly)
                elif status == Q_VM_NOTFOUND:
                    pickle.dump(self.format_vm_listing(), sockfile)
                else: # unknown lock mode, or lock acquisition failed
                    pass
            elif vers == 1:
                pickle.dump((vers, self.format_vm_listing()), sockfile)
            else:
                pickle.dump(Exception('No common version'), sockfile)
            sockfile.flush()
        except Exception, e:
            logging.debug('handle_query_socket exception: %s' % str(e))

    def format_vm_listing(self):
        vms = self.get_observed_vms()

        l = []
        for vm in vms:
            l.append({Q_NAME: vm.name, Q_UUID: vm.uuid, Q_PORT: vm.port})
        return l

    def observed_vm_for_name(self, name):
        if name is None: return None

        vms = self.get_observed_vms()
        for vm in vms:
            if vm.name == name or vm.uuid == name:
                return vm
        return None

    def maybe_unlock_vm(self, vm, sock):
        """
        I determine whether a vm can be unlocked due to a client disconnecting.
        """
        if vm.lockholder is sock:
            vm.lockholder = None
            vm.lock.release()
        if sock in vm.writers:
            vm.writers.remove(sock)
        if sock in vm.readers:
            vm.readers.remove(sock)
        if not vm.writers:
            vm.lock_mode = None

    def try_to_lock_vm(self, vm, sock, lock_mode):
        """
        I try to acquire the requested locking mode on the given Vm. If I'm
        successful, I return True; otherwise, I return False.
        """
        logging.debug("Trying to lock vm %s for client" % vm.name)
        if lock_mode == Q_LOCK_EXCL:
            logging.debug("Exclusive lock mode selected")
            if vm.lock.acquire(False):
                logging.debug("Acquired exclusive lock")
                # got the lock; need to check for other readers and writers.
                if not vm.readers and not vm.writers:
                    logging.debug("No clients and no other writers; we're good")
                    vm.lockholder = sock
                    vm.lock_mode = lock_mode
                    vm.readers.append(sock)
                    vm.writers.append(sock)
                    return lock_mode
                else:
                    logging.debug("clients or writers; releasing lock")
                    vm.lock.release()

        elif lock_mode == Q_LOCK_WRITE:
            logging.debug("Write lock selected")
            if vm.lock.acquire(False):
                # got the lock; need to check for other writers
                logging.debug("Write lock acquired")
                if not vm.writers:
                    logging.debug("No other writers; we're good")
                    vm.lockholder = sock
                    vm.lock_mode = lock_mode
                    vm.readers.append(sock)
                    vm.writers.append(sock)
                    return lock_mode
                else:
                    logging.debug("Other writers, bail out")
                    vm.lock.release()

        elif lock_mode in (Q_LOCK_FFA, Q_LOCK_FFAR):
            logging.debug("free-for-all selected")
            if vm.lockholder is None:
                logging.debug("No one thinks they have exclusive write access, returning True")
                vm.lock_mode = Q_LOCK_FFA
                vm.writers.append(sock)
                vm.readers.append(sock)
                return Q_LOCK_FFA

            if vm.lock_mode is not Q_LOCK_EXCL and lock_mode == Q_LOCK_FFAR:
                logging.debug("VM has a write lock, adding as read-only")
                vm.readers.append(sock)
                return Q_LOCK_FFAR

        logging.debug("Lock acquisition failed, returning False")
        return False

class vSPCBackendFile(vSPCBackendMemory):
    def __init__(self):
        vSPCBackendMemory.__init__(self)

        self.shelf = None

    def usage(self):
        sys.stderr.write('''\
%s options: [-h|--help] -f|--file filename

  -h|--help: This message
  -f|--file: Where to persist VMs (required argument)
''' % str(self.__class__))

    def setup(self, args):
        import shlex
        import shelve

        fname = None

        try:
            opts, args = getopt.gnu_getopt(shlex.split(args), 'hf:', ['--help', '--file='])
            for o, a in opts:
                if o in ['-h', '--help']:
                    self.usage()
                    sys.exit(0)
                elif o in ['-f', '--file']:
                    fname = a
                else:
                    assert False, 'unhandled option'
        except getopt.GetoptError, err:
            print str(err)
            self.usage()
            sys.exit(2)

        if not fname:
            self.usage()
            sys.exit(2)

        self.shelf = shelve.open(fname)

    def vm_hook(self, uuid, name, port):
        self.shelf[uuid] = { P_UUID : uuid, P_NAME : name, P_PORT : port }

    def vm_del_hook(self, uuid):
        del self.shelf[uuid]

    def load_vms(self):
        vms = {}
        for v in self.shelf.values():
            vms[v[P_UUID]] = \
                self.OVm(uuid = v[P_UUID], name = v[P_NAME], port = v[P_PORT])

        return vms

class vSPC(Poller, VMExtHandler):
    class Vm:
        def __init__(self, uuid = None, name = None, vts = None):
            self.vts = vts if vts else []
            self.clients = []
            self.uuid = uuid
            self.name = name
            self.port = None
            self.listener = None
            self.last_time = None
            self.vmotion = None

        def fileno(self):
            return self.listener.fileno()

    class Client(TelnetServer):
        def __init__(self, sock,
                     server_opts = (BINARY, SGA, ECHO),
                     client_opts = (BINARY, SGA)):
            TelnetServer.__init__(self, sock, server_opts, client_opts)
            self.uuid = None

    def __init__(self, proxy_port, admin_port,
                 vm_port_start, vm_expire_time, backend, use_ssl=False,
                 ssl_cert=None, ssl_key=None):
        Poller.__init__(self)

        self.proxy_port = proxy_port
        self.admin_port = admin_port
        self.vm_port_next = vm_port_start
        self.vm_expire_time = vm_expire_time
        self.backend = backend

        self.orphans = []
        self.vms = {}
        self.ports = {}
        self.vmotions = {}
        self.do_ssl = use_ssl
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key

        self.task_queue = Queue.Queue()
        self.task_queue_threads = []

    def _queue_run(self, queue):
        while True:
            try:
                queue.get()()
            except Exception, e:
                logging.exception("Worker exception caught")

    def task_queue_run(self):
        self._queue_run(self.task_queue)

    def start(self):
        self.task_queue_threads.append(self._start_thread(self.task_queue_run))

    def _start_thread(self, f):
        th = threading.Thread(target = f)
        th.daemon = True
        th.start()

        return th

    def send_buffered(self, ts, s = ''):
        if ts.send_buffered(s):
            self.add_writer(ts, self.send_buffered)
        else:
            self.del_writer(ts)

    def new_vm_connection(self, sock):
        sock.setblocking(0)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        vt = VMTelnetServer(sock, handler = self)
        self.add_reader(vt, self.queue_new_vm_data)

    def queue_new_vm_connection(self, listener):
        sock = listener.accept()[0]
        self.task_queue.put(lambda: self.new_vm_connection(sock))

    def new_client_connection(self, sock, vm):
        sock.setblocking(0)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        client = self.Client(sock)
        client.uuid = vm.uuid

        self.add_reader(client, self.queue_new_client_data)
        vm.clients.append(client)

        logging.debug('uuid %s new client, %d active clients'
                      % (client.uuid, len(vm.clients)))

    def queue_new_client_connection(self, vm):
        sock = vm.listener.accept()[0]
        self.task_queue.put(lambda: self.new_client_connection(sock, vm))

    def abort_vm_connection(self, vt):
        if vt.uuid and vt in self.vms[vt.uuid].vts:
            logging.debug('uuid %s VM socket closed' % vt.uuid)
            self.vms[vt.uuid].vts.remove(vt)
            self.stamp_orphan(self.vms[vt.uuid])
        else:
            logging.debug('unidentified VM socket closed')
        self.del_all(vt)

    def new_vm_data(self, vt):
        neg_done = False
        try:
            neg_done = vt.negotiation_done()
        except (EOFError, IOError, socket.error):
            self.abort_vm_connection(vt)
            return

        if not neg_done:
            self.add_reader(vt, self.queue_new_vm_data)
            return

        # Queue VM data during vmotion
        if vt.uuid and self.vms[vt.uuid].vmotion:
            self.add_reader(vt, self.queue_new_vm_data)
            return

        s = None
        try:
            s = vt.read_very_lazy()
        except (EOFError, IOError, socket.error):
            self.abort_vm_connection(vt)
            return

        if not s: # May only be option data, or exception
            self.add_reader(vt, self.queue_new_vm_data)
            return

        if not vt.uuid or not self.vms.has_key(vt.uuid):
            # In limbo, no one can hear you scream
            self.add_reader(vt, self.queue_new_vm_data)
            return

        # logging.debug('new_vm_data %s: %s' % (vt.uuid, repr(s)))
        self.backend.notify_vm_msg(vt.uuid, vt.name, s)

        for cl in self.vms[vt.uuid].clients:
            try:
                self.send_buffered(cl, s)
            except (EOFError, IOError, socket.error), e:
                logging.debug('cl.socket send error: %s' % (str(e)))
        self.add_reader(vt, self.queue_new_vm_data)

    def queue_new_vm_data(self, vt):
        # Don't alert repeatedly on the same input
        self.del_reader(vt)
        self.task_queue.put(lambda: self.new_vm_data(vt))

    def abort_client_connection(self, client):
        logging.debug('uuid %s client socket closed, %d active clients' %
                      (client.uuid, len(self.vms[client.uuid].clients)-1))
        if client in self.vms[client.uuid].clients:
            self.vms[client.uuid].clients.remove(client)
            self.stamp_orphan(self.vms[client.uuid])
        self.del_all(client)
        self.backend.notify_client_del(client.sock, client.uuid)

    def new_client_data(self, client):
        neg_done = False
        try:
            neg_done = client.negotiation_done()
        except (EOFError, IOError, socket.error):
            self.abort_client_connection(client)
            return

        if not neg_done:
            self.add_reader(client, self.queue_new_client_data)
            return

        # Queue VM data during vmotion
        if self.vms[client.uuid].vmotion:
            self.add_reader(client, self.queue_new_client_data)
            return

        s = None
        try:
            s = client.read_very_lazy()
        except (EOFError, IOError, socket.error):
            self.abort_client_connection(client)
            return

        if not s: # May only be option data, or exception
            self.add_reader(client, self.queue_new_client_data)
            return

        # logging.debug('new_client_data %s: %s' % (client.uuid, repr(s)))

        for vt in self.vms[client.uuid].vts:
            try:
                self.send_buffered(vt, s)
            except (EOFError, IOError, socket.error), e:
                logging.debug('cl.socket send error: %s' % (str(e)))
        self.add_reader(client, self.queue_new_client_data)

    def queue_new_client_data(self, client):
        # Don't alert repeatedly on the same input
        self.del_reader(client)
        self.task_queue.put(lambda: self.new_client_data(client))

    def new_vm(self, uuid, name, port = None, vts = None):
        vm = self.Vm(uuid = uuid, name = name, vts = vts)

        self.open_vm_port(vm, port)
        self.vms[uuid] = vm

        # Only notify if we generated the port
        if not port:
            self.backend.notify_vm(vm.uuid, vm.name, vm.port)

        logging.debug('%s:%s connected' % (vm.uuid, repr(vm.name)))
        if vm.port is not None:
            logging.debug("listening on port %d" % vm.port)

        # The clock is always ticking
        self.stamp_orphan(vm)

        return vm

    def _add_vm_when_ready(self, vt):
        if not vt.name or not vt.uuid:
            return

        self.new_vm(vt.uuid, vt.name, vts = [vt])

    def handle_vc_uuid(self, vt):
        if not self.vms.has_key(vt.uuid):
            self._add_vm_when_ready(vt)
            return

        # This could be a reconnect, or it could be a vmotion
        # peer. Regardless, it's easy enough just to allow this
        # new vt to send to all clients, and all clients to
        # receive.
        vm = self.vms[vt.uuid]
        vm.vts.append(vt)

        logging.debug('uuid %s VM reconnect, %d active' %
                      (vm.uuid, len(vm.vts)))

    def handle_vm_name(self, vt):
        if not self.vms.has_key(vt.uuid):
            self._add_vm_when_ready(vt)
            return

        vm = self.vms[vt.uuid]
        if vt.name != vm.name:
            vm.name = vt.name
            self.backend.notify_vm(vm.uuid, vm.name, vm.port)

    def handle_vmotion_begin(self, vt, data):
        if not vt.uuid:
            # No Vm structure created yet
            return False

        vm = self.vms[vt.uuid]
        if vm.vmotion:
            return False

        vm.vmotion = data
        self.vmotions[data] = vt.uuid

        return True

    def handle_vmotion_peer(self, vt, data):
        if not self.vmotions.has_key(data):
            logging.debug('peer cookie %s doesn\'t exist' % hexdump(data))
            return False

        logging.debug('peer cookie %s maps to uuid %s' %
                      (hexdump(data), self.vmotions[data]))

        peer_uuid = self.vmotions[data]
        if vt.uuid:
            vm = self.vms[vt.uuid]
            if vm.uuid != peer_uuid:
                logging.debug('peer uuid %s != other uuid %s' % hexdump(data))
                return False
            return True # vt already in place
        else:
            # Act like we just learned the uuid
            vt.uuid = peer_uuid
            self.handle_vc_uuid(vt)

        return True

    def handle_vmotion_complete(self, vt):
        logging.debug('uuid %s vmotion complete' % vt.uuid)
        vm = self.vms[vt.uuid]
        del self.vmotions[vm.vmotion]
        vm.vmotion = None

    def handle_vmotion_abort(self, vt):
        logging.debug('uuid %s vmotion abort' % vt.uuid)
        vm = self.vms[vt.uuid]
        if vm.vmotion:
            del self.vmotions[vm.vmotion]
            vm.vmotion = None

    def check_orphan(self, vm):
        return len(vm.vts) == 0 and len(vm.clients) == 0

    def stamp_orphan(self, vm):
        if self.check_orphan(vm):
            self.orphans.append(vm.uuid)
            vm.last_time = time.time()

    def new_admin_connection(self, sock):
        self.collect_orphans()
        backend.notify_query_socket(sock, self)

    def queue_new_admin_connection(self, listener):
        sock = listener.accept()[0]
        self.task_queue.put(lambda: self.new_admin_connection(sock))

    def new_admin_client_connection(self, sock, uuid, readonly):
        client = self.Client(sock)
        client.uuid = uuid

        vm = self.vms[uuid]

        if not readonly:
            self.add_reader(client, self.queue_new_client_data)
        vm.clients.append(client)

        logging.debug('uuid %s new client, %d active clients'
                      % (client.uuid, len(vm.clients)))

    def queue_new_admin_client_connection(self, sock, uuid, readonly=False):
        self.task_queue.put(lambda: self.new_admin_client_connection(sock, uuid, readonly))

    def collect_orphans(self):
        t = time.time()

        orphans = self.orphans[:]
        for uuid in orphans:
            if not self.vms.has_key(uuid):
                self.orphans.remove(uuid)
                continue
            vm = self.vms[uuid]

            if not self.check_orphan(vm):
                self.orphans.remove(uuid) # Orphan no longer
                continue
            elif vm.last_time + self.vm_expire_time > t:
                continue

            logging.debug('expired VM with uuid %s' % uuid)
            if vm.port is not None:
                logging.debug(", port %d" % vm.port)
            self.backend.notify_vm_del(vm.uuid)

            self.del_all(vm)
            del vm.listener
            if self.vm_port_next is not None:
                self.vm_port_next = min(vm.port, self.vm_port_next)
                del self.ports[vm.port]
            del self.vms[uuid]
            if vm.vmotion:
                del self.vmotions[vm.vmotion]
                vm.vmotion = None
            del vm

    def open_vm_port(self, vm, port):
        self.collect_orphans()

        if self.vm_port_next is None:
            return

        if port:
            vm.port = port
        else:
            p = self.vm_port_next
            while self.ports.has_key(p):
                p += 1

            self.vm_port_next = p + 1
            vm.port = p

        assert not self.ports.has_key(vm.port)
        self.ports[vm.port] = vm.uuid

        vm.listener = openport(vm.port)
        self.add_reader(vm, self.queue_new_client_connection)

    def create_old_vms(self, vms):
        for vm in vms:
            self.new_vm(uuid = vm.uuid, name = vm.name, port = vm.port)

    def run(self):
        logging.info('Starting vSPC on proxy port %d, admin port %d' %
                     (self.proxy_port, self.admin_port))
        if self.vm_port_next is not None:
            logging.info("Allocating VM ports starting at %d" % self.vm_port_next)

        self.create_old_vms(self.backend.get_observed_vms())

        self.add_reader(openport(self.proxy_port, self.do_ssl, self.ssl_cert, self.ssl_key), self.queue_new_vm_connection)
        self.add_reader(openport(self.admin_port), self.queue_new_admin_connection)
        self.start()
        self.run_forever()

class AdminProtocolClient(Poller):
    def __init__(self, host, admin_port, vm_name, src, dst):
        Poller.__init__(self)
        self.admin_port = admin_port
        self.host       = host
        self.vm_name    = vm_name
        # needed for the selector to work
        assert hasattr(src, "fileno")
        self.command_source = src
        self.destination    = dst

    class Client(TelnetServer):
        def __init__(self, sock,
                     server_opts = (BINARY, SGA, ECHO),
                     client_opts = (BINARY, SGA)):
            TelnetServer.__init__(self, sock, server_opts, client_opts)
            self.uuid = None

    def connect_to_vspc(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.admin_port))
        sockfile = s.makefile()

        unpickler = pickle.Unpickler(sockfile)

        # trade protocol versions
        pickle.dump(Q_VERS, sockfile)
        sockfile.flush()
        server_vers = int(unpickler.load())
        if server_vers == 2:
            pickle.dump(self.vm_name, sockfile)
            pickle.dump(Q_LOCK_WRITE, sockfile)
            sockfile.flush()
            status = unpickler.load()
            if status == Q_VM_NOTFOUND:
                if self.vm_name is not None:
                    sys.stderr.write("The host '%s' couldn't find the vm '%s'. "
                                     "The host knows about the following VMs:\n" % (self.host, self.vm_name))
                vm_list = unpickler.load()
                self.process_noninteractive(vm_list)
                return None
            elif status == Q_LOCK_BAD:
                sys.stderr.write("The host doesn't understand how to give me a write lock\n")
                return None
            elif status == Q_LOCK_FAILED:
                sys.stderr.write("Someone else has a write lock on the VM\n")
                return None

            assert status == Q_OK
            applied_lock_mode = unpickler.load()
            if applied_lock_mode == Q_LOCK_FFAR:
                self.destination.write("Someone else has an exclusive write lock; operating in read-only mode\n")
            seed_data = unpickler.load()
            assert isinstance(seed_data, list)
            for entry in seed_data:
                self.destination.write(entry)

        elif server_vers == 1:
            vers, resp = unpickler.load()
            assert vers == server_vers
            self.process_noninteractive(resp)
            return None

        else:
            sys.stderr.write("Server sent us a version %d response, "
                             "which we don't understand. Bad!" % vers)
            return None

        # From this point on, we write data directly to s; the rest of
        # the protocol doesn't bother with pickle.
        client = self.Client(sock = s)
        return client

    def new_client_data(self, listener):
        """
        I'm called when we have new data to send to the vSPC.
        """
        data = listener.read()
        if CLIENT_ESCAPE_CHAR in data:
            loc = data.index(CLIENT_ESCAPE_CHAR)
            pre_data = data[:loc]
            self.send_buffered(self.vspc_socket, pre_data)
            post_data = data[loc+1:]
            data = self.process_escape_character() + post_data

        self.send_buffered(self.vspc_socket, data)

    def send_buffered(self, ts, s = ''):
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
            self.destination.write(c)

    def process_escape_character(self):
        self.restore_terminal()
        ret = ""
        while True:
            c = raw_input("vspc> ")
            if c == "quit":
                self.quit()
            elif c == "continue":
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

        for vm in listing:
            out = "%s:%s" % (vm[Q_NAME], vm[Q_UUID])
            if vm[Q_PORT] is not None:
                out += ":%d" % vm[Q_PORT]
            print out

    def prepare_terminal(self):
        fd = self.command_source
        self.oldterm = termios.tcgetattr(fd)
        newattr = self.oldterm[:]
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

        self.oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, self.oldflags | os.O_NONBLOCK)

    def restore_terminal(self):
        fd = self.command_source
        termios.tcsetattr(fd, termios.TCSAFLUSH, self.oldterm)
        fcntl.fcntl(fd, fcntl.F_SETFL, self.oldflags)

    def quit(self):
        self.restore_terminal()
        self.vspc_socket.close()
        sys.exit(0)

    def run(self):
        s = self.connect_to_vspc()
        if s is None:
            return

        try:
            self.prepare_terminal()
            self.vspc_socket = s

            self.add_reader(self.vspc_socket, self.new_server_data)
            self.add_reader(self.command_source, self.new_client_data)
            self.run_forever()
        except Exception, e:
            sys.stderr.write("Caught exception %s, closing" % e)
        finally:
            self.quit()

def do_query(host, port, vm_name=None):
    client = AdminProtocolClient(host, port, vm_name, sys.stdin, sys.stdout)
    client.run()

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

def daemonize():
    '''
    Daemonize, based on http://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
    '''

    pid = os.fork()
    if pid:
        os._exit(0) # Parent exits
    os.setsid() # Become session leader
    pid = os.fork() # Re-fork
    if pid:
        os._exit(0) # Child exits

    # We are daemonized grandchild, reset some process state
    os.chdir('/')
    os.umask(0)

def usage():
    sys.stderr.write('''\
%s (%s)

Common options:
%s: [-h|--help] [-d|--debug] [-a|--admin-port P] -s|--server|hostname

Query (without --server): Connect to the --admin-port (default %s) on
  the specified host and return a list of VMs. Output is colon
  delimited, vm-name:vm-uuid:port.

Server (with --server):
  Additional options:
    [-p|--proxy-port P] [-r|--port-range-start P] [--vm-expire-time seconds]
    [--backend Backend] [--backend-args 'arg string'] [--backend-help]
    [-f|--persist-file file] [--pidfile file]
    [--stdout] [--no-fork]

  Start Virtual Serial Port Concentrator. By default, vSPC listens on
  port %s for VMware virtual serial connections. Each new VM is
  assigned a listener, starting at port %s. VM to port mappings may be
  queried using %s without the --server option (e.g. '%s localhost').
  A standard 'telnet' may then be used to connect to the VM serial port.

  In order to configure a VM to use the vSPC, you must be running ESXi 4.1+.
  Add the serial port to the VM, then select:
    (*) Use Network
      (*) Server
      Port URI: %s
      [X] Use Virtual Serial Port Concentrator:
      vSPC: telnet://%s:%s
  NOTE: Direction MUST be Server, and Port URI MUST be %s

  Virtual serial ports support TLS/SSL on connections to a concentrator.
  To use TLS/SSL, configure the serial port as above, except for the
  vSPC URI field, which should say:
      vSPC URI: telnets://%s:%s
  then launch vSPC.py with the --ssl, --cert, and --key (if necessary)
  options.

  To have the process id of the server written to a file, use the
  --pidfile argument. This is useful for initscripts and other process
  management tools.

  %s makes a best effort to keep VM to port number mappings stable,
  based on the UUID of the connecting VM. Even if a VM disconnects,
  client connections are maintained in anticipation of the VM
  reconnecting (e.g. if the VM is rebooting). The UUID<->port mapping
  is maintained as long as there are either client connections or as
  long as the VM is connected, and even after this condition is no
  longer met, the mapping is retained for --vm-expire-time seconds
  (default %s).

  The backend of %s serves three major purposes: (a) On initial load,
  all port mappings are retrieved from the backend. The main thread
  maintains the port mappings after initial load, but the backend is
  responsible for setting the initial map. (This design was chosen to
  avoid blocking on the backend when a new VM connects.) (b) The
  backend serves all admin connections (because it has full knowledge
  of the mappings), (c) The backend can fire off customizable hooks as
  VMs come and go, allowing for persistence, or database tracking, or
  whatever.

  By default, %s uses the "Memory" backend, which really just
  means that no initial mappings are loaded on startup and all state
  is retained in memory alone. The other builtin backend is the "File"
  backend, which can be configured like so:
    --backend File --backend-args '-f /tmp/vSPC'.
  As a convenience, this same configuration can be accomplished using
  the top level parameter -f or --persist-file, i.e. '-f /tmp/vSPC' is
  synonymous with the previous set of arguments.

  If '--backend Foo' is given but no builtin backend Foo exists, %s
  tries to import module vSPCBackendFoo, looking for class vSPCBackendFoo.
  See --backend-help for programming details.

  Explanation of server options:
    -a|--admin-port: The port to listen/use for queries (default %s)
    -p|--proxy-port: The proxy port to listen on (default %s)
    -r|--port-range-start: What port to start port allocations from (default %s)
    --vm-expire-time: How long to wait before expiring a mapping with no connections
    -f|--persist-file: DBM file prefix to persist mappings to (.dat/.dir may follow)
    --backend: Name of custom backend class (see above)
    --backend-args: Arguments to custom backend
    --stdout: Log to stdout instead of syslog
    --ssl: Start SSL/TLS on connections to the proxy port
    --cert: The certificate or PEM file to use on the proxy port. Only meaningful with --ssl
    --key: The key, if necessary, to the certificate given by --cert. Only meaningful with --ssl
    --no-fork: Don't daemonize
    --pidfile: The file to write the process ID of the server to (no file by default)
    -d|--debug: Debug mode (turns up logging and implies --stdout --no-fork)
''' % (BASENAME, __revision__, BASENAME, ADMIN_PORT, PROXY_PORT,
       VM_PORT_START, BASENAME, BASENAME, BASENAME,
       socket.gethostname(), PROXY_PORT, BASENAME, socket.gethostname(), PROXY_PORT,
       BASENAME, VM_EXPIRE_TIME, BASENAME, BASENAME, BASENAME,
       ADMIN_PORT, PROXY_PORT, VM_PORT_START))

if __name__ == '__main__':
    import getopt

    proxy_port = PROXY_PORT
    admin_port = ADMIN_PORT
    vm_port_start = VM_PORT_START
    vm_expire_time = VM_EXPIRE_TIME
    debug = False
    syslog = True
    fork = True
    server_mode = False
    backend_type_name = 'Memory'
    backend_args = ''
    use_ssl = False
    ssl_cert = None
    ssl_key = None
    pidfile = None

    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], 'a:f:hdp:r:s',
                                       ['help', 'debug', 'admin-port=',
                                        'proxy-port=', 'port-range-start=',
                                        'server', 'stdout', 'no-fork', 'ssl',
                                        'vm-expire-time=', "cert=", "key=",
                                        'backend=', 'backend-args=',
                                        'backend-help', "no-vm-ports",
                                        'persist-file=', 'pidfile='])
        for o,a in opts:
            if o in ['-h', '--help']:
                usage()
                sys.exit(0)
            elif o in ['-d', '--debug']:
                debug = True
                syslog = False
                fork = False
            elif o in ['-a', '--admin-port']:
                admin_port = int(a)
            elif o in ['-p', '--proxy-port']:
                proxy_port = int(a)
            elif o in ['-r', '--port-range-start']:
                vm_port_start = int(a)
            elif o in ['-s', '--server']:
                server_mode = True
            elif o in ['--vm-expire-time']:
                vm_expire_time = int(a)
            elif o in ['--stdout']:
                syslog = False
            elif o in ['--no-fork']:
                fork = False
            elif o in ['--backend']:
                backend_type_name = a
            elif o in ['--backend-args']:
                backend_args = a
            elif o in ['--backend-help']:
                help(vSPCBackendMemory)
                sys.exit(0)
            elif o in ['-f', '--persist-file']:
                import pipes
                backend_type_name = 'File'
                backend_args = '-f %s' % pipes.quote(a)
            elif o in ['--ssl']:
                use_ssl = True
            elif o in ['--cert']:
                ssl_cert = a
            elif o in ['--key']:
                ssl_key = a
            elif o in ['--pidfile']:
                pidfile = a
            elif o in ['--no-vm-ports']:
                vm_port_start = None
            else:
                assert False, 'unhandled option'
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)

    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    if syslog:
        from logging.handlers import SysLogHandler
        from logging import Formatter
        formatter = Formatter(fmt="vSPC.py[%(process)d]: %(message)s")
        handler = SysLogHandler(address="/dev/log")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if not server_mode:
        if len(args) < 1 or len(args) > 2:
            print "Expected 1 or 2 arguments, found %d" % len(args)
            usage()
            sys.exit(2)

        vm_name = None
        if len(args) == 2:
            vm_name = args[1]

        sys.exit(do_query(args[0], admin_port, vm_name))

    # Server mode

    if len(args) > 0:
        print "Unexpected arguments: %s" % args
        usage()
        sys.exit(2)

    if use_ssl and not ssl_cert:
        print "Must specify certificate in order to use SSL"
        usage()
        sys.exit(2)

    backend = get_backend_type(backend_type_name)()
    backend.setup(backend_args)

    if fork:
        daemonize()
        if pidfile is not None:
            f = open(pidfile, "w")
            f.write("%d" % os.getpid())
            f.close()

    try:
        backend.start()

        vSPC(proxy_port, admin_port, vm_port_start, vm_expire_time, backend, use_ssl, ssl_cert, ssl_key).run()
    except KeyboardInterrupt:
        logging.info("Shutdown requested on keyboard, exiting")
        sys.exit(0)
    except Exception, e:
        logging.exception("Top level exception caught")
        sys.exit(1)
