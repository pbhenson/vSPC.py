#!/usr/bin/python

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

import logging
import os
import pickle
import select
import socket
import ssl
import struct
import sys
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
Q_VERS = 1
Q_NAME = 'name'
Q_UUID = 'uuid'
Q_PORT = 'port'

# Persistence fields
P_UUID = 'uuid'
P_NAME = 'name'
P_PORT = 'port'

# How long to wait for an option response. Any option response resets
# the counter. This is mainly to deal with "raw" connections (like
# gdb) that don't negotiate telnet options at all.
UNACK_TIMEOUT=0.5

LISTEN_BACKLOG = 5

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
        (readers, writers, exceptions) = \
            select.select(self.read_handlers.keys(), [], [], timeout)
        for reader in readers:
            self.read_handlers[reader](reader)
        for writer in writers:
            self.write_handlers[writer](writer)

    def run_forever(self):
        while True:
            self.run_once()

class vSPCBackendMemory:
    ADMIN_THREADS = 4
    ADMIN_CONN_TIMEOUT = 0.2

    class OVm:
        def __init__(self, uuid = None, port = None, name = None):
            self.uuid = uuid
            self.port = port
            self.name = name

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

    def notify_vm_del(self, uuid):
        self.observer_queue.put(lambda: self.vm_del(uuid))

    def vm_del(self, uuid):
        with self.observed_vms_lock:
            if self.observed_vms.has_key(uuid):
                del self.observed_vms[uuid]

        self.hook_queue.put(lambda: self.vm_del_hook(uuid))

    def vm_del_hook(self, uuid):
        logging.debug("vm_del_hook: uuid: %s" % uuid)

    def notify_query_socket(self, sock):
        self.admin_queue.put(lambda: self.handle_query_socket(sock))

    def handle_query_socket(self, sock):
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
            if vers == 1:
                vms = self.get_observed_vms()

                l = []
                for vm in vms:
                    l.append({Q_NAME: vm.name, Q_UUID: vm.uuid, Q_PORT: vm.port})
                pickle.dump((vers, l), sockfile)
            else:
                pickle.dump(Exception('No common version'), sockfile)
            sockfile.flush()
        except Exception, e:
            logging.debug('handle_query_socket exception: %s' % str(e))

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

class vSPC(Selector, VMExtHandler):
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
        Selector.__init__(self)

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

    def send_buffered(self, ts, s = ''):
        if ts.send_buffered(s):
            self.add_writer(ts, self.send_buffered)
        else:
            self.del_writer(ts)

    def new_vm_connection(self, listener):
        sock = listener.accept()[0]
        sock.setblocking(0)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        vt = VMTelnetServer(sock, handler = self)
        self.add_reader(vt, self.new_vm_data)

    def new_client_connection(self, vm):
        sock = vm.listener.accept()[0]
        sock.setblocking(0)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        client = self.Client(sock)
        client.uuid = vm.uuid

        self.add_reader(client, self.new_client_data)
        vm.clients.append(client)

        logging.debug('uuid %s new client, %d active clients'
                      % (client.uuid, len(vm.clients)))

    def abort_vm_connection(self, vt):
        if vt.uuid:
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

        if not neg_done:
            return

        # Queue VM data during vmotion
        if vt.uuid and self.vms[vt.uuid].vmotion:
            return

        s = None
        try:
            s = vt.read_very_lazy()
        except (EOFError, IOError, socket.error):
            self.abort_vm_connection(vt)

        if not s: # May only be option data, or exception
            return

        if not vt.uuid or not self.vms.has_key(vt.uuid):
            # In limbo, no one can hear you scream
            return

        # logging.debug('new_vm_data %s: %s' % (vt.uuid, repr(s)))

        for cl in self.vms[vt.uuid].clients:
            try:
                self.send_buffered(cl, s)
            except (EOFError, IOError, socket.error), e:
                logging.debug('cl.socket send error: %s' % (str(e)))

    def abort_client_connection(self, client):
        logging.debug('uuid %s client socket closed, %d active clients' %
                      (client.uuid, len(self.vms[client.uuid].clients)-1))
        self.vms[client.uuid].clients.remove(client)
        self.stamp_orphan(self.vms[client.uuid])
        self.del_all(client)

    def new_client_data(self, client):
        neg_done = False
        try:
            neg_done = client.negotiation_done()
        except (EOFError, IOError, socket.error):
            self.abort_client_connection(client)

        if not neg_done:
            return

        # Queue VM data during vmotion
        if self.vms[client.uuid].vmotion:
            return

        s = None
        try:
            s = client.read_very_lazy()
        except (EOFError, IOError, socket.error):
            self.abort_client_connection(client)

        if not s: # May only be option data, or exception
            return

        # logging.debug('new_client_data %s: %s' % (client.uuid, repr(s)))

        for vt in self.vms[client.uuid].vts:
            try:
                self.send_buffered(vt, s)
            except (EOFError, IOError, socket.error), e:
                logging.debug('cl.socket send error: %s' % (str(e)))

    def new_vm(self, uuid, name, port = None, vts = None):
        vm = self.Vm(uuid = uuid, name = name, vts = vts)

        self.open_vm_port(vm, port)
        self.vms[uuid] = vm

        # Only notify if we generated the port
        if not port:
            self.backend.notify_vm(vm.uuid, vm.name, vm.port)

        logging.debug('%s:%s listening on port %d' % 
                      (vm.uuid, repr(vm.name), vm.port))

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

    def new_admin_connection(self, listener):
        sock = listener.accept()[0]
        self.collect_orphans()
        backend.notify_query_socket(sock)

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

            logging.debug('expired VM with uuid %s, port %d' 
                          % (uuid, vm.port))
            self.backend.notify_vm_del(vm.uuid)

            self.del_all(vm)
            del vm.listener
            self.vm_port_next = min(vm.port, self.vm_port_next)
            del self.ports[vm.port]
            del self.vms[uuid]
            if vm.vmotion:
                del self.vmotions[vm.vmotion]
                vm.vmotion = None
            del vm

    def open_vm_port(self, vm, port):
        self.collect_orphans()

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
        self.add_reader(vm, self.new_client_connection)

    def create_old_vms(self, vms):
        for vm in vms:
            self.new_vm(uuid = vm.uuid, name = vm.name, port = vm.port)

    def run(self):
        logging.info('Starting vSPC on proxy port %d, admin port %d, '
                     'allocating ports starting at %d' % 
                     (self.proxy_port, self.admin_port, self.vm_port_next))

        self.create_old_vms(self.backend.get_observed_vms())

        self.add_reader(openport(self.proxy_port), self.new_vm_connection)
        self.add_reader(openport(self.admin_port), self.new_admin_connection)
        self.run_forever()

def do_query(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    sockfile = s.makefile()

    # Trade versions
    pickle.dump(Q_VERS, sockfile)
    sockfile.flush()
    server_vers = pickle.load(sockfile)
    # Server chooses what we're doing

    resp = pickle.load(sockfile)
    if type(resp) == type(Exception()):
        sys.stderr.write("Server complained: %s\n", str(resp))
        sys.exit(3)

    (vers, data) = resp
    if vers == 1:
        for vm in data:
            print "%s:%s:%d" % (vm[Q_NAME], vm[Q_UUID], vm[Q_PORT])
    else:
        sys.stderr.write("Server sent us a version %d response, "
                         "which we don't understand. Bad!" % vers)
        sys.exit(4)

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
    [-f|--persist-file file]
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
    --no-fork: Don't daemonize
    -d|--debug: Debug mode (turns up logging and implies --stdout --no-fork)
''' % (BASENAME, __revision__, BASENAME, ADMIN_PORT, PROXY_PORT,
       VM_PORT_START, BASENAME, BASENAME, BASENAME,
       socket.gethostname(), PROXY_PORT,
       BASENAME, BASENAME, VM_EXPIRE_TIME, BASENAME, BASENAME, BASENAME,
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

    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], 'a:f:hdp:r:s',
                                       ['help', 'debug', 'admin-port=',
                                        'proxy-port=', 'port-range-start=',
                                        'server', 'stdout', 'no-fork',
                                        'vm-expire-time=',
                                        'backend=', 'backend-args=',
                                        'backend-help',
                                        'persist-file='])
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
            else:
                assert False, 'unhandled option'
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)

    if not server_mode:        
        if len(args) != 1:
            print "Expected 1 argument, found %d" % len(args)
            usage()
            sys.exit(2)

        sys.exit(do_query(args[0], admin_port))

    # Server mode

    if len(args) > 0:
        print "Unexpected arguments: %s" % args
        usage()
        sys.exit(2)

    backend = get_backend_type(backend_type_name)()
    backend.setup(backend_args)

    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    if syslog:
        from logging.handlers import SysLogHandler
        logger.addHandler(SysLogHandler(address='/dev/log'))

    if fork:
        daemonize()

    try:
        backend.start()

        vSPC(proxy_port, admin_port, vm_port_start, vm_expire_time, backend).run()
    except KeyboardInterrupt:
        logging.info("Shutdown requested on keyboard, exiting")
        sys.exit(0)
    except Exception, e:
        logging.exception("Top level exception caught")
        sys.exit(1)
