# vSPC/telnet.py -- telnet code.

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

BASENAME = 'vSPC.py'

import logging
import struct
import time

from telnetlib import *
from telnetlib import IAC,DO,DONT,WILL,WONT,BINARY,ECHO,SGA,SB,SE,NOOPT,theNULL

# How long to wait for an option response. Any option response resets
# the counter. This is mainly to deal with "raw" connections (like
# gdb) that don't negotiate telnet options at all.
UNACK_TIMEOUT = 0.5

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
    return reduce(lambda x, y: x + ('%x' % ord(y)), data, '')

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
            logging.debug("sending WILL %d", ord(opt))
            self._send_cmd(WILL + opt)
            self.unacked.append((WILL, opt))
        for opt in self.client_opts:
            logging.debug("sending DO %d", ord(opt))
            self._send_cmd(DO + opt)
            self.unacked.append((DO, opt))

    def _send_cmd(self, s):
        self.sock.sendall(IAC + s)

    def _option_callback(self, sock, cmd, opt):
        if cmd in (DO, DONT):
            if opt not in self.server_opts:
                logging.debug("client wants us to %d, sending WONT", ord(opt))
                self._send_cmd(WONT + opt)
                return

            msg_is_reply = False
            if (WILL, opt) in self.unacked:
                msg_is_reply = True
                self.last_ack = time.time()
                self.unacked.remove((WILL, opt))

            if cmd == DONT:
                logging.debug("client doesn't want us to %d", ord(opt))
                try:
                    self.server_opts_accepted.remove(opt)
                except ValueError:
                    pass
            else:
                logging.debug("client says we should %d", ord(opt))

            if not msg_is_reply:
                # Remind client that we want this option
                self._send_cmd(WILL + opt)
        elif cmd in (WILL, WONT):
            if opt not in self.client_opts:
                logging.debug("client wants to %d, sending DONT", ord(opt))
                self._send_cmd(DONT + opt)
                return

            msg_is_reply = False
            if (DO, opt) in self.unacked:
                msg_is_reply = True
                self.last_ack = time.time()
                self.unacked.remove((DO, opt))

            if cmd == WONT:
                logging.debug("client won't %d", ord(opt))
                try:
                    self.client_opts_accepted.remove(opt)
                except ValueError:
                    pass
            else:
                logging.debug("client will %d", ord(opt))

            if not msg_is_reply:
                # Remind client that we want this option
                self._send_cmd(DO + opt)
        elif cmd == SB:
            pass # Don't log this, caller is processing
        else:
            logging.debug("cmd %d %s", ord(cmd), opt)

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
            desc = map(lambda (x, y): (ord(x), ord(y)), self.unacked)
            if time.time() > self.last_ack + UNACK_TIMEOUT:
                logging.debug("timeout waiting for commands %s", desc)
                self.unacked = []
            else:
                logging.debug("still waiting for %s", desc)

        return not self.unacked

    def read_after_negotiate(self):
        if not self.negotiation_done():
            return ''
        return self.read_very_lazy()

    def send_buffered(self, s = ''):
        self.send_buffer += s.replace(IAC, IAC+IAC)
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
        self.sock.sendall(IAC + SB + VMWARE_EXT + s.replace(IAC, IAC+IAC)
                          + IAC + SE)

    def _handle_known_options(self, data):
        logging.debug("client knows VM commands: %s", map(ord, data))

    def _handle_unknown_option(self, data):
        logging.debug("client doesn't know VM command %d, dropping",
                      hexdump(data))

    def _handle_do_proxy(self, data):
        dir = 'client' if data[:1] == "C" else 'server'
        uri = data[1:]
        logging.debug("client wants to proxy %s to %s", dir, uri)
        if dir == 'server' and uri == BASENAME:
            self._send_vmware(WILL_PROXY)
            logging.debug("direction and uri are correct, will proxy")
        else:
            self._send_vmware(WONT_PROXY)
            logging.error("client serial configuration incorrect (direction: "
                "%s, uri: %s), will not proxy for this VM", dir, uri)

    def _handle_vmotion_begin(self, data):
        cookie = data + struct.pack("I", hash(self) & 0xFFFFFFFF)

        if self.handler.handle_vmotion_begin(self, cookie):
            logging.debug("vMotion initiated: %s", hexdump(cookie))
            self._send_vmware(VMOTION_GOAHEAD + cookie)
        else:
            logging.debug("vMotion denied: %s", hexdump(cookie))
            self._send_vmware(VMOTION_NOTNOW + cookie)

    def _handle_vmotion_peer(self, cookie):
        if self.handler.handle_vmotion_peer(self, cookie):
            logging.debug("vMotion peer: %s", hexdump(cookie))
            self._send_vmware(VMOTION_PEER_OK + cookie)
        else:
            # There's no clear spec on rejecting this
            logging.debug("vMotion peer rejected: %s", hexdump(cookie))
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
                         "old: %s, new: %s", self.uuid, data)
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
            logging.debug('VMware command %d (data %s) not handled',
                          ord(subcmd), hexdump(data))
            self._send_vmware(UNKNOWN_SUBOPTION_RCVD_2 + subcmd)

class VMTelnetProxyClient(TelnetServer):
    def __init__(self, sock, vm_name, vm_uuid,
                 server_opts = (BINARY, SGA, VMWARE_EXT),
                 client_opts = (BINARY, SGA, ECHO)):
        self.vm_name = vm_name
        self.vm_uuid = vm_uuid

        TelnetServer.__init__(self, sock, server_opts, client_opts)

    def _send_vmware(self, s):
        self.sock.sendall(IAC + SB + VMWARE_EXT + s + IAC + SE)

    def _handle_known_options(self, data):
        logging.debug("client knows VM commands: %s", map(ord, data))

    def _handle_unknown_option(self, data):
        logging.debug("client doesn't know VM command %d, dropping", hexdump(data))

    def _handle_unknown_option_resp(self, data):
        logging.debug("client doesn't know VM command %s, dropping", hexdump(data))

    def _handle_get_vm_name(self, data):
        self._send_vmware(VM_NAME + self.vm_name)

    def _handle_get_vc_uuid(self, data):
        self._send_vmware(VM_VC_UUID + self.vm_uuid)

    def _handle_do_proxy_will(self, data):
        logging.debug("proxy will handle proxy request for vm %s (%s)",
                      self.vm_name, self.vm_uuid)

    def _handle_do_proxy_wont(self, data):
        logging.debug("proxy won't handle proxy request for vm %s (%s)",
                      self.vm_name, self.vm_uuid)
        # XXX: Consider more robust error handling here?
        self.close()

    def _send_do_proxy(self):
        # the server-side part of this only handles server proxy
        # requests, and requires that serviceURI be vSPC.py, so we need
        # to send 'S' and 'vSPC.py'.
        self._send_vmware(DO_PROXY + 'S' + 'vSPC.py')

    def _send_vmware_initial(self):
        # Send options
        self._send_vmware(KNOWN_SUBOPTIONS_1 + \
                              reduce(lambda s,c: s+c,
                                     sorted(EXT_SUPPORTED.keys())))

        # Send proxy request
        self._send_do_proxy()
        # expect other end to send us KNOWN_SUBOPTIONS_2
        self.unacked.append((VMWARE_EXT, KNOWN_SUBOPTIONS_2))

    def _option_callback(self, sock, cmd, opt):
        if cmd == DO and opt == VMWARE_EXT:
            self._send_vmware_initial()
            # Fall through so VMWARE_EXT will get removed from unacked
        elif cmd == DONT and opt == VMWARE_EXT:
            # Proxy doesn't want to talk to us anymore.
            # TODO: Error handling.
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
            logging.debug('VMware command %d (data %s) not handled',
                          ord(subcmd), hexdump(data))
            self._send_vmware(UNKNOWN_SUBOPTION_RCVD_2 + subcmd)

