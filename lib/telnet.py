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

BASENAME = b'vSPC.py'

from copy import deepcopy
from collections.abc import Sequence
import logging
import struct
import time
import os
import functools

from telnetlib import *
from telnetlib import IAC,DO,DONT,WILL,WONT,BINARY,ECHO,SGA,SB,SE,NOOPT,theNULL


logger = logging.getLogger(__name__)


def bchr(v):
    return bytes([int(v)])

# How long to wait for an option response. Any option response resets
# the counter. This is mainly to deal with "raw" connections (like
# gdb) that don't negotiate telnet options at all.
UNACK_TIMEOUT = 0.5

VMWARE_EXT = bchr(232) # VMWARE-TELNET-EXT

KNOWN_SUBOPTIONS_1 = bchr(0) # + suboptions
KNOWN_SUBOPTIONS_2 = bchr(1) # + suboptions
UNKNOWN_SUBOPTION_RCVD_1 = bchr(2) # + code
UNKNOWN_SUBOPTION_RCVD_2 = bchr(3) # + code
VMOTION_BEGIN = bchr(40) # + sequence
VMOTION_GOAHEAD = bchr(41) # + sequence + secret
VMOTION_NOTNOW = bchr(43) # + sequence + secret
VMOTION_PEER = bchr(44) # + sequence + secret
VMOTION_PEER_OK = bchr(45) # + sequence + secret
VMOTION_COMPLETE = bchr(46) # + sequence
VMOTION_ABORT = bchr(48) # <EOM> (?)
DO_PROXY = bchr(70) # + [CS] + URI
WILL_PROXY = bchr(71) # <EOM>
WONT_PROXY = bchr(73) # <EOM>
VM_VC_UUID = bchr(80) # + uuid
GET_VM_VC_UUID = bchr(81) # <EOM>
VM_NAME = bchr(82) # + name
GET_VM_NAME = bchr(83) # <EOM>
VM_BIOS_UUID = bchr(84) # + bios uuid
GET_VM_BIOS_UUID = bchr(85) # <EOM>
VM_LOCATION_UUID = bchr(86) # + location uuid
GET_VM_LOCATION_UUID = bchr(87) # <EOM>

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

# used for logging
_PROTOCOL_CODE_TO_DEBUG_STR = deepcopy(EXT_SUPPORTED)
_PROTOCOL_CODE_TO_DEBUG_STR.update(
    {
        VM_BIOS_UUID: "vm_bios_uuid",
        GET_VM_BIOS_UUID: "get_vm_bios_uuid",
        VM_LOCATION_UUID: "vm_location_uuid",
        GET_VM_LOCATION_UUID: "get_vm_location_uuid",
        VMWARE_EXT: "VMWARE-TELNET-EXT",

        bchr(240): "SE",
        bchr(241): "NOP",
        bchr(250): "SB",
        bchr(251): "WILL",
        bchr(252): "WONT",
        bchr(253): "DO",
        bchr(254): "DONT",
        bchr(255): "IAC"
    }
)


NOT_VMWARE = '''\
\r
You are trying to connect to the vSPC.py proxy port with a normal\r
telnet client. This port is intended for VMware connections only.\r
\r
'''

def telnet_code_to_debug_str(data):
    """
    return telnet command data in human readable format (for logging)
    """
    if isinstance(data, bytes) and len(data) == 1:
        return _PROTOCOL_CODE_TO_DEBUG_STR.get(data, str(ord(data)))
    elif isinstance(data, int):
        return _PROTOCOL_CODE_TO_DEBUG_STR.get(bchr(data), str(data))
    elif isinstance(data, Sequence):
        return ", ".join(telnet_code_to_debug_str(d) for d in data)
    else:
        return str(data)


def hexdump(data):
    if isinstance(data, bytes):
        return functools.reduce(lambda x, y: x + ('%x' % y), data, '')
    else:
        return functools.reduce(lambda x, y: x + ('%x' % ord(y)), data, '')

class FixedTelnet(Telnet):
    '''
    FixedTelnet is a bug-fix override of the base Telnet class. In
    particular, base Telnet does not properly handle NULL characters,
    and in general is a little sloppy for BINARY mode.
    '''
    def _set_peer_name(self):
        """
        store socket peer name, for use in logs
        """
        try:
            self.peername = self.sock.getpeername()
        except Exception:
            logging.exception("could not get socket peer name")

    def __init__(self, *args, **kwargs):
        self.peername = None
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"{self.__class__.__name__}({self.host},{self.port})"

    def msg(self, msg, *args):
        """
        Telnet.msg uses print function for debug messages, override to use logger
        """
        if logger.isEnabledFor(logging.DEBUG):
            # avoid interpreting arguments unless necessary
            if args:
                formatted_args = msg % args
            else:
                formatted_args = msg
            logger.debug("%s: %s", str(self), formatted_args)

    def _send_cmd(self, s):
        cmd = IAC + s
        if logger.isEnabledFor(logging.DEBUG):
            peername_str = f" to {self.peername}" if self.peername else ""
            logger.debug("%s: sending cmd %s%s", str(self), cmd, peername_str)
        self.sock.sendall(cmd)

    def process_rawq(self):
        """Transfer from raw queue to cooked queue.

        Set self.eof when connection is closed.  Don't block unless in
        the midst of an IAC sequence.

        """
        buf = [b'', b'']
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

                    self.iacseq = b''
                    if c == IAC:
                        buf[self.sb] = buf[self.sb] + c
                    else:
                        if c == SB: # SB ... SE start.
                            self.sb = 1
                            self.sbdataq = b''
                        elif c == SE:
                            self.sb = 0
                            self.sbdataq = self.sbdataq + buf[1]
                            buf[1] = b''
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
                    cmd = self.iacseq[1:2]
                    self.iacseq = b''
                    opt = c
                    if cmd in (DO, DONT):
                        self.msg('IAC %s %d',
                            cmd == DO and 'DO' or 'DONT', ord(opt))
                        if self.option_callback:
                            self.option_callback(self.sock, cmd, opt)
                        else:
                            self._send_cmd(WONT + opt)
                    elif cmd in (WILL, WONT):
                        self.msg('IAC %s %d',
                            cmd == WILL and 'WILL' or 'WONT', ord(opt))
                        if self.option_callback:
                            self.option_callback(self.sock, cmd, opt)
                        else:
                            self._send_cmd(DONT + opt)
        except EOFError: # raised by self.rawq_getchar()
            self.iacseq = b'' # Reset on EOF
            self.sb = 0
            pass
        self.cookedq = self.cookedq + buf[0]
        self.sbdataq = self.sbdataq + buf[1]

class TelnetServer(FixedTelnet):
    def __init__(self, sock, server_opts = (), client_opts = ()):
        super().__init__()
        self.set_option_negotiation_callback(self._option_callback)
        self.sock = sock
        self._set_peer_name()
        self.server_opts = list(server_opts) # What do WE do?
        self.server_opts_accepted = list(server_opts)
        self.client_opts = list(client_opts) # What do THEY do?
        self.client_opts_accepted = list(client_opts)
        self.unacked = []
        self.last_ack = time.time()
        self.send_buffer = b''

        for opt in self.server_opts:
            logger.debug("sending WILL %s", telnet_code_to_debug_str(opt))
            self._send_cmd(WILL + opt)
            self.unacked.append((WILL, opt))
        for opt in self.client_opts:
            logger.debug("sending DO %s", telnet_code_to_debug_str(opt))
            self._send_cmd(DO + opt)
            self.unacked.append((DO, opt))

    def _option_callback(self, sock, cmd, opt):
        if cmd in (DO, DONT):
            if opt not in self.server_opts:
                logger.debug("client wants us to %s, sending WONT",
                             telnet_code_to_debug_str(opt))
                self._send_cmd(WONT + opt)
                return

            msg_is_reply = False
            if (WILL, opt) in self.unacked:
                msg_is_reply = True
                self.last_ack = time.time()
                self.unacked.remove((WILL, opt))

            if cmd == DONT:
                logger.debug("client doesn't want us to %s",
                             telnet_code_to_debug_str(opt))
                try:
                    self.server_opts_accepted.remove(opt)
                except ValueError:
                    pass
            else:
                logger.debug("client says we should %s",
                             telnet_code_to_debug_str(opt))

            if not msg_is_reply:
                # Remind client that we want this option
                self._send_cmd(WILL + opt)
        elif cmd in (WILL, WONT):
            if opt not in self.client_opts:
                logger.debug("client wants to %s, sending DONT",
                             telnet_code_to_debug_str(opt))
                self._send_cmd(DONT + opt)
                return

            msg_is_reply = False
            if (DO, opt) in self.unacked:
                msg_is_reply = True
                self.last_ack = time.time()
                self.unacked.remove((DO, opt))

            if cmd == WONT:
                logger.debug("client won't %s", telnet_code_to_debug_str(opt))
                try:
                    self.client_opts_accepted.remove(opt)
                except ValueError:
                    pass
            else:
                logger.debug("client will %s", telnet_code_to_debug_str(opt))

            if not msg_is_reply:
                # Remind client that we want this option
                self._send_cmd(DO + opt)
        elif cmd == SB:
            pass # Don't log this, caller is processing
        else:
            logger.debug(
                "cmd %s %s",
                telnet_code_to_debug_str(cmd),
                telnet_code_to_debug_str(opt)
            )

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
            desc = map(telnet_code_to_debug_str, self.unacked)
            if time.time() > self.last_ack + UNACK_TIMEOUT:
                if logger.isEnabledFor(logging.DEBUG):
                    # use list to evaluate the map, otherwise its
                    # printed as <map object at 0x...>
                    logger.debug("timeout waiting for commands %s", list(desc))
                self.unacked = []
            else:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("still waiting for %s", list(desc))

        return not self.unacked

    def read_after_negotiate(self):
        if not self.negotiation_done():
            return ''
        return self.read_very_lazy()

    def send_buffered(self, s = b''):
        self.send_buffer += s.replace(IAC, IAC+IAC)
        nbytes = self.sock.send(self.send_buffer)
        if logger.isEnabledFor(logging.DEBUG):
            peername_str = f" to {self.peername}" if self.peername else ""
            logger.debug(
                "%s: sent first %d bytes of %s%s",
                str(self),
                nbytes,
                self.send_buffer,
                peername_str,
            )
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
        self.name = None
        self.uuid = None
        TelnetServer.__init__(self, sock, server_opts, client_opts)
        self.handler = handler or VMExtHandler()

    def __str__(self):
        if self.name is None:
            return f"{self.__class__.__name__}(name not set)"
        return f"{self.__class__.__name__}({self.name})"

    def _send_vmware(self, s):
        self._send_cmd(SB + VMWARE_EXT + s.replace(IAC, IAC+IAC) + IAC + SE)

    def _handle_known_options(self, data):
        logger.debug("client knows VM commands: %s",
                     telnet_code_to_debug_str(data))

    def _handle_unknown_option(self, data):
        logger.debug("client doesn't know VM command %s, dropping",
                      telnet_code_to_debug_str(data))

    def _handle_do_proxy(self, data):
        dir = 'client' if data[:1] == "C" else 'server'
        uri = data[1:]
        logger.debug("client wants to proxy %s to %s", dir, uri)
        if dir == 'server' and uri == BASENAME:
            self._send_vmware(WILL_PROXY)
            logger.debug("direction and uri are correct, will proxy")
        else:
            self._send_vmware(WONT_PROXY)
            logger.error("client serial configuration incorrect (direction: "
                "%s, uri: %s), will not proxy for this VM", dir, uri)

    def _handle_vmotion_begin(self, data):
        cookie = data + os.urandom(4)

        if self.handler.handle_vmotion_begin(self, cookie):
            logger.debug("vMotion initiated: %s", cookie.hex())
            self._send_vmware(VMOTION_GOAHEAD + cookie)
        else:
            logger.debug("vMotion denied: %s", cookie.hex())
            self._send_vmware(VMOTION_NOTNOW + cookie)

    def _handle_vmotion_peer(self, cookie):
        if self.handler.handle_vmotion_peer(self, cookie):
            logger.debug("vMotion peer: %s", cookie.hex())
            self._send_vmware(VMOTION_PEER_OK + cookie)
        else:
            # There's no clear spec on rejecting this
            logger.debug("vMotion peer rejected: %s", cookie.hex())
            self._send_vmware(UNKNOWN_SUBOPTION_RCVD_2 + VMOTION_PEER)

    def _handle_vmotion_complete(self, data):
        self.handler.handle_vmotion_complete(self)

    def _handle_vmotion_abort(self, data):
        self.handler.handle_vmotion_abort(self)

    def _handle_vc_uuid(self, data):
        data = data.decode("utf-8", errors='replace')
        data = data.replace(' ', '')
        if not self.uuid:
            self.uuid = data
            self.handler.handle_vc_uuid(self)
        elif self.uuid != data:
            logger.warn("conflicting uuids? "
                         "old: %s, new: %s", self.uuid, data)
            self.close()

    def _handle_vm_name(self, data):
        self.name = data.decode('utf-8', errors='replace')
        self.handler.handle_vm_name(self)

    def _send_vmware_initial(self):
        self._send_vmware(KNOWN_SUBOPTIONS_2 + \
                              functools.reduce(lambda s,c: s+c,
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
            logger.debug("peer is not using vmware extension protocol. closing")
            self.sock.sendall(NOT_VMWARE.encode("utf-8"))
            self.close()

        if not cmd == SE or not self.sbdataq[:1] == VMWARE_EXT:
            TelnetServer._option_callback(self, sock, cmd, opt)
            return

        data = self.read_sb_data()
        subcmd = data[1:2]
        data = data[2:]

        handled = False
        if subcmd in EXT_SUPPORTED:
            meth = '_handle_%s' % EXT_SUPPORTED[subcmd]
            if hasattr(self, meth):
                getattr(self, meth)(data)
                handled = True
            if (VMWARE_EXT, subcmd) in self.unacked:
                self.unacked.remove((VMWARE_EXT, subcmd))

        if not handled:
            logger.debug('VMware command %s (data %s) not handled',
                         telnet_code_to_debug_str(subcmd),
                         telnet_code_to_debug_str(data))
            self._send_vmware(UNKNOWN_SUBOPTION_RCVD_2 + subcmd)

class VMTelnetProxyClient(TelnetServer):
    def __init__(self, sock, vm_name, vm_uuid,
                 server_opts = (BINARY, SGA, VMWARE_EXT),
                 client_opts = (BINARY, SGA, ECHO)):
        self.vm_name = vm_name
        self.vm_uuid = vm_uuid

        TelnetServer.__init__(self, sock, server_opts, client_opts)

    def __str__(self):
        return f"{self.__class__.__name__}({self.vm_name})"

    def _send_vmware(self, s):
        self._send_cmd(SB + VMWARE_EXT + s + IAC + SE)

    def _handle_known_options(self, data):
        logger.debug("client knows VM commands: %s",
                     telnet_code_to_debug_str(data))

    def _handle_unknown_option(self, data):
        logger.debug("client doesn't know VM command %s, dropping",
                     telnet_code_to_debug_str(data))

    def _handle_unknown_option_resp(self, data):
        logger.debug("client doesn't know VM command %s, dropping", 
                     telnet_code_to_debug_str(data))

    def _handle_get_vm_name(self, data):
        self._send_vmware(VM_NAME + self.vm_name.encode("utf-8"))

    def _handle_get_vc_uuid(self, data):
        self._send_vmware(VM_VC_UUID + self.vm_uuid.encode("utf-8"))

    def _handle_do_proxy_will(self, data):
        logger.debug("proxy will handle proxy request for vm %s (%s)",
                      self.vm_name, self.vm_uuid)

    def _handle_do_proxy_wont(self, data):
        logger.debug("proxy won't handle proxy request for vm %s (%s)",
                      self.vm_name, self.vm_uuid)
        # XXX: Consider more robust error handling here?
        self.close()

    def _send_do_proxy(self):
        # the server-side part of this only handles server proxy
        # requests, and requires that serviceURI be vSPC.py, so we need
        # to send 'S' and 'vSPC.py'.
        cmd = DO_PROXY + "S".encode("utf-8") + "vSPC.py".encode("utf-8")
        self._send_vmware(cmd)

    def _send_vmware_initial(self):
        # Send options
        self._send_vmware(KNOWN_SUBOPTIONS_1 + \
                              functools.reduce(lambda s,c: s+c,
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
        if subcmd in EXT_SUPPORTED:
            meth = '_handle_%s' % EXT_SUPPORTED[subcmd]
            if hasattr(self, meth):
                getattr(self, meth)(data)
                handled = True
            if (VMWARE_EXT, subcmd) in self.unacked:
                self.unacked.remove((VMWARE_EXT, subcmd))

        if not handled:
            logger.debug('VMware command %s (data %s) not handled',
                         telnet_code_to_debug_str(subcmd),
                         telnet_code_to_debug_str(data))
            self._send_vmware(UNKNOWN_SUBOPTION_RCVD_2 + subcmd)
