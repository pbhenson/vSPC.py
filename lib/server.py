# vSPC/server.py -- vSPC server implementation
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
from __future__ import with_statement

__author__ = "Zachary M. Loafman"
__copyright__ = "Copyright (C) 2011 Isilon Systems LLC."
__revision__ = "$Id$"

import logging
import resource
import socket
import ssl
import time
import threading
import queue

from telnetlib import BINARY, SGA, ECHO

from vSPC.poll import Poller
from vSPC.telnet import TelnetServer, VMTelnetServer, VMExtHandler, hexdump
from vSPC import settings

LISTEN_BACKLOG = 128 # match the default SOMAXCONN value to max performance

def openport(port, iface="", use_ssl=False, ssl_cert=None, ssl_key=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if use_ssl:
        sock = ssl.wrap_socket(sock, keyfile=ssl_key, certfile=ssl_cert)
    sock.setblocking(0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((iface, port))
    sock.listen(LISTEN_BACKLOG)
    return sock

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
            self.lock = threading.Lock()

        def __str__(self):
            return "Vm(name={}, uuid={}, port={}, clients={}, vts={}, last_time={}, vmotion={})".format(
                self.name, self.uuid, self.port, self.clients, self.vts, self.last_time, self.vmotion,
            )

        def fileno(self):
            return self.listener.fileno()

    class Client(TelnetServer):
        def __init__(self, sock,
                     server_opts = (BINARY, SGA, ECHO),
                     client_opts = (BINARY, SGA)):
            self.uuid = None
            TelnetServer.__init__(self, sock, server_opts, client_opts)

        def __str__(self):
            return "{}(uuid={}, port={}, peer={})".format(
                self.__class__.__name__,
                self.uuid,
                self.port,
                self.peername,
            )

    def __init__(self, proxy_port, admin_port, proxy_iface, admin_iface,
                 vm_port_start, vm_iface, vm_expire_time, backend, use_ssl=False,
                 ssl_cert=None, ssl_key=None):
        Poller.__init__(self)

        self.proxy_port = proxy_port
        self.admin_port = admin_port
        self.vm_iface = vm_iface
        self.proxy_iface = proxy_iface
        self.admin_iface = admin_iface
        if not vm_port_start: # account for falsey things, not just None
            vm_port_start = None
        self.vm_port_start = vm_port_start
        self.vm_expire_time = vm_expire_time
        self.backend = backend

        # should be held when modifying self.ports
        self.ports_lock = threading.Lock()

        self.orphans = []
        self.vms = {}
        self.ports = {}
        self.vmotions = {}
        self.do_ssl = use_ssl
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key

        self.task_queue = queue.Queue()
        self.task_queue_threads = []

        # raise the open files soft limit up to the hard limit to maximize
        # the number of open connections this process can have open
        (_, open_files_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
        logging.debug("Setting open files soft limit to %d", open_files_limit)
        resource.setrlimit(resource.RLIMIT_NOFILE,
                (open_files_limit, open_files_limit))

        # create an internal hard limit we want to stay below; the number of
        # open files used by this process is more than just the connections
        # so we build in a bit of buffer
        self.open_conns_hard_limit = open_files_limit - 64
        # set a soft limit above which we'll start collecting orphans before
        # their expire time (75% of hard limit)
        self.open_conns_soft_limit = int(self.open_conns_hard_limit * 0.75)
        logging.debug("Connection limits: soft: %d; hard: %d",
                      self.open_conns_soft_limit, self.open_conns_hard_limit)

    def _queue_run(self, queue):
        while True:
            try:
                queue.get()()
            except Exception as e:
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

    def send_buffered(self, ts, s = b''):
        if ts.send_buffered(s):
            self.add_writer(ts, self.send_buffered)
        else:
            self.del_writer(ts)

    def _count_open_connections(self):
        '''
        Return the total number of open connections.
        '''

        vm_connections = len(self.vms)
        client_connections = 0
        for uuid in self.vms.keys():
            try:
                vm = self.vms[uuid]
                client_connections += len(vm.clients)
            except KeyError:
                logging.debug("got keyerror while iterating over vms", 
                              exc_info=True, stack_info=True)
                # Other processes may be changing self.vms under us so don't
                # die if the vms record doesn't exist when we get to it.
                pass

        logging.debug("Current open connection count: "
                "%d vms (%d orphans), %d clients", vm_connections,
                len(self.orphans), client_connections)

        return (vm_connections + client_connections)


    def _can_accept_more_connections(self):
        '''
        Evaluate if this process can accept more connections given its
        limit on the open number of files and how many connections
        it currently has open. This is to prevent the primary process
        from dying due to attempting to exceed this limit.
        '''

        if self._count_open_connections() >= self.open_conns_hard_limit:
            return False

        return True

    def new_vm_connection(self, sock):
        sock.setblocking(0)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        try:
            vt = VMTelnetServer(sock, handler = self)
            self.add_reader(vt, self.queue_new_vm_data)
        except socket.error:
            # If there was a socket error on initialization, capture the
            # exception to avoid logging a traceback.
            logging.debug("uninitialized VM socket error", exc_info=True)

    def queue_new_vm_connection(self, listener):
        try:
            sock = listener.accept()[0]
        except (ssl.SSLError, OSError):
            logging.exception("Failed to accept new connection")
            return

        if not self._can_accept_more_connections():
            logging.error("Maximum number of connections reached, refusing "
                "incoming VM connection")
            sock.close()
            return

        self.task_queue.put(lambda: self.new_vm_connection(sock))

    def new_client_connection(self, sock, vm):
        logging.debug("new client connecting to %s", vm)

        sock.setblocking(0)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        if settings.VM_CLIENT_LIMIT > 0:
            if len(vm.clients) >= settings.VM_CLIENT_LIMIT:
                logging.error("%s already has %d connections. Refusing connection",
                              vm, len(vm.clients))
                sock.close()
                return

        try:
            client = self.Client(sock)
            client.uuid = vm.uuid
        except socket.error:
            # If there was a socket error on initialization, capture the
            # exception to avoid logging a traceback.
            logging.debug("uninitialized client socket error", exc_info=True)
            return

        self.add_reader(client, self.queue_new_client_data)
        vm.clients.append(client)

        logging.info("%s connected to %s (%d active clients)", client, vm, len(vm.clients))

    def queue_new_client_connection(self, vm):
        sock = vm.listener.accept()[0]

        if not self._can_accept_more_connections():
            logging.error("Maximum number of connections reached, refusing "
                "incoming client connection")
            sock.close()
            return

        self.task_queue.put(lambda: self.new_client_connection(sock, vm))

    def abort_vm_connection(self, vt):
        logging.info("%s disconnected", vt)
        vm = self.vms.get(vt.uuid)
        if vt.uuid and vm is not None:
            with vm.lock:
                if vt in vm.vts:
                    vm.vts.remove(vt)
                self.stamp_orphan(vm)
        vt.close()

    def new_vm_data(self, vt):
        neg_done = False
        try:
            neg_done = vt.negotiation_done()
        except (EOFError, IOError, socket.error):
            logging.debug("%s got socket error", vt, stack_info=True, exc_info=True)
            logging.warn('%s experienced a socket error, closing socket', vt)
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
            logging.debug("%s got socket error", vt, stack_info=True, exc_info=True)
            self.abort_vm_connection(vt)
            return

        if not s: # May only be option data, or exception
            self.add_reader(vt, self.queue_new_vm_data)
            return

        if not vt.uuid or not vt.uuid in self.vms:
            # In limbo, no one can hear you scream
            self.add_reader(vt, self.queue_new_vm_data)
            return

        # logging.debug('new_vm_data %s: %s', vt.uuid, repr(s))
        self.backend.notify_vm_msg(vt.uuid, vt.name, s)

        clients = self.vms[vt.uuid].clients[:]
        for cl in clients:
            try:
                self.send_buffered(cl, s)
            except (EOFError, IOError, socket.error):
                logging.debug('%s to %s: cl.socket send error', vt, cl, exc_info=True,
                              stack_info=True)
                self.abort_client_connection(cl)
        self.add_reader(vt, self.queue_new_vm_data)

    def queue_new_vm_data(self, vt):
        # Don't alert repeatedly on the same input
        self.del_reader(vt)
        self.task_queue.put(lambda: self.new_vm_data(vt))

    def abort_client_connection(self, client):
        vm = self.vms.get(client.uuid)
        logging.info("%s disconnected from %s", client, vm)
        if vm is not None:
            with vm.lock:
                if client in vm.clients:
                    vm.clients.remove(client)
                self.stamp_orphan(vm)
        self.backend.notify_client_del(client.sock, client.uuid)

    def new_client_data(self, client):
        neg_done = False
        try:
            neg_done = client.negotiation_done()
        except EOFError:
            logging.debug("%s: client closed connection", client)
            self.abort_client_connection(client)
            return
        except (IOError, socket.error):
            logging.debug('%s: socket error, aborting client connection',
                          client, exc_info=True, stack_info=True)
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
        except EOFError:
            logging.debug("%s: client closed connection", client)
            self.abort_client_connection(client)
            return
        except (IOError, socket.error):
            logging.debug('%s: socket error, aborting client connection', 
                          client, exc_info=True, stack_info=True)
            self.abort_client_connection(client)
            return

        if not s: # May only be option data, or exception
            self.add_reader(client, self.queue_new_client_data)
            return

        # logging.debug('new_client_data %s: %s', client.uuid, repr(s))

        for vt in self.vms[client.uuid].vts:
            try:
                self.send_buffered(vt, s)
            except BrokenPipeError:
                logging.debug('%s to %s: BrokenPipeError', client, vt,
                              exc_info=True, stack_info=True)
                self.abort_vm_connection(vt)
            except (EOFError, IOError, socket.error):
                logging.debug('%s to %s: cl.socket send error', client, vt,
                              exc_info=True, stack_info=True)
        self.add_reader(client, self.queue_new_client_data)

    def queue_new_client_data(self, client):
        # Don't alert repeatedly on the same input
        self.del_reader(client)
        self.task_queue.put(lambda: self.new_client_data(client))

    def new_vm(self, uuid, name, port = None, vts = None):
        vm = self.Vm(uuid = uuid, name = name, vts = vts)

        self.open_vm_port(vm, port)

        # The clock is always ticking
        self.stamp_orphan(vm)

        self.vms[uuid] = vm

        # Only notify if we generated the port
        if not port:
            self.backend.notify_vm(vm.uuid, vm.name, vm.port)

        logging.info('VM %s connected, listening on port %s',
                     vm, vm.port)

        return vm

    def _add_vm_when_ready(self, vt):
        if not vt.name or not vt.uuid:
            return

        self.new_vm(vt.uuid, vt.name, vts = [vt])

    def handle_vc_uuid(self, vt):
        if not vt.uuid in self.vms:
            self._add_vm_when_ready(vt)
            return

        # This could be a reconnect, or it could be a vmotion
        # peer. Regardless, it's easy enough just to allow this
        # new vt to send to all clients, and all clients to
        # receive.
        vm = self.vms[vt.uuid]
        vm.vts.append(vt)

        logging.info('VM %s reconnected', vm)

    def handle_vm_name(self, vt):
        if not vt.uuid in self.vms:
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
        logging.debug("vmotion began for %s", vt)

        return True

    def handle_vmotion_peer(self, vt, data):
        if not data in self.vmotions:
            logging.debug('peer cookie %s doesn\'t exist', hexdump(data))
            return False

        logging.debug('peer cookie %s maps to uuid %s',
                      hexdump(data), self.vmotions[data])

        peer_uuid = self.vmotions[data]
        if vt.uuid:
            vm = self.vms[vt.uuid]
            if vm.uuid != peer_uuid:
                logging.debug('peer uuid %s != other uuid %s',
                              vm.uuid, peer_uuid)
                return False
            return True # vt already in place
        else:
            # Act like we just learned the uuid
            vt.uuid = peer_uuid
            if settings.SUPPORT_MULTI_CONSOLE:
                uuid_split = peer_uuid.rsplit("_", 1)
                if len(uuid_split) < 2:
                    logging.error("peer uuid appears invalid. didnt find URI suffix")
                    return False
                vt.uri = uuid_split[-1]
                logging.debug("set URI to %s", vt.uri)
            logging.debug("vmotion_peer, calling handle_vc_uuid for %s", vt)
            self.handle_vc_uuid(vt)

        return True

    def handle_vmotion_complete(self, vt):
        logging.debug('%s vmotion complete', vt)
        vm = self.vms[vt.uuid]
        del self.vmotions[vm.vmotion]
        vm.vmotion = None

    def handle_vmotion_abort(self, vt):
        logging.debug('%s vmotion abort', vt)
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
        self.backend.notify_query_socket(sock, self)

    def queue_new_admin_connection(self, listener):
        sock = listener.accept()[0]

        if not self._can_accept_more_connections():
            logging.error("Maximum number of connections reached, refusing "
                "incoming admin connection")
            sock.close()
            return

        self.task_queue.put(lambda: self.new_admin_connection(sock))

    def new_admin_client_connection(self, sock, uuid, readonly):
        vm = self.vms[uuid]

        if settings.VM_CLIENT_LIMIT > 0:
            if len(vm.clients) >= settings.VM_CLIENT_LIMIT:
                logging.error("%s already has %d connections. Refusing connection",
                              vm, len(vm.clients))
                sock.close()
                return

        client = self.Client(sock)
        client.uuid = uuid

        if not readonly:
            self.add_reader(client, self.queue_new_client_data)
        vm.clients.append(client)

        logging.debug('uuid %s new client, %d active clients',
                      client.uuid, len(vm.clients))

    def queue_new_admin_client_connection(self, sock, uuid, readonly):
        self.task_queue.put(lambda: self.new_admin_client_connection(sock, uuid, readonly))

    def collect_orphans(self):
        t = time.time()

        orphans = self.orphans[:]
        for uuid in orphans:
            if not uuid in self.vms:
                self.orphans.remove(uuid)
                continue
            vm = self.vms[uuid]
            expire_time = vm.last_time + self.vm_expire_time
            remaining_time = expire_time - t

            if not self.check_orphan(vm):
                logging.debug("%s is no longer an orphan", vm)
                self.orphans.remove(uuid) # Orphan no longer
            elif remaining_time > 0:
                logging.debug("expire time for %s is in %ds", vm, remaining_time)
            else:
                logging.debug("expire time for %s was %ds ago", vm, remaining_time)
                self.expire_orphan(vm)

        # if the number of connections is above our soft limit and we have
        # orphans, collect enough to drop it below that limit, oldest first
        connection_overage = (self._count_open_connections() -
                              self.open_conns_soft_limit)
        if connection_overage > 0:
            logging.warn("Number of open connections (%d) is above "
                    "soft limit (%d). Expiring oldest orphans until "
                    "under that limit.", self._count_open_connections(),
                    self.open_conns_soft_limit)

            orphans = self.orphans[:]
            orphans.sort(key=lambda uuid: self.vms[uuid].last_time,
                         reverse=True)
            for index in range(min(connection_overage, len(orphans))):
                uuid = orphans[index]
                vm = self.vms[uuid]
                self.expire_orphan(vm)

    def expire_orphan(self, vm):
        '''
        Expire an orphan. Assumes the due-diligence has already been done
        to confirm that vm is, indeed, an orphan.
        '''

        logging.debug('expired VM with uuid %s, port %s', vm.uuid, vm.port)
        self.backend.notify_vm_del(vm.uuid)

        self.delete_stream(vm)
        del vm.listener
        with self.ports_lock:
            if self.vm_port_start is not None:
                del self.ports[vm.port]
        del self.vms[vm.uuid]
        if vm.vmotion:
            del self.vmotions[vm.vmotion]
            vm.vmotion = None
        del vm

    def open_vm_port(self, vm, port):
        self.collect_orphans()

        if self.vm_port_start is None:
            return

        with self.ports_lock:
            if port:
                vm.port = port
            else:
                p = self.vm_port_start
                while p in self.ports:
                    p += 1
                vm.port = p

            assert not vm.port in self.ports
            self.ports[vm.port] = vm.uuid

        vm.listener = openport(vm.port, self.vm_iface)
        self.add_reader(vm, self.queue_new_client_connection)

    def clear_port(self, port_num):
        """
        Disconnect all the clients connected to the VM whose port
        number is 'port_num'
        """
        if self.vm_port_start is None:
            return False

        with self.ports_lock:
            uuid = self.ports.get(port_num)
            if uuid is None:
                logging.debug("port %d appears to not be in use", port_num)
                return False
            vm = self.vms.get(uuid)
            if vm is None:
                logging.debug("could not find VM with uuid %s", uuid)
                return False
            for client in vm.clients:
                self.abort_client_connection(client)
        return True

    def create_old_vms(self, vms):
        for vm in vms:
            self.new_vm(uuid = vm.uuid, name = vm.name, port = vm.port)

    def run(self):
        logging.info('Starting vSPC on proxy iface %s port %d, admin iface %s '
                     'port %d', self.proxy_iface, self.proxy_port,
                     self.admin_iface, self.admin_port)
        if self.vm_port_start is not None:
            logging.info("Allocating VM ports starting at %d on interface %s",
                         self.vm_port_start, self.vm_iface)

        self.create_old_vms(self.backend.get_observed_vms())

        self.add_reader(openport(self.proxy_port, self.proxy_iface, self.do_ssl, self.ssl_cert, self.ssl_key), self.queue_new_vm_connection)
        self.add_reader(openport(self.admin_port, self.admin_iface), self.queue_new_admin_connection)
        self.start()
        self.run_forever()
