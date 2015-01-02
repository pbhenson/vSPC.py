# vSPC/backend.py -- various backend implementations

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

import getopt
import logging
import optparse
import os
import cPickle as pickle
import signal
import string
import sys
import threading
import Queue

from admin import Q_VERS, Q_NAME, Q_UUID, Q_PORT, Q_OK, Q_VM_NOTFOUND, Q_LOCK_EXCL, Q_LOCK_WRITE, Q_LOCK_FFA, Q_LOCK_FFAR, Q_LOCK_BAD, Q_LOCK_FAILED

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

    def get_option_group(self, parser):
        group = optparse.OptionGroup(parser, "Memory backend options",
            "This backend takes no arguments")
        return group

    def setup(self, options):
        pass

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

    def shutdown(self):
        pass

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
        Return a list of console activity to give a newly connected client,
        giving them some context (if available) for their newly-created
        session.
        """
        return ""

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
        logging.debug("vm_hook: uuid: %s, name: %s, port: %s",
                      uuid, name, port)

    def notify_vm_msg(self, uuid, name, s):
        self.hook_queue.put(lambda: self.vm_msg_hook(uuid, name, s))

    def vm_msg_hook(self, uuid, name, s):
        logging.debug("vm_msg_hook: uuid: %s, name: %s, msg: %s",
                      uuid, name, s)

    def notify_client_del(self, sock, uuid):
        self.hook_queue.put(lambda: self.client_del(sock, uuid))

    def client_del(self, sock, uuid):
        logging.debug("client_del: uuid %s, client %s", uuid, sock)
        vm = None
        with self.observed_vms_lock:
            if uuid in self.observed_vms: vm = self.observed_vms[uuid]
        if vm is not None:
            with vm.modification_lock:
                self.maybe_unlock_vm(vm, sock.fileno())
        sock.close()

    def notify_vm_del(self, uuid):
        self.observer_queue.put(lambda: self.vm_del(uuid))

    def vm_del(self, uuid):
        with self.observed_vms_lock:
            if self.observed_vms.has_key(uuid):
                del self.observed_vms[uuid]

        self.hook_queue.put(lambda: self.vm_del_hook(uuid))

    def vm_del_hook(self, uuid):
        logging.debug("vm_del_hook: uuid: %s", uuid)

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
                        lock_result = self.try_to_lock_vm(vm, sock.fileno(), lock_mode)
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
            logging.debug('handle_query_socket exception: %s', str(e))

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

    def maybe_unlock_vm(self, vm, sockno):
        """
        I determine whether a vm can be unlocked due to a client disconnecting.

        Callers are assumed to hold the modification lock of the vm argument.
        """
        if vm.lockholder is sockno:
            vm.lockholder = None
            vm.lock.release()
        if sockno in vm.writers:
            vm.writers.remove(sockno)
        if sockno in vm.readers:
            vm.readers.remove(sockno)
        if not vm.writers:
            vm.lock_mode = None

    def try_to_lock_vm(self, vm, sockno, lock_mode):
        """
        I try to acquire the requested locking mode on the given Vm. If I'm
        successful, I return True; otherwise, I return False.

        Callers are assumed to hold the modification lock of the vm argument.
        """
        logging.debug("Trying to lock vm %s for client", vm.name)
        if lock_mode == Q_LOCK_EXCL:
            logging.debug("Exclusive lock mode selected")
            if vm.lock.acquire(False):
                logging.debug("Acquired exclusive lock")
                # got the lock; need to check for other readers and writers.
                if not vm.readers and not vm.writers:
                    logging.debug("No clients and no other writers; we're good")
                    vm.lockholder = sockno
                    vm.lock_mode = lock_mode
                    vm.readers.append(sockno)
                    vm.writers.append(sockno)
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
                    vm.lockholder = sockno
                    vm.lock_mode = lock_mode
                    vm.readers.append(sockno)
                    vm.writers.append(sockno)
                    return lock_mode
                else:
                    logging.debug("Other writers, bail out")
                    vm.lock.release()

        elif lock_mode in (Q_LOCK_FFA, Q_LOCK_FFAR):
            logging.debug("free-for-all selected")
            if vm.lockholder is None:
                logging.debug("No one thinks they have exclusive write access, returning True")
                vm.lock_mode = Q_LOCK_FFA
                vm.writers.append(sockno)
                vm.readers.append(sockno)
                return Q_LOCK_FFA

            if vm.lock_mode != Q_LOCK_EXCL and lock_mode == Q_LOCK_FFAR:
                logging.debug("VM has a write lock, adding as read-only")
                vm.readers.append(sockno)
                return Q_LOCK_FFAR

        logging.debug("Lock acquisition failed, returning False")
        return False

# Persistence fields for file backend.
P_UUID = 'uuid'
P_NAME = 'name'
P_PORT = 'port'

class vSPCBackendFile(vSPCBackendMemory):
    def __init__(self):
        vSPCBackendMemory.__init__(self)

        self.shelf = None

    def get_option_group(self, parser):
        group = optparse.OptionGroup(parser, "File backend options")
        group.add_option("-f", "--file", dest="filename",
            help="DBM file prefix to persist mappings to (.dat/.dir may follow")

        return group

    def setup(self, options):
        import shelve

        if not options.filename:
            raise ValueError("Filename is required when using the File backend")

        self.shelf = shelve.open(options.filename)

    def shutdown(self):
        self.shelf.close()

    def vm_hook(self, uuid, name, port):
        self.shelf[uuid] = { P_UUID : uuid, P_NAME : name, P_PORT : port }
        self.shelf.sync()

    def vm_del_hook(self, uuid):
        del self.shelf[uuid]
        self.shelf.sync()

    def load_vms(self):
        vms = {}
        for v in self.shelf.values():
            vms[v[P_UUID]] = \
                self.OVm(uuid = v[P_UUID], name = v[P_NAME], port = v[P_PORT])

        return vms

class vSPCBackendLogging(vSPCBackendMemory):
    """
    I'm a backend for vSPC.py that logs VM messages to a file or files.
    """
    def __init__(self):
        self.logdir = "/var/log/consoles"
        self.prefix = ""
        self.mode = "0600"

        # uuid => filehandle
        self.logfiles = {}

        # uuid => name
        self.vm_names = {}

        # uuid => string of scrollback
        self.scrollback = {}
        self.scrollback_limit = 200


    def setup(self, args):
        parsed_args = self.parse_args(args)

        self.logdir = parsed_args.logdir
        self.prefix = parsed_args.prefix
        self.mode  = parsed_args.mode

        # register for SIGHUP, so we know when to reload logfiles.
        signal.signal(signal.SIGHUP, self.handle_sighup)

        # How many scrollback lines to keep for each VM.
        self.scrollback_limit = options.context

    def shutdown(self):
        for k, f in self.logfiles.iteritems():
            f.close()

    def add_scrollback(self, uuid, msg):
        msgs = self.scrollback.setdefault(uuid, "")
        msgs += msg
        msgs = msgs[len(msgs)-self.scrollback_limit:]
        self.scrollback[uuid] = msgs

    def get_seed_data(self, uuid):
        if uuid in self.scrollback:
            return self.scrollback[uuid]
        return ""

    def vm_msg_hook(self, uuid, name, msg):
        f = self.file_for_vm(name, uuid)
        try:
            f.write(msg)
            f.flush()
            self.add_scrollback(uuid, msg)
        except ValueError, e:
            # we tried to write to a closed fd, which means that we were
            # told to reload our log files between when we got the file
            # descriptor and when we tried to write to it. if we try
            # again, it should go through, so just do that.
            return self.vm_msg_hook(uuid, name, msg)

    def get_option_group(self, parser):
        group = optparse.OptionGroup(parser, "Logging backend options")

        # XXX: Annoying; it would be nicer if OptionParser would print
        # out a more verbose message upon encountering unrecognized
        # arguments
        group.add_option("-l", "--logdir", type='string',
                         action='store', default="/var/log/consoles",
                         help='Directory in which log files are written')
        group.add_option("-p", "--prefix", default='', type='string',
                         help="First part of log file names")
        group.add_option("--context", type='int', action='store', default=200,
                         help="Number of VM messages to keep as context for new connections")
        group.add_option("-m", "--mode", default='0600', type='string',
                         help="Mode for new logs (default 0600)")

        return group

    def file_for_vm(self, name, uuid):
        if uuid not in self.logfiles:
            if self.prefix:
                filename = "%s/%s-%s.log" % (self.logdir, self.prefix, name)
            else:
                filename = "%s/%s.log" % (self.logdir, name)
            fd = os.open(filename, os.O_WRONLY | os.O_APPEND | os.O_CREAT, string.atoi(self.mode, 8))
            self.logfiles[uuid] = os.fdopen(fd, "w")
            self.vm_names[uuid] = name
        return self.logfiles[uuid]

    def reload(self):
        for k, f in self.logfiles.iteritems():
            f.close()
            del(self.logfiles[k])
            self.logfiles[k] = self.file_for_vm(self.vm_names[k], k)

    def handle_sighup(self, signum, frame):
        assert signum == signal.SIGHUP

        logging.info('vSPC received reload request, reopening log files')
        self.reload()
