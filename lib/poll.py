# vSPC/poll.py -- poller and selector objects.
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

import logging
import select
import threading

class Poller:
    def __init__(self):
        # stream => func
        self.read_handlers = {}
        self.write_handlers = {}

        # fileno => stream
        # needed to associate filenos returned by epoll.poll with streams.
        self.fds = {}

        # stream => epoll mask
        # needed to associate streams passed by higher-level apps with
        # epoll masks.
        self.fd_mask = {}

        self.lock = threading.Lock()

        self.epoll = select.epoll()

    def add_stream(self, stream):
        # called with self.lock
        self.fds[stream.fileno()] = stream
        self.fd_mask[stream] = select.EPOLLERR | select.EPOLLHUP
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
            if event == select.EPOLLIN or event == select.EPOLLERR or event == select.EPOLLHUP:
                # read event, or error condition that we should treat like a read event
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
                    fd = self.fds[fileno]
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


