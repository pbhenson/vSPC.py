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

import errno
import logging
import select
import threading

class PollEventSource:
    """
    Encapsulates epoll state around a stream provided by other code.
    """
    def __init__(self, stream):
        self.fileno        = stream.fileno()
        self.stream        = stream
        self.read_handler  = None
        self.write_handler = None
        self.mask          = select.EPOLLERR | select.EPOLLHUP

    def enable_writes(self):
        """Alter epoll mask so epoll triggers on write events"""
        self.mask |= select.EPOLLOUT

    def disable_writes(self):
        """Alter epoll mask so epoll doesn't trigger on write events"""
        self.mask &= ~select.EPOLLOUT

    def enable_reads(self):
        """Alter epoll mask so epoll triggers on read events"""
        self.mask |= select.EPOLLIN

    def disable_reads(self):
        """Alter epoll mask for epoll doesn't trigger on read events"""
        self.mask &= ~select.EPOLLIN

class Poller:
    """
    Manage & respond to events on a set of streams.

    Each stream is assumed to be a file descriptor like object (or at
    least an object with a fileno method that resolves to an fd), and
    can have a read and write handler associated with it. Poller will
    monitor the descriptor for activity, and call the read or write
    handler as appropriate when it detects activity.

    Poller uses Linux's epoll facility to work. See epoll(7) for more
    information on epoll.
    """
    def __init__(self):
        # stream => PollEventSource instance
        # used to translate arguments from higher level code
        self.event_sources_by_stream = {}
        # fileno => PollEventSource instance
        # used to translate filenos from epoll
        self.event_sources_by_fileno = {}

        # If a stream is in event_sources_by_stream, its fileno should
        # be in event_sources_by_fileno, and vice-versa.

        # Poller needs to be thread safe, as client code may use
        # threads. All code that changes self.event_sources_by_stream or
        # self.event_sources_by_fileno needs to do so while holding the
        # lock.
        self.lock = threading.Lock()

        self.epoll = select.epoll()

    def unsafe_has_stream(self, stream):
        """
        Return True if stream is known to Poller, False otherwise.
        """
        return stream in self.event_sources_by_stream

    def unsafe_add_stream(self, stream):
        """
        Add stream to Poller, updating internal state as necessary to
        get ready to start listening for events on the stream.
        """
        pes = PollEventSource(stream)
        self.event_sources_by_stream[stream] = pes
        self.event_sources_by_fileno[pes.fileno] = pes
        self.epoll.register(pes.fileno, pes.mask)

    def add_reader(self, stream, func):
        """
        Associate func with stream's read events.
        """
        with self.lock:
            if not self.unsafe_has_stream(stream):
                self.unsafe_add_stream(stream)

            pes = self.event_sources_by_stream[stream]
            pes.read_handler = func
            pes.enable_reads()

            self.epoll.modify(pes.fileno, pes.mask)

    def del_reader(self, stream):
        """
        Stop watching for read events on stream.
        """
        with self.lock:
            try:
                pes = self.event_sources_by_stream[stream]
                pes.disable_reads()
                self.epoll.modify(pes.fileno, pes.mask)
            except KeyError:
                pass

    def add_writer(self, stream, func):
        """
        Associate func with stream's write events.
        """
        with self.lock:
            if not self.unsafe_has_stream(stream):
                self.unsafe_add_stream(stream)

            pes = self.event_sources_by_stream[stream]
            pes.write_handler = func
            pes.enable_writes()

            self.epoll.modify(pes.fileno, pes.mask)

    def del_writer(self, stream):
        """
        Stop watching for write events on stream.
        """
        with self.lock:
            try:
                pes = self.event_sources_by_stream[stream]
                pes.disable_writes()
                self.epoll.modify(pes.fileno, pes.mask)
            except KeyError:
                pass

    def del_all(self, stream):
        """
        Stop watching for any events on stream.
        """
        self.del_reader(stream)
        self.del_writer(stream)

    def delete_stream(self, stream):
        """
        Delete stream from Poller. Call to handle disconnects, errors, etc.

        Tolerates some errors associated with common use cases:
            - Won't raise error on EBADF (disconnected/closed FDs may be
              removed from epoll set automatically, in which case
              attempts to do so by user code will raise EBADF)
        """
        with self.lock:
            try:
                self.unsafe_remove_fd(stream)
            except IOError, e:
                if e.errno != errno.EBADF:
                    raise

    def unsafe_remove_fd(self, fd):
        """
        Remove stream & associate state from Poller.
        """
        pes = self.event_sources_by_stream[fd]
        del self.event_sources_by_stream[fd]
        del self.event_sources_by_fileno[pes.fileno]
        self.epoll.unregister(pes.fileno)

    def run_once(self, timeout = -1):
        """
        Poll for events on monitored streams, then process them.
        """
        try:
            events = self.epoll.poll(timeout)
        except IOError, e:
            if e.errno == errno.EINTR:
                # interrupted syscall; continue w/o error
                return False

            # unknown error; raise exception
            raise

        for (fileno, event) in events:
            if event & select.EPOLLIN:
                # read event
                with self.lock:
                    pes = self.event_sources_by_fileno[fileno]
                    handler = pes.read_handler
                handler(pes.stream)
            elif event & select.EPOLLOUT:
                # write event
                with self.lock:
                    pes = self.event_sources_by_fileno[fileno]
                    handler = pes.write_handler
                handler(pes.stream)
            elif event & select.EPOLLERR or event & select.EPOLLHUP:
                # error or disconnect
                with self.lock:
                    pes = self.event_sources_by_fileno[fileno]
                    fd = pes.stream
                    self.unsafe_remove_fd(fd)
            else:
                # Event that we don't know how to handle.
                logging.debug("I was asked to handle an unsupported event (%d) "
                              "for fd %d. I'm removing fd %d" % (event, fileno, fileno))
                with self.lock:
                    pes = self.event_sources_by_fileno[fileno]
                    fd = pes.stream
                    self.unsafe_remove_fd(fd)

    def run_forever(self):
        """
        Repeatedly poll for & process events.
        """
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


