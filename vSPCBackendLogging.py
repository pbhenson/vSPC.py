# Copyright 2011 California State Polytechnic University, Pomona. All Rights Reserved
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
# THIS SOFTWARE IS PROVIDED BY California State Polytechnic University, Pomona.
# ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those of the
# authors and should not be interpreted as representing official policies, either expressed
# or implied, of California State Polytechnic University, Pomona.

import signal
import logging
import optparse
import shlex
import os
import string

__author__    = "Kevan Carstensen"
__copyright__ = "Copyright (C) 2011 California State Polytechnic University, Pomona"

from vSPC import vSPCBackendMemory

class vSPCBackendLogging(vSPCBackendMemory):
    """
    I'm a backend for vSPC.py that logs VM messages to a file or files.
    """
    def setup(self, args):
        parsed_args = self.parse_args(args)

        self.logdir = parsed_args.logdir
        self.prefix = parsed_args.prefix
        self.mode  = parsed_args.mode
        # uuid => filehandle
        self.logfiles = {}

        # uuid => name
        self.vm_names = {}

        # register for SIGHUP, so we know when to reload logfiles.
        signal.signal(signal.SIGHUP, self.handle_sighup)

        # uuid => string of scrollback
        self.scrollback = {}
        # How many scrollback lines to keep for each VM.
        self.scrollback_limit = parsed_args.context

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

    def parse_args(self, args):
        # XXX: Annoying; it would be nicer if OptionParser would print
        # out a more verbose message upon encountering unrecognized
        # arguments
        u = "%prog ...--backend-args='[ [ (-l | --logdir) logdir ] [ (-p | --prefix) prefix ] [ (-m | --mode) mode ]'"
        parser = optparse.OptionParser(usage=u)
        parser.add_option("-l", "--logdir", type='string',
                          action='store', default="/var/log/consoles",
                          help='Directory in which log files are written')
        parser.add_option("-p", "--prefix", default='', type='string',
                          help="First part of log file names")
        parser.add_option("--context", type='int', action='store', default=200,
                          help="Number of VM messages to keep as context for new connections")
        parser.add_option("-m", "--mode", default='0600', type='string',
                          help="Mode for new logs (default 0600)")
        args_list = shlex.split(args)
        (options, args) = parser.parse_args(args_list)
        return options

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
