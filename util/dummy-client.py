#!/usr/bin/python

# Copyright 2013 Kevan A. Carstensen <kevan@isnotajoke.com>. All Rights Reserved
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

from optparse import OptionParser, OptionValueError

if __name__ == '__main__':
    parser = OptionParser(usage="usage: %prog [options] VSPC_HOST PORT")

    parser.add_option("-n", "--name", dest='vm_name', default="test_vm",
                      help="VM name to give to the server when connecting")
    parser.add_option("-u", "--uid", dest='vm_uid', default="test123456789",
                      help="ID to give to the server when connecting")
    parser.add_option("-d", "--debug", action='store_true', default=False,
                      help="Debug mode; print debug information")

    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.error("Expected 2 arguments, found %d" % len(args))

    vspc_host = args[0]
    vspc_port = args[1]
