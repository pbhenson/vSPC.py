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
vSPCBackendSample.py - Sample backend for vSPC.py

Example file to show a sample backend implementation, inheriting from
vSPCBackendMemory. This demonstrates how to modify the hooks in your
own backend implementation. Hooks can block arbitrarily, as they run
on a separate worker thread, in order of VM modification.

Run with something like:
  PYTHONPATH=/path/to/sample vSPC.py -s --backend Sample

"""

__author__ = "Zachary M. Loafman"
__copyright__ = "Copyright (C) 2011 Isilon Systems LLC."
__revision__ = "$Id$"

from vSPC import vSPCBackendMemory
import logging

class vSPCBackendSample(vSPCBackendMemory):
    def vm_hook(self, uuid, name, port):
        logging.debug("sample vm_hook: uuid: %s, name: %s, port: %s" %
                      (uuid, name, port))

    def vm_del_hook(self, uuid):
        logging.debug("sample vm_del_hook: uuid: %s" % uuid)



