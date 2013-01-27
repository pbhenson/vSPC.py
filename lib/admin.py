# lib/admin.py -- things related to the implementation of the admin query protocol

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

# Query protocol
Q_VERS        = 2
Q_NAME        = 'name'
Q_UUID        = 'uuid'
Q_PORT        = 'port'
Q_OK          = 'vm_found'
Q_VM_NOTFOUND = 'vm_not_found'
# Exclusive write and read access; no other clients have any access to the VM.
Q_LOCK_EXCL   = "exclusive"
# Exclusive write access; other clients can watch the session
Q_LOCK_WRITE  = "write"
# Nonexclusive write access; other clients may watch and interact with the VM.
Q_LOCK_FFA    = "free_for_all"
# Same as FFA, but with a fallback to read access if the VM is locked in
# nonexclusive mode.
Q_LOCK_FFAR   = "free_for_all_or_readonly"
Q_LOCK_BAD    = "lock_invalid"
Q_LOCK_FAILED = "lock_failed"

