
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Support an illegal message
"""

import struct
import ofp

class illegal_message_type(object):
    version = ofp.OFP_VERSION
    type = 217

    def __init__(self, xid=None):
        self.xid = xid

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0)) # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(buf):
        raise NotImplementedError()

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.version != other.version: return False
        if self.type != other.type: return False
        if self.xid != other.xid: return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return self.show()

    def show(self):
        return "illegal_message_type"
