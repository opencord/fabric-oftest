
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


# Imported from scapy at revision 1270:113ef25f9583
# This file is not included in the Ubuntu packages of scapy, so it is checked
# in to our repo to simplify installation. This file is under the GPLv2.

# http://trac.secdev.org/scapy/ticket/31 

# scapy.contrib.description = MPLS
# scapy.contrib.status = loads

from scapy.packet import Packet,bind_layers
from scapy.fields import BitField,ByteField
from scapy.layers.l2 import Ether

class MPLS(Packet): 
   name = "MPLS" 
   fields_desc =  [ BitField("label", 3, 20), 
                    BitField("cos", 0, 3), 
                    BitField("s", 1, 1), 
                    ByteField("ttl", 0)  ] 

bind_layers(Ether, MPLS, type=0x8847)

# Not in upstream scapy
bind_layers(MPLS, MPLS, s=0)
