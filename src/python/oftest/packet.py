
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


# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2010 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
"""
Wrap scapy to satisfy pylint
"""
from oftest import config
import sys

try:
    import scapy.config
    import scapy.route
    import scapy.layers.l2
    import scapy.layers.inet
    if not config["disable_ipv6"]:
        import scapy.route6
        import scapy.layers.inet6
except ImportError:
    sys.exit("Need to install scapy for packet parsing")

Ether = scapy.layers.l2.Ether
LLC = scapy.layers.l2.LLC
SNAP = scapy.layers.l2.SNAP
Dot1Q = scapy.layers.l2.Dot1Q
IP = scapy.layers.inet.IP
IPOption = scapy.layers.inet.IPOption
ARP = scapy.layers.inet.ARP
TCP = scapy.layers.inet.TCP
UDP = scapy.layers.inet.UDP
ICMP = scapy.layers.inet.ICMP


from scapy.fields import *
from scapy.packet import *

class ThreeBytesField(X3BytesField, ByteField):
    def i2repr(self, pkt, x):
        return ByteField.i2repr(self, pkt, x)

class VXLAN(Packet):
    name = "VXLAN"
    fields_desc = [ FlagsField("flags", 0x08, 8, ['R', 'R', 'R', 'I', 'R', 'R', 'R', 'R']),
                    X3BytesField("reserved1", 0x000000),
                    ThreeBytesField("vni", 0),
                    XByteField("reserved2", 0x00)]

    def mysummary(self):
        return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

bind_layers(UDP, VXLAN, dport=4789)
bind_layers(VXLAN, Ether)


class MPLS(Packet): 
   name = "MPLS" 
   fields_desc =  [ BitField("label", 3, 20), 
                    BitField("cos", 0, 3), 
                    BitField("s", 1, 1), 
                    ByteField("ttl", 0)  ] 

bind_layers(Ether, MPLS, type=0x8847)

if not config["disable_ipv6"]:
    IPv6 = scapy.layers.inet6.IPv6
    ICMPv6Unknown = scapy.layers.inet6.ICMPv6Unknown
    ICMPv6EchoRequest = scapy.layers.inet6.ICMPv6EchoRequest
