
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


import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr

"""
Not Verify yet, need to think how to verify meter
"""

class wred(base_tests.SimpleDataPlane):
    """
    [WRED]
      WRED (DCTCP)

    Inject  eth 1/1 untag, SA000000112233, DA000000000111, TCP ECN 01 [100%]
    Output  eth 1/5 ECN 11

    [CLI] interface eth 1/1 => switch priority default 1
    dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20005 group=any,port=any,weight=0 output=5
    dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=2 goto:20
    dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=2 goto:20
    dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 in_port=3 write:group=0x20005
    dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=1 write:group=0x20005
    dpctl tcp:192.168.1.1:6633 queue-mod type=wred,port=5,queue=0 min=1,max=60,ecn=100,drop=100
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        input_port2 = test_ports[1]
        output_port = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=2 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port2)+",vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=2 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port2)+" write:group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28")
        apply_dpctl_mod(self, config, "queue-mod type=wred,port="+str(output_port)+",queue=0 min=1,max=60,ecn=100,drop=100")

        # TCP ecn = 01
        input_pkt = simple_packet(
                '70 72 cf 7c f3 a3 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 01 00 4e 04 d2 00 00 7f 06 b2 7b c0 a8 '
                '01 0a c0 a8 02 02 00 03 00 06 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 2f 5d 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        # TCP ecn = 00
        input_pkt2 = simple_packet(
                '70 72 cf 7c f3 a3 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 06 b2 7b c0 a8 '
                '01 0a c0 a8 02 02 00 03 00 06 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 2f 5d 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        # TCP ecn = 11
        output_pkt = simple_packet(
                '70 72 cf 7c f3 a3 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 11 00 4e 04 d2 00 00 7f 06 b2 7b c0 a8 '
                '01 0a c0 a8 02 02 00 03 00 06 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 2f 5d 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        self.dataplane.send(input_port2, str(input_pkt2))
        verify_packet(self, str(output_pkt), output_port)

