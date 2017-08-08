
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


class test_v4(base_tests.SimpleDataPlane):
    """
    [PIM BIDR IPv4]
      PIM BIDR IPv4

    Inject  eth 1/3 tag 3, SA unknown, DA 01005E010101, SIP 192.168.2.1, DIP 224.0.0.1
    Output  eth 1/1 tag 2, SA 000001223355, DA 01005e010101, SIP 192.168.2.1, DIP 224.0.0.1

    Inject  eth 1/1 tag 2, SA unknown, DA 01005E010101, SIP 192.168.2.1, DIP 224.0.0.1
    Output  eth 1/3 tag 3, SA 000002223355, DA 01005e010101, SIP 192.168.2.1, DIP 224.0.0.1

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x00001fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x00001fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 eth_dst=01:00:5e:01:01:01/ff:ff:ff:80:00:00,eth_type=0x0800 goto:40
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x58000001 group=any,port=any,weight=0 set_field=eth_src=00:00:01:22:33:55,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x58000002 group=any,port=any,weight=0 set_field=eth_src=00:00:02:22:33:55,set_field=vlan_vid=3,group=0x30003
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=all,group=0x60058001 group=any,port=any,weight=0 group=0x58000001 group=any,port=any,weight=0 group=0x58000002
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=40,cmd=add,prio=401 eth_type=0x800,ip_dst=224.0.0.1 write:group=0x60058001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1002/0x00001fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x00001fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 eth_dst=01:00:5e:01:01:01/ff:ff:ff:80:00:00,eth_type=0x0800 goto:40")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x58000001 group=any,port=any,weight=0 set_field=eth_src=00:00:01:22:33:55,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x58000002 group=any,port=any,weight=0 set_field=eth_src=00:00:02:22:33:55,set_field=vlan_vid=3,group=0x3000"+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x60058001 group=any,port=any,weight=0 group=0x58000001 group=any,port=any,weight=0 group=0x58000002")
        apply_dpctl_mod(self, config, "flow-mod table=40,cmd=add,prio=401 eth_type=0x800,ip_dst=224.0.0.1 write:group=0x60058001 goto:60")

        input_pkt = simple_packet(
                '01 00 5e 01 01 01 00 00 00 00 00 aa 81 00 00 03 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 94 33 c0 a8 '
                '02 01 e0 00 00 01 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '01 00 5e 01 01 01 00 00 01 22 33 55 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7e 00 95 33 c0 a8 '
                '02 01 e0 00 00 01 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

        input_pkt = simple_packet(
                '01 00 5e 01 01 01 00 00 00 00 00 aa 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 94 33 c0 a8 '
                '02 01 e0 00 00 01 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '01 00 5e 01 01 01 00 00 02 22 33 55 81 00 00 03 '
                '08 00 45 00 00 4e 04 d2 00 00 7e 00 95 33 c0 a8 '
                '02 01 e0 00 00 01 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(output_port, str(input_pkt))
        verify_packet(self, str(output_pkt), input_port)


class test_v6(base_tests.SimpleDataPlane):
    """
    [PIM BIDR IPv4]
      PIM BIDR IPv4

    Inject  eth 1/3 tag 3, SA unknown, DA 333300224477, SIP 2015::1, DIP ff01::2, UDP proto
    Output  eth 1/1 tag 2, SA 000001223355, DA 333300224477, SIP 2015::1, DIP ff01::2

    Inject  eth 1/1 tag 2, SA unknown, DA 333300224477, SIP 2015::1, DIP ff01::2, UDP proto
    Output  eth 1/3 tag 3, SA 000002223355, DA 333300224477, SIP 2015::1, DIP ff01::2

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 eth_dst=33:33:00:22:44:77/ff:ff:00:00:00:00,eth_type=0x86dd goto:40
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x58000001 group=any,port=any,weight=0 set_field=eth_src=00:00:01:22:33:55,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x58000002 group=any,port=any,weight=0 set_field=eth_src=00:00:02:22:33:55,set_field=vlan_vid=3,group=0x30003
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=all,group=0x60058001 group=any,port=any,weight=0 group=0x58000001 group=any,port=any,weight=0 group=0x58000002
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=40,cmd=add,prio=401 eth_type=0x86dd,ipv6_dst=ff01::2 write:group=0x60058001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1002/0x00001fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x00001fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 eth_dst=33:33:00:22:44:77/ff:ff:00:00:00:00,eth_type=0x86dd goto:40")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x58000001 group=any,port=any,weight=0 set_field=eth_src=00:00:01:22:33:55,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x58000002 group=any,port=any,weight=0 set_field=eth_src=00:00:02:22:33:55,set_field=vlan_vid=3,group=0x3000"+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x60058001 group=any,port=any,weight=0 group=0x58000001 group=any,port=any,weight=0 group=0x58000002")
        apply_dpctl_mod(self, config, "flow-mod table=40,cmd=add,prio=401 eth_type=0x86dd,ipv6_dst=ff01::2 write:group=0x60058001 goto:60")

        input_pkt = simple_packet(
                '33 33 00 22 44 77 00 00 00 00 00 aa 81 00 00 03 '
                '86 dd 60 00 00 00 00 26 11 7f 20 15 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 ff 01 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 00 3f 00 41 00 26 '
                '71 8f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d '
                '0e 0f 10 11 12 13 14 15 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '33 33 00 22 44 77 00 00 01 22 33 55 81 00 00 02 '
                '86 dd 60 00 00 00 00 26 11 7e 20 15 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 ff 01 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 00 3f 00 41 00 26 '
                '71 8f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d '
                '0e 0f 10 11 12 13 14 15 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

        input_pkt = simple_packet(
                '33 33 00 22 44 77 00 00 00 00 00 aa 81 00 00 02 '
                '86 dd 60 00 00 00 00 26 11 7f 20 15 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 ff 01 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 00 3f 00 41 00 26 '
                '71 8f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d '
                '0e 0f 10 11 12 13 14 15 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '33 33 00 22 44 77 00 00 02 22 33 55 81 00 00 03 '
                '86 dd 60 00 00 00 00 26 11 7e 20 15 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 ff 01 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 00 3f 00 41 00 26 '
                '71 8f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d '
                '0e 0f 10 11 12 13 14 15 00 00 00 00 00 00 00 00')

        self.dataplane.send(output_port, str(input_pkt))
        verify_packet(self, str(output_pkt), input_port)
