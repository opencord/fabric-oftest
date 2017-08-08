
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


class l3ucast_route(base_tests.SimpleDataPlane):
    """
    [L3 unicast route]
      Do unicast route and output to specified port

    Inject  eth 1/3 Tag2, SA000000112233, DA7072cf7cf3a3, SIP 192.168.1.100, DIP 192.168.2.2
    Output  eth 1/1 Tag3, SA 000004223355, DA 000004224466

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=2/0xfff,eth_dst=70:72:cf:7c:f3:a3,eth_type=0x0800 goto:30
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20000003 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=3,group=0x30001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x20000003 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",eth_dst=70:72:cf:7c:f3:a3,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x20000003 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=3,group=0x3000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x20000003 goto:60")

        input_pkt = simple_packet(
                '70 72 cf 7c f3 a3 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 06 b2 7b c0 a8 '
                '01 0a c0 a8 02 02 00 03 00 06 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 2f 5d 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 03 '
                '08 00 45 00 00 4e 04 d2 00 00 7e 06 b3 7b c0 a8 '
                '01 0a c0 a8 02 02 00 03 00 06 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 2f 5d 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class l3ucast_route6(base_tests.SimpleDataPlane):
    """
    [L3 IPv6 unicast route]
      Do unicast route and output to specified port

    Inject  eth 1/3 Tag2, SA000000112233, DA7072cf7cf3a3, SIP 2014::2, DIP 2014::1
    Output  eth 1/1 Tag2, SA 000004223355, DA 000004224466

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=2/0xfff,eth_dst=70:72:cf:7c:f3:a3,eth_type=0x86dd goto:30
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x86dd,ipv6_dst=2014::1/64 write:group=0x20000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",eth_dst=70:72:cf:7c:f3:a3,eth_type=0x86dd goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x20000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x86dd,ipv6_dst=2014::1/64 write:group=0x20000001 goto:60")

        input_pkt = simple_packet(
                '70 72 cf 7c f3 a3 00 00 00 11 22 33 81 00 00 02 '
                '86 dd 60 00 00 00 00 08 11 7f 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 00 0d 00 07 00 08 '
                'bf 9f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '86 dd 60 00 00 00 00 08 11 7e 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 00 0d 00 07 00 08 '
                'bf 9f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class l3mcast_route(base_tests.SimpleDataPlane):
    """
    [L3 multicast route]
      Do multicast route and output to specified ports

    Inject  eth 1/3 Tag2, SA000000112233, DA01005E404477, SIP 192.168.1.100, DIP 224.0.2.2
    Output  eth 1/1 original

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 eth_dst=01:00:5e:40:44:77/ff:ff:ff:80:00:00,eth_type=0x0800 goto:40
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=all,group=0x60020001 group=any,port=any,weight=0 group=0x20001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=40,cmd=add,prio=401 eth_type=0x0800,ip_src=192.168.2.2,ip_dst=224.0.2.2,vlan_vid=2 write:group=0x60020001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 eth_dst=01:00:5e:40:44:77/ff:ff:ff:80:00:00,eth_type=0x0800 goto:40")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x60020001 group=any,port=any,weight=0 group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=40,cmd=add,prio=401 eth_type=0x0800,ip_src=192.168.2.2,ip_dst=224.0.2.2,vlan_vid=2 write:group=0x60020001 goto:60")

        input_pkt = simple_packet(
                '01 00 5e 40 44 77 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 84 91 ad c0 a8 '
                '02 02 e0 00 02 02 00 17 00 08 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 0e 79 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '01 00 5e 40 44 77 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 84 91 ad c0 a8 '
                '02 02 e0 00 02 02 00 17 00 08 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 0e 79 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class l3mcast_route6(base_tests.SimpleDataPlane):
    """
    [L3 IPv6 multicast route]
      Do multicast route and output to specified ports

    Inject  eth 1/5 Tag2, SA000000112233, DA333300224477, SIP 2014::2, DIP ff01::2
    Output  eth 1/1 Tag2, original
    Output  eth 1/3 Tag3, original

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=5,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 eth_dst=33:33:00:22:44:77/ff:ff:00:00:00:00,eth_type=0x86dd goto:40
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x50000003 group=any,port=any,weight=0 set_field=eth_src=00:00:05:22:33:99,set_field=vlan_vid=3,group=0x30003
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=all,group=0x60020001 group=any,port=any,weight=0 group=0x20001 group=any,port=any,weight=0 group=0x50000003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=40,cmd=add,prio=501 eth_type=0x86dd,ipv6_dst=ff01::2,vlan_vid=2 write:group=0x60020001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 eth_dst=33:33:00:22:44:77/ff:ff:00:00:00:00,eth_type=0x86dd goto:40")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(output_port2)+" group=any,port=any,weight=0 output="+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x50000003 group=any,port=any,weight=0 set_field=eth_src=00:00:05:22:33:99,set_field=vlan_vid=3,group=0x3000"+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x60020001 group=any,port=any,weight=0 group=0x2000"+str(output_port)+" group=any,port=any,weight=0 group=0x50000003")
        apply_dpctl_mod(self, config, "flow-mod table=40,cmd=add,prio=401 eth_type=0x86dd,ipv6_dst=ff01::2,vlan_vid=2 write:group=0x60020001 goto:60")

        input_pkt = simple_packet(
                '33 33 00 22 44 77 00 00 00 11 22 33 81 00 00 02 '
                '86 dd 60 00 00 00 00 26 3b 7f 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 ff 01 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '33 33 00 22 44 77 00 00 00 11 22 33 81 00 00 02 '
                '86 dd 60 00 00 00 00 26 3b 7f 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 ff 01 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '33 33 00 22 44 77 00 00 05 22 33 99 81 00 00 03 '
                '86 dd 60 00 00 00 00 26 3b 7e 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 ff 01 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        verify_packet(self, str(output_pkt2), output_port2)


class bridge_ucast(base_tests.SimpleDataPlane):
    """
    [Bridge unicast]
      Do unicast bridge

    Inject  eth 1/1 Tag2, SA000000112233, DA000000224477, SIP 192.168.2.1, DIP 192.168.2.2
    Output  eth 1/3 untag

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 pop_vlan,output=3
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=2,eth_dst=00:00:00:22:44:77 write:group=0x20003 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 pop_vlan,output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=2,eth_dst=00:00:00:22:44:77 write:group=0x2000"+str(output_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 00 22 44 77 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 b1 8a c0 a8 '
                '02 01 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 22 44 77 00 00 00 11 22 33 08 00 45 00 '
                '00 4e 04 d2 00 00 7f 00 b1 8a c0 a8 02 01 c0 a8 '
                '02 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class bridge_mcast(base_tests.SimpleDataPlane):
    """
    [Bridge multicast]
      Do multicast bridge

    Inject  eth 1/5 Tag2, SA000000112233, DA110000224477, SIP 192.168.2.1, DIP 192.168.2.2
    Output  eth 1/1 Tag2, SA000000112233, DA110000224477, SIP 192.168.2.1, DIP 192.168.2.2
    Output  eth 1/3 untag

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=5,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 pop_vlan,output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=all,group=0x30020001 group=any,port=any,weight=0 group=0x20001 group=any,port=any,weight=0 group=0x20003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=601 vlan_vid=2,eth_dst=11:00:00:22:44:77 write:group=0x30020001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port2)+" group=any,port=any,weight=0 pop_vlan,output="+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x30020001 group=any,port=any,weight=0 group=0x2000"+str(output_port)+" group=any,port=any,weight=0 group=0x2000"+str(output_port2))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=2,eth_dst=11:00:00:22:44:77 write:group=0x30020001 goto:60")

        input_pkt = simple_packet(
                '11 00 00 22 44 77 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 b1 8a c0 a8 '
                '02 01 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '11 00 00 22 44 77 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 b1 8a c0 a8 '
                '02 01 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '11 00 00 22 44 77 00 00 00 11 22 33 08 00 45 00 '
                '00 4e 04 d2 00 00 7f 00 b1 8a c0 a8 02 01 c0 a8 '
                '02 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        verify_packet(self, str(output_pkt2), output_port2)


class bridge_dlf(base_tests.SimpleDataPlane):
    """
    [Bridge DLF]
      Do DLF bridge

    Inject  eth 1/5 Tag2, SA000000112233, DA110000224466, SIP 192.168.2.1, DIP 192.168.2.2
    Output  eth 1/1 Tag2, SA000000112233, DA110000224477, SIP 192.168.2.1, DIP 192.168.2.2
    Output  eth 1/3 untag

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=5,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 pop_vlan,output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=all,group=0x40020001 group=any,port=any,weight=0 group=0x20001 group=any,port=any,weight=0 group=0x20003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=601 vlan_vid=2 write:group=0x40020001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port2)+" group=any,port=any,weight=0 pop_vlan,output="+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x40020001 group=any,port=any,weight=0 group=0x2000"+str(output_port)+" group=any,port=any,weight=0 group=0x2000"+str(output_port2))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=601 vlan_vid=2 write:group=0x40020001 goto:60")

        input_pkt = simple_packet(
                '00 00 00 22 44 66 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 b1 8a c0 a8 '
                '02 01 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 22 44 66 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 b1 8a c0 a8 '
                '02 01 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '00 00 00 22 44 66 00 00 00 11 22 33 08 00 45 00 '
                '00 4e 04 d2 00 00 7f 00 b1 8a c0 a8 02 01 c0 a8 '
                '02 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        verify_packet(self, str(output_pkt2), output_port2)

