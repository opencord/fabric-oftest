
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


class dnat(base_tests.SimpleDataPlane):
    """
    [DNAT]
      DNAT (inbound)

    Inject  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 200.0.0.1, DIP 100.0.0.01, Sport 2828, Dport 5000
    Output  eth 1/1 DA000000000101, SA000000000100, Tag 100, SIP 200.0.0.1, DIP 10.0.0.01, Sport 2828, Dport 2000

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x10c8/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x640001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x640001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x23000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x10c8/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x64000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x64000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28")
        apply_dpctl_mod(self, config, "flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x23000001 goto:60")

        input_pkt = simple_packet(
                '00 00 00 00 02 00 00 00 00 00 02 01 81 00 00 c8 '
                '08 00 45 00 00 2a 04 d2 00 00 7f 06 0a fa c8 00 '
                '00 01 64 00 00 01 0b 0c 13 88 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 69 50 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 00 01 01 00 00 00 00 01 00 81 00 00 64 '
                '08 00 45 00 00 2a 04 d2 00 00 7e 06 65 fa c8 00 '
                '00 01 0a 00 00 01 0b 0c 07 d0 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 cf 08 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class dnat_vrf(base_tests.SimpleDataPlane):
    """
    [DNAT VRF]
      DNAT (inbound) with specified VRF

    Inject  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 200.0.0.1, DIP 100.0.0.01, Sport 2828, Dport 5000
    Output  eth 1/1 DA000000000101, SA000000000100, Tag 100, SIP 200.0.0.1, DIP 10.0.0.01, Sport 2828, Dport 2000

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x10c8/0x1fff goto:20 apply:set_field=ofdpa_vrf:3
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1064/0x1fff goto:20 apply:set_field=ofdpa_vrf:3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x640001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x640001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000,ofdpa_vrf=3 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x23000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x10c8/0x1fff goto:20 apply:set_field=ofdpa_vrf:3")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1064/0x1fff goto:20 apply:set_field=ofdpa_vrf:3")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x64000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x64000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28")
        apply_dpctl_mod(self, config, "flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000,ofdpa_vrf=3 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x23000001 goto:60")

        input_pkt = simple_packet(
                '00 00 00 00 02 00 00 00 00 00 02 01 81 00 00 c8 '
                '08 00 45 00 00 2a 04 d2 00 00 7f 06 0a fa c8 00 '
                '00 01 64 00 00 01 0b 0c 13 88 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 69 50 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 00 01 01 00 00 00 00 01 00 81 00 00 64 '
                '08 00 45 00 00 2a 04 d2 00 00 7e 06 65 fa c8 00 '
                '00 01 0a 00 00 01 0b 0c 07 d0 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 cf 08 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

"""
currently this case will fail, due to packet rx SRC IP problem
"""
class dnat_ecmp(base_tests.SimpleDataPlane):
    """
    [DNAT ECMP]
      DNAT (inbound) with ECMP

    Inject  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 200.0.0.1, DIP 100.0.0.01, Sport 2828, Dport 5000 [increase SIP]
    Output  eth 1/1 DA000000000101, SA000000000100, Tag 100, SIP 200.0.0.X, DIP 10.0.0.01, Sport 2828, Dport 2000
    Output  eth 1/5 DA000005224466, SA000005223355, Tag 2, SIP 200.0.0.X, DIP 10.0.0.01, Sport 2828, Dport 2000

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x10c8/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x640001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x640001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20005 group=any,port=any,weight=0 output=5
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x23000005 group=any,port=any,weight=0 set_field=eth_src=00:00:05:22:33:55,set_field=eth_dst=00:00:05:22:44:66,set_field=vlan_vid=2,group=0x20005
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=sel,group=0x71000001 group=any,port=any,weight=0 group=0x23000001 group=any,port=any,weight=0 group=0x23000005
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x71000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x10c8/0x1fff goto:20 apply:set_field=ofdpa_vrf:3")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x64000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x64000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port2)+" group=any,port=any,weight=0 output="+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x23000005 group=any,port=any,weight=0 set_field=eth_src=00:00:05:22:33:55,set_field=eth_dst=00:00:05:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=sel,group=0x71000001 group=any,port=any,weight=0 group=0x23000001 group=any,port=any,weight=0 group=0x23000005")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28")
        apply_dpctl_mod(self, config, "flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x71000001 goto:60")

        #increased SIP
        input_pkt = simple_packet(
                '00 00 00 00 02 00 00 00 00 00 02 01 81 00 00 c8 '
                '08 00 45 00 00 2a 04 d2 00 00 7f 06 0a fa c8 00 '
                '00 01 64 00 00 01 0b 0c 13 88 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 69 50 00 00 00 00')

        #random SIP
        output_pkt = simple_packet(
                '00 00 00 00 01 01 00 00 00 00 01 00 81 00 00 64 '
                '08 00 45 00 00 2a 04 d2 00 00 7e 06 65 ee c8 00 '
                '00 0d 0a 00 00 01 0b 0c 07 d0 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 ce fc 00 00 00 00')

        #random SIP
        output_pkt2 = simple_packet(
                '00 00 05 22 44 66 00 00 05 22 33 55 81 00 00 02 '
                '08 00 45 00 00 2a 04 d2 00 00 7e 06 65 ef c8 00 '
                '00 0c 0a 00 00 01 0b 0c 07 d0 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 ce fd 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt2), output_port2)


class dnat_decap_mpls(base_tests.SimpleDataPlane):
    """
    [Decap MPLS label and DNAT]
      Decap MPLS label and DNAT

    Inject  eth 1/3 Tag 12, SA000000112233, DA000000000111, MPLS 0x1234, SIP 200.0.0.1, DIP 100.0.0.1
    Output  eth 1/1 DA000000000101, SA000000000100, Tag 100, SIP 200.0.0.1, DIP 10.0.0.01

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x640001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x640001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x100c/0x1fff apply:set_field=ofdpa_vrf:1 goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=12/0xfff,eth_dst=00:00:00:00:01:11,eth_type=0x8847 goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x1234,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ofdpa_vrf=1 write:set_field=ip_dst:10.0.0.1,group=0x23000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x64000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x64000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x100c/0x1fff apply:set_field=ofdpa_vrf:1 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=12/0xfff,eth_dst=00:00:00:00:01:11,eth_type=0x8847 goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x1234,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ofdpa_vrf=1 write:set_field=ip_dst:10.0.0.1,group=0x23000001 goto:60")

        input_pkt = simple_packet(
                '00 00 00 00 01 11 00 00 00 11 22 33 81 00 00 0c '
                '88 47 01 23 41 3f 45 00 00 26 00 00 00 00 3f 00 '
                '4f d6 c8 00 00 01 64 00 00 01 00 01 02 03 04 05 '
                '06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 '
                '16 17 18 19')

        output_pkt = simple_packet(
                '00 00 00 00 01 01 00 00 00 00 01 00 81 00 00 64 '
                '08 00 45 00 00 26 00 00 00 00 3e 00 aa d6 c8 00 '
                '00 01 0a 00 00 01 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class snat(base_tests.SimpleDataPlane):
    """
    [SNAT]
      SNAT (outbound)

    Inject  eth 1/1 DA000000000100, SA000000000101, Tag 100, SIP 10.0.0.1, DIP 200.0.0.01, Sport 2000, Dport 2828
    Output  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 100.0.0.1, DIP 200.0.0.01, Sport 5000, Dport 2828

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1064/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=100/0xfff,eth_dst=00:00:00:00:01:00,eth_type=0x0800 goto:29
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0xC80003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x22000002 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:02:00,set_field=eth_dst=00:00:00:00:02:01,set_field=vlan_vid=200,group=0xC80003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=29,cmd=add,prio=291 eth_type=0x800,ip_src=10.0.0.1,ip_proto=6,tcp_src=2000 write:set_field=ip_src:100.0.0.1,set_field=tcp_src:5000 goto:30
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=200.0.0.1/255.255.255.0 write:group=0x22000002 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1064/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=100/0xfff,eth_dst=00:00:00:00:01:00,eth_type=0x0800 goto:29")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xC8000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x22000002 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:02:00,set_field=eth_dst=00:00:00:00:02:01,set_field=vlan_vid=200,group=0xC8000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=29,cmd=add,prio=291 eth_type=0x800,ip_src=10.0.0.1,ip_proto=6,tcp_src=2000 write:set_field=ip_src:100.0.0.1,set_field=tcp_src:5000 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=200.0.0.1/255.255.255.0 write:group=0x22000002 goto:60")

        input_pkt = simple_packet(
                '00 00 00 00 01 00 00 00 00 00 02 00 81 00 00 64 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 06 64 f6 0a 00 '
                '00 01 c8 00 00 01 07 d0 0b 0c 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 cf 04 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 00 02 01 00 00 00 00 02 00 81 00 00 c8 '
                '08 00 45 00 00 2e 04 d2 00 00 7e 06 0b f6 64 00 '
                '00 01 c8 00 00 01 13 88 0b 0c 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 69 4c 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class snat_vrf(base_tests.SimpleDataPlane):
    """
    [SNAT VRF]
      SNAT (outbound) with specified VRF

    Inject  eth 1/1 DA000000000100, SA000000000101, Tag 100, SIP 10.0.0.1, DIP 200.0.0.01, Sport 2000, Dport 2828
    Output  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 100.0.0.1, DIP 200.0.0.01, Sport 5000, Dport 2828

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1064/0x1fff goto:20 apply:set_field=ofdpa_vrf:3
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x10c8/0x1fff goto:20 apply:set_field=ofdpa_vrf:3
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=100/0xfff,eth_dst=00:00:00:00:01:00,eth_type=0x0800 goto:29
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0xC80003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x22000002 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:02:00,set_field=eth_dst=00:00:00:00:02:01,set_field=vlan_vid=200,group=0xC80003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=29,cmd=add,prio=291 eth_type=0x800,ip_src=10.0.0.1,ip_proto=6,tcp_src=2000,ofdpa_vrf=3 write:set_field=ip_src:100.0.0.1,set_field=tcp_src:5000 goto:30
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=200.0.0.1/255.255.255.0,ofdpa_vrf=3 write:group=0x22000002 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1064/0x1fff goto:20 apply:set_field=ofdpa_vrf:3")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x10c8/0x1fff goto:20 apply:set_field=ofdpa_vrf:3")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=100/0xfff,eth_dst=00:00:00:00:01:00,eth_type=0x0800 goto:29")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xC8000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x22000002 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:02:00,set_field=eth_dst=00:00:00:00:02:01,set_field=vlan_vid=200,group=0xC8000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=29,cmd=add,prio=291 eth_type=0x800,ip_src=10.0.0.1,ip_proto=6,tcp_src=2000,ofdpa_vrf=3 write:set_field=ip_src:100.0.0.1,set_field=tcp_src:5000 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=200.0.0.1/255.255.255.0,ofdpa_vrf=3 write:group=0x22000002 goto:60")

        input_pkt = simple_packet(
                '00 00 00 00 01 00 00 00 00 00 02 00 81 00 00 64 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 06 64 f6 0a 00 '
                '00 01 c8 00 00 01 07 d0 0b 0c 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 cf 04 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 00 02 01 00 00 00 00 02 00 81 00 00 c8 '
                '08 00 45 00 00 2e 04 d2 00 00 7e 06 0b f6 64 00 '
                '00 01 c8 00 00 01 13 88 0b 0c 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 69 4c 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

"""
currently this case will fail, due to packet rx src IP problem
"""
class snat_ecmp(base_tests.SimpleDataPlane):
    """
    [SNAT ECMP]
      SNAT (outbound) with ECMP

    Inject  eth 1/1 DA000000000100, SA000000000101, Tag 100, SIP 10.0.0.1, DIP 200.0.0.01, Sport 2000, Dport 2828 [increase DIP]
    Output  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 100.0.0.1, DIP 200.0.0.X, Sport 5000, Dport 2828
    Output  eth 1/5 DA000000000500, SA000000000501, Tag 5, SIP 100.0.0.1, DIP 200.0.0.X, Sport 5000, Dport 2828

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1064/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=100/0xfff,eth_dst=00:00:00:00:01:00,eth_type=0x0800 goto:29
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0xC80003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x22000002 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:02:00,set_field=eth_dst=00:00:00:00:02:01,set_field=vlan_vid=200,group=0xC80003
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x50005 group=any,port=any,weight=0 output=5
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x22000005 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:05:00,set_field=eth_dst=00:00:00:00:05:01,set_field=vlan_vid=5,group=0x50005
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=sel,group=0x71000001 group=any,port=any,weight=0 group=0x22000002 group=any,port=any,weight=0 group=0x22000005
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=29,cmd=add,prio=291 eth_type=0x800,ip_src=10.0.0.1,ip_proto=6,tcp_src=2000 write:set_field=ip_src:100.0.0.1,set_field=tcp_src:5000 goto:30
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=200.0.0.1/255.255.255.0 write:group=0x71000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1064/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=100/0xfff,eth_dst=00:00:00:00:01:00,eth_type=0x0800 goto:29")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xC8000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x22000002 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:02:00,set_field=eth_dst=00:00:00:00:02:01,set_field=vlan_vid=200,group=0xC8000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x5000"+str(output_port2)+" group=any,port=any,weight=0 output="+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x22000005 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:05:00,set_field=eth_dst=00:00:00:00:05:01,set_field=vlan_vid=5,group=0x5000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=sel,group=0x71000001 group=any,port=any,weight=0 group=0x22000002 group=any,port=any,weight=0 group=0x22000005")
        apply_dpctl_mod(self, config, "flow-mod table=29,cmd=add,prio=291 eth_type=0x800,ip_src=10.0.0.1,ip_proto=6,tcp_src=2000 write:set_field=ip_src:100.0.0.1,set_field=tcp_src:5000 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=200.0.0.1/255.255.255.0 write:group=0x71000001 goto:60")

        #increased DIP
        input_pkt = simple_packet(
                '00 00 00 00 01 00 00 00 00 00 02 00 81 00 00 64 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 06 64 f6 0a 00 '
                '00 01 c8 00 00 01 07 d0 0b 0c 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 cf 04 00 00 00 00 00 00 00 00')

        #rnadom DIP
        output_pkt = simple_packet(
                '00 00 00 00 02 01 00 00 00 00 02 00 81 00 00 c8 '
                '08 00 45 00 00 2e 04 d2 00 00 7e 06 0b e8 64 00 '
                '00 01 c8 00 00 0f 13 88 0b 0c 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 69 3e 00 00 00 00 00 00 00 00')

        #rnadom DIP
        output_pkt2 = simple_packet(
                '00 00 00 00 05 01 00 00 00 00 05 00 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7e 06 0b f4 64 00 '
                '00 01 c8 00 00 03 13 88 0b 0c 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 69 4a 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt2), output_port2)
