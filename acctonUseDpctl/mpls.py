
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
import time
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr

class encap_mpls(base_tests.SimpleDataPlane):
    """
    [Encap one MPLS label]
      Encap a MPLS label

    Inject  eth 1/3 Tag 3, SA000000112233, DA000000113355, V4
    Output  eth 1/1 Tag 2, SA000004223355, DA000004224466, MPLS label 2305, EXP7, BoS1, TTL250, CW

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3 apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(output_port)+" goto:60")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+" apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(output_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 03 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b2 47 c0 a8 01 64 c0 a8 02 02 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_mpls(base_tests.SimpleDataPlane):
    """
    [Decap one MPLS label]
      Decap the MPLS label

    Inject  eth 1/1 Tag 2, SA000004223355, DA000004224466, MPLS label 2305, EXP7, BoS1, TTL250, CW, InSA000000112233, InDA000000113355
    Output  eth 1/3 SA000000112233, DA000000113355

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3 apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(input_port)+" goto:60")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+" apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 '
                '00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class encap_2mpls(base_tests.SimpleDataPlane):
    """
    [Encap two MPLS labels]
      Encap two MPLS labels

    Inject  eth 1/3 Tag 3, SA000000112233, DA000000113355
    Output  eth 1/1 Tag 2, Outer label 0x903, TTL 250, InLabel 0x901, TTL 250, SA000004223355, DA000004224466

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(output_port)+" goto:60")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class encap_3mpls(base_tests.SimpleDataPlane):
    """
    [Encap 3 MPLS labels]
      Encap 3 MPLS labels

    Inject  eth 1/3 Tag 3, SA000000112233, DA000000113355
    Output  eth 1/1 Tag 2, Outest label 0x904, TTL 250, Middle label 0x903, InLabel 0x901, SA000004223355, DA000004224466

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x94000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x904,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x94000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(output_port)+" goto:60")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x94000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x904,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x94000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 4e fa 00 90 3e fa 00 90 1f fa 00 00 '
                '00 00 00 00 00 11 33 55 00 00 00 11 22 33 81 00 '
                '00 03 08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 '
                'c0 a8 01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_penultimate_mpls(base_tests.SimpleDataPlane):
    """
    [Penultimate Hop Pop]
      Pop outermost tunnel label

    Inject  eth 1/1 Tag 2, Outer label 0x901, InLabel 0xF, SA000004223355, DA000004224466
    Output  eth 1/3 Tag 2, label 0xF, SA000004223355, DA000004224466

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901 apply:pop_mpls=0x8847,mpls_dec write:group=0x90000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901 apply:pop_mpls=0x8847,mpls_dec write:group=0x90000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1e fa 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 01 0f f9 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_2mpls(base_tests.SimpleDataPlane):
    """
    [Pop, decap, and L2 forward]
      Pop outermost tunnel label and pop outer L2 header (L2 Switch VPWS )

    Inject  eth 1/1 Tag 2, Outer label 0x903, InLabel 0x901, SA000004223355, DA000004224466; InTag 5, InSA000000112233, InDA000000113355
    Output  eth 1/3 Tag 5, SA000000112233, DA000000113355

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x00008847 goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x00008847 goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(input_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_penultimate_swap_mpls(base_tests.SimpleDataPlane):
    """
    [Penultimate Hop Pop and swap inner MPLS label]
      Pop outermost tunnel label and swap inner MPLS label (MS-PW, LSR)

    Inject  eth 1/1 Tag 2, Outer label 0x903, InLabel 0x901, SA000004223355, DA000004224466; InTag 5, InSA000000112233, InDA000000113355
    Output  eth 1/3 Tag 2, Label 0x905, TTL 249, SA000004223355, DA000004224466

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x905,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:mpls_dec write:group=0x95000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x905,group=0x90000001")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:mpls_dec write:group=0x95000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 51 f9 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)



class swap_out_mpls(base_tests.SimpleDataPlane):
    """
    [Swap outermost MPLS label]
      Swap outermost MPLS label (LSR)

    Inject  eth 1/1 Tag 2, Outer label 0x901, TTL 250, InLabel 0xF, DA000004223355, SA000004224466
    Output  eth 1/3 Tag 2, Outer label 0x9051, TTL 249, InLabel 0xF, SA000004223357, DA000004224467

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:57,set_field=eth_dst=00:00:04:22:44:67,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x9051,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901 apply:mpls_dec write:group=0x95000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:57,set_field=eth_dst=00:00:04:22:44:67,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x9051,group=0x90000001")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901 apply:mpls_dec write:group=0x95000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1e fa 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt = simple_packet(
                '00 00 04 22 44 67 00 00 04 22 33 57 81 00 00 02 '
                '88 47 09 05 10 f9 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)



class swap_encap_mpls(base_tests.SimpleDataPlane):
    """
    [Swap and encap a MPLS label]
      Swap and encap a MPLS label

    Inject  eth 1/1 Tag 2, MPLS label 0x901, TTL 250, DA000004223355, SA000004224466
    Output  eth 1/3 Tag 2, Outer label 0x9052, TTL 249, InLabel 0xF, SA000004223358, DA000004224468

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:58,set_field=eth_dst=00:00:04:22:44:68,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x9052,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:mpls_dec write:group=0x95000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:58,set_field=eth_dst=00:00:04:22:44:68,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x9052,group=0x90000001")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:mpls_dec write:group=0x95000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 68 00 00 04 22 33 58 81 00 00 02 '
                '88 47 09 05 21 f9 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class swap_encap_2mpls(base_tests.SimpleDataPlane):
    """
    [Swap and encap 2 MPLS labels]
      Swap and encap 2 MPLS labels

    Inject  eth 1/1 Tag 2, MPLS label 0x901, TTL 250, DA000004223355, SA000004224466
    Output  eth 1/3 Tag 2, Outest label 0x904, TTL 249, Middle label 0x903, InLabel 0x9052, SA000004223358, DA000004224468

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:58,set_field=eth_dst=00:00:04:22:44:68,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x94000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x904,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x94000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x9052,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:mpls_dec write:group=0x95000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:58,set_field=eth_dst=00:00:04:22:44:68,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x94000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x904,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x94000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x9052,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:mpls_dec write:group=0x95000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 68 00 00 04 22 33 58 81 00 00 02 '
                '88 47 00 90 40 f9 00 90 30 f9 09 05 21 f9 00 00 '
                '00 00 00 00 00 11 33 55 00 00 00 11 22 33 81 00 '
                '00 05 08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa '
                'c0 a8 02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 '
                '08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 '
                '18 19 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_1mpls_of3(base_tests.SimpleDataPlane):
    """
    [Decap outermost MPLS label of 3 MPLS labels]
      Decap outermost one MPLS of 3 MPLS labels

    Inject  eth 1/1 Tag 2, Outest label 0x904, TTL 250, Middle label 0x903/250, InLabel 0x901/250, SA000004224466, DA000004223355
    Output  eth 1/3 Tag 2, Outer label 0x903/249, InLabel 0x901/250, SA000004223355, DA000004224466

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x904 apply:pop_mpls=0x8847,mpls_dec write:group=0x90000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x904 apply:pop_mpls=0x8847,mpls_dec write:group=0x90000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 4e fa 00 90 3e fa 00 90 1f fa 00 00 '
                '00 00 00 00 00 11 33 55 00 00 00 11 22 33 00 00 '
                '00 03 08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa '
                'c0 a8 02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 '
                '08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 '
                '18 19')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e f9 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 00 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_2mpls_of3(base_tests.SimpleDataPlane):
    """
    [Decap outermost 2 MPLS labels of 3 MPLS labels]
      Decap outermost two MPLS of 3 MPLS labels

    Inject  eth 1/1 Tag 2, Outest label 0x904, TTL 250, Middle label 0x903/250, InLabel 0x901/250, SA000004224466, DA000004223355
    Output  eth 1/3 Tag 2, MPLS Label 0x901/249, SA000004223355, DA000004224466

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x904 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec write:group=0x90000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x904 apply:pop_mpls=0x8847,mpls_dec goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec write:group=0x90000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 4e fa 00 90 3e fa 00 90 1f fa 00 00 '
                '00 00 00 00 00 11 33 55 00 00 00 11 22 33 00 00 '
                '00 03 08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa '
                'c0 a8 02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 '
                '08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 '
                '18 19')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 1f f9 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 00 00 00 03 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class encap_2mpls_ff(base_tests.SimpleDataPlane):
    """
    [Encap two MPLS labels with FF]
      Encap two MPLS labels with fast failover group

    Env eth 1/1 link up; eth 1/5 link down
    Inject  eth 1/3 Tag 3, SA000000112233, DA000000113355
    Output  eth 1/1 Tag 2, Outest label 0x931, TTL 250, InLabel 0x901, SA000004223351, DA000004224461

    Env eth 1/1 link down; eth 1/5 link up
    Inject  eth 1/3 Tag 3, SA000000112233, DA000000113355
    Output  eth 1/5 Tag 2, Outest label 0x935, TTL 250, InLabel 0x901, SA000004223355, DA000004224465

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:51,set_field=eth_dst=00:00:04:22:44:61,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x931,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20005 group=any,port=any,weight=0 output=5
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000005 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:65,set_field=vlan_vid=2,group=0x20005
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000005 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x935,group=0x90000005
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ff,group=0xA6000001 group=any,port=1,weight=0 group=0x93000001 group=any,port=5,weight=0 group=0x93000005
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0xA6000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]
        
        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:51,set_field=eth_dst=00:00:04:22:44:61,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x931,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port2)+" group=any,port=any,weight=0 output="+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000005 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:65,set_field=vlan_vid=2,group=0x2000"+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000005 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x935,group=0x90000005")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ff,group=0xA6000001 group=any,port="+str(output_port)+",weight=0 group=0x93000001 group=any,port="+str(output_port2)+",weight=0 group=0x93000005")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0xA6000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(output_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '00 00 04 22 44 65 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 93 5e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

        #if output_port link down
        apply_dpctl_mod(self, config, "port-mod port="+str(output_port)+",conf=0x1,mask=0x1")
        time.sleep(1)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt2), output_port2)
        apply_dpctl_mod(self, config, "port-mod port="+str(output_port)+",conf=0x0,mask=0x1")
        #make sure port link up        
        port_up = 0
        while port_up == 0:
            time.sleep(1)
            #apply_dpctl_mod(self, config, "port-mod port="+str(output_port)+",conf=0x0,mask=0x1")
            json_result = apply_dpctl_get_cmd(self, config, "port-desc")
            result=json_result["RECEIVED"][1]
            for p_desc in result["port"]:
                if p_desc["no"] == output_port:
                    if p_desc["config"] != 0x01 : #up                        
                        port_up = 1
                                


class decap_mpls_acl(base_tests.SimpleDataPlane):
    """
    [Decap a MPLS label with ACL]
      Decap a MPLS label with ACL

    Inject  eth 1/1 Tag 2, SA000004223355, DA000004224466, MPLS label 2305, EXP7, BoS1, TTL250, CW, InSA000000112233, InDA000000113355
    Output  eth 1/5 SA000000112233, DA000000113355

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3 apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20005 group=any,port=any,weight=0 output=5
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 tunn_id=0x10001,ofdpa_mpls_l2_port=131328 write:group=0x20005
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(input_port)+" goto:60")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+" apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 tunn_id=0x10001,ofdpa_mpls_l2_port=131328 write:group=0x2000"+str(output_port))

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 '
                '00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class encap_mpls_l3(base_tests.SimpleDataPlane):
    """
    [Encap a MPLS label with L3]
      Encap a MPLS label with L3 routing

    Inject  eth 1/3 Tag 2, SA000000112233, DA000000113355, SIP 192.168.1.10, DIP 192.168.2.2
    Output  eth 1/1 SA000004223355, DA000004224466, Tag2, MPLS label 0x901; IP the same as original

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x92000001 goto:60
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
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0x90000001")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x92000001 goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 b0 81 c0 a8 '
                '03 0a c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 1f fa 45 00 00 4e 04 d2 00 00 7e 00 '
                'b1 81 c0 a8 03 0a c0 a8 02 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_mpls_l3(base_tests.SimpleDataPlane):
    """
    [Decap a MPLS label with L3]
      Decap a MPLS label with L3 routing

    Inject  eth 1/3 Tag 12, SA000000112233, DA000000000111, MPLS 0x1234, SIP 192.168.3.1, DIP 192.168.2.1
    Output  eth 1/1 Tag 10, SA000006223355, DA000006224466, SIP 192.168.3.1, DIP 192.168.2.1

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x100c/0x1fff apply:set_field=ofdpa_vrf:1 goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0xa0001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20000001 group=any,port=any,weight=0 set_field=eth_src=00:00:06:22:33:55,set_field=eth_dst=00:00:06:22:44:66,set_field=vlan_vid=10,group=0xa0001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x1234,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.3.2/255.255.255.0,ofdpa_vrf=1 write:group=0x20000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=12/0xfff,eth_dst=00:00:00:00:01:11,eth_type=0x8847 goto:24
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x100c/0x1fff apply:set_field=ofdpa_vrf:1 goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xa000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x20000001 group=any,port=any,weight=0 set_field=eth_src=00:00:06:22:33:55,set_field=eth_dst=00:00:06:22:44:66,set_field=vlan_vid=10,group=0xa000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x1234,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.3.2/255.255.255.0,ofdpa_vrf=1 write:group=0x20000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=12/0xfff,eth_dst=00:00:00:00:01:11,eth_type=0x8847 goto:24")

        input_pkt = simple_packet(
                '00 00 00 00 01 11 00 00 00 11 22 33 81 00 00 0c '
                '88 47 01 23 41 3f 45 00 00 26 00 00 00 00 3f 00 '
                'f5 84 c0 a8 02 01 c0 a8 03 02 00 01 02 03 04 05 '
                '06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 '
                '16 17 18 19')

        output_pkt = simple_packet(
                '00 00 06 22 44 66 00 00 06 22 33 55 81 00 00 0a '
                '08 00 45 00 00 26 00 00 00 00 3e 00 f6 84 c0 a8 '
                '02 01 c0 a8 03 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class encap_2mpls_l3(base_tests.SimpleDataPlane):
    """
    [Encap two MPLS labels with L3]
      Encap two MPLS labels with L3 routing

    Inject  eth 1/3 Tag 2, SA000000112233, DA000000113355, SIP 192.168.1.10, DIP 192.168.2.2
    Output  eth 1/1 SA000004223355, DA000004224466, Tag2, Outer Label 0x903, EXP 7, TTL 250, Inner Label 0x901, EXP 7, TTL 250; IP the same as original

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x92000001 goto:60
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
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x92000001 goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 b0 81 c0 a8 '
                '03 0a c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 04 d2 '
                '00 00 7e 00 b1 81 c0 a8 03 0a c0 a8 02 02 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_2mpls_l3(base_tests.SimpleDataPlane):
    """
    [Decap two MPLS labels with L3]
      Decap two MPLS labels with L3 routing

    Inject  eth 1/1 SA000004223355, DA000004224466, Tag2, Outer Label 0x903, EXP 7, TTL 250, Inner Label 0x901, SIP 192.168.3.2, DIP 192.168.2.10
    Output  eth 1/3 SA000006223355, DA000006224466, Tag2, SIP 192.168.3.2, DIP 192.168.2.10

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20000003 group=any,port=any,weight=0 set_field=eth_src=00:00:06:22:33:55,set_field=eth_dst=00:00:06:22:44:66,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff apply:set_field=ofdpa_vrf:1 goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0,ofdpa_vrf=1 write:group=0x20000003 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x20000003 group=any,port=any,weight=0 set_field=eth_src=00:00:06:22:33:55,set_field=eth_dst=00:00:06:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff apply:set_field=ofdpa_vrf:1 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0,ofdpa_vrf=1 write:group=0x20000003 goto:60")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 26 00 00 '
                '00 00 7e 06 b6 75 c0 a8 03 02 c0 a8 02 0a 00 03 '
                '00 06 00 01 f7 fa 00 00 00 00 50 00 04 00 2f 5d '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 06 22 44 66 00 00 06 22 33 55 81 00 00 02 '
                '08 00 45 00 00 26 00 00 00 00 f9 06 3b 75 c0 a8 '
                '03 02 c0 a8 02 0a 00 03 00 06 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 2f 5d 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class encap_3mpls_l3(base_tests.SimpleDataPlane):
    """
    [Encap 3 MPLS labels with L3]
      Encap 3 MPLS labels with L3 routing

    Inject  eth 1/3 Tag 2, SA000000112233, DA000000113355, SIP 192.168.1.10, DIP 192.168.2.2
    Output  eth 1/1 SA000004223355, DA000004224466, Tag2, OuterLabel 0x904 EXP 7, TTL 250, M 0x903, Inner0x901, EXP 7, TTL 250; IP the same as original

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x94000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x904,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x94000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x92000001 goto:60
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
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x94000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x904,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x94000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x92000001 goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 00 b0 81 c0 a8 '
                '03 0a c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 4e fa 00 90 3e fa 00 90 1f fa 45 00 '
                '00 4e 04 d2 00 00 7e 00 b1 81 c0 a8 03 0a c0 a8 '
                '02 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

