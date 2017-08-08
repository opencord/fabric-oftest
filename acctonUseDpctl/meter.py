
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
Not verify yet, need to think how to verify meter
"""

class dscp(base_tests.SimpleDataPlane):
    """
    [DSCP meter]
      DSCP meter

    Inject  eth 1/3 {DA000000113355, SA000000112233, Tag 2} pkt [100* 10 pkt/sec]
    Output  eth 1/1 [10] no change

    Inject  eth 1/3 {DA000000113355, SA000000112233, Tag 2} pkt [100 bytes, 10 burst]
    Output  eth 1/1 [8] no change; [2] dscp 2

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 meter-mod cmd=add,flags=0x06,meter=1 dscp_remark:rate=5,prec_level=2,burst=5
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x20001 meter:1
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "meter-mod cmd=add,flags=0x06,meter=1 dscp_remark:rate=5,prec_level=2,burst=5")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x2000"+str(output_port)+" meter:1")

        input_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      ip_src=toIpV4Str(0xc0a80164),
                                      ip_dst=toIpV4Str(0xc0a80202),
                                      dl_vlan_enable=True,
                                      vlan_vid=2)

        output_pkt = input_pkt

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class drop(base_tests.SimpleDataPlane):
    """
    [Drop meter]
        Drop meter

    Inject  eth 1/3 {DA000000113355, SA000000112233, Tag 2} pkt [100 bytes, 10 pkt/sec]
    Output  eth 1/1 [8] output

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 meter-mod cmd=add,flags=0x01,meter=1 drop:rate=8
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x20001 meter:1
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "meter-mod cmd=add,flags=0x01,meter=1 drop:rate=8")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x2000"+str(output_port)+" meter:1")

        input_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      ip_src=toIpV4Str(0xc0a80164),
                                      ip_dst=toIpV4Str(0xc0a80202),
                                      dl_vlan_enable=True,
                                      vlan_vid=2)

        output_pkt = input_pkt

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class trtcm(base_tests.SimpleDataPlane):
    """
    [TrTCM meter]
        TrTCM meter

    Inject  eth 1/3 {DA000000113355, SA000000112233, Tag 2} pkt [100 bytes, 50 pkt/sec]
    Output  eth 1/1 [16] vlan pcp 1 + [14] vlan pcp 3 + [20] vlan pcp 5

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 meter-mod cmd=add,flags=0x6,meter=1 set_color:rate=10,burst=5,exp_id=0x1018,exp_type=3,mode=1,color_aware=0,color=1 set_color:rate=20,burst=10,exp_id=0x1018,exp_type=3,mode=1,color_aware=0,color=2
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x20001 apply:set_field=ofdpa_color_actions_index:1 goto:65 meter:1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=2,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:5
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=1,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:3
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=0,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:1
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "meter-mod cmd=add,flags=0x6,meter=1 set_color:rate=10,burst=5,exp_id=0x1018,exp_type=3,mode=1,color_aware=0,color=1 set_color:rate=20,burst=10,exp_id=0x1018,exp_type=3,mode=1,color_aware=0,color=2")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x2000"+str(output_port)+" apply:set_field=ofdpa_color_actions_index:1 goto:65 meter:1")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=2,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:5")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=1,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:3")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=0,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:1")

        input_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      ip_src=toIpV4Str(0xc0a80164),
                                      ip_dst=toIpV4Str(0xc0a80202),
                                      dl_vlan_enable=True,
                                      vlan_vid=2,
                                      vlan_pcp=0)

        output_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      ip_src=toIpV4Str(0xc0a80164),
                                      ip_dst=toIpV4Str(0xc0a80202),
                                      dl_vlan_enable=True,
                                      vlan_vid=2,
                                      vlan_pcp=1)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class srtcm(base_tests.SimpleDataPlane):
    """
    [SrTCM meter]
        SrTCM meter

    Inject  eth 1/3 {DA000000113355, SA000000112233, Tag 2} pkt [100 bytes, 50 pkt/sec]
    Output  eth 1/1 [15] vlan pcp 1 + [15] vlan pcp 3 + [20] vlan pcp 5

    Inject  eth 1/3 {DA000000113355, SA000000112233, Tag 2} pkt [100 bytes, 30 pkt/sec]
    Output  eth 1/1 [15] vlan pcp 1 + [15] vlan pcp 3

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 meter-mod cmd=add,flags=0x6,meter=1 set_color:rate=10,exp_id=0x1018,exp_type=3,mode=2,color_aware=0,color=1,burst=10 set_color:rate=20,exp_id=0x1018,exp_type=3,mode=2,color_aware=0,color=2,burst=20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x20001 apply:set_field=ofdpa_color_actions_index:1 goto:65 meter:1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=2,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:5
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=1,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:3
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=0,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:1
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "meter-mod cmd=add,flags=0x6,meter=1 set_color:rate=10,exp_id=0x1018,exp_type=3,mode=2,color_aware=0,color=1,burst=10 set_color:rate=20,exp_id=0x1018,exp_type=3,mode=2,color_aware=0,color=2,burst=20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x2000"+str(output_port)+" apply:set_field=ofdpa_color_actions_index:1 goto:65 meter:1")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=2,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:5")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=1,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:3")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=0,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:1")

        input_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      ip_src=toIpV4Str(0xc0a80164),
                                      ip_dst=toIpV4Str(0xc0a80202),
                                      dl_vlan_enable=True,
                                      vlan_vid=2,
                                      vlan_pcp=0)

        output_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      ip_src=toIpV4Str(0xc0a80164),
                                      ip_dst=toIpV4Str(0xc0a80202),
                                      dl_vlan_enable=True,
                                      vlan_vid=2,
                                      vlan_pcp=1)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class mod_trtcm(base_tests.SimpleDataPlane):
    """
    [Mod TrTCM meter]
        Mod TrTCM meter

    Inject  eth 1/3 {DA000000113355, SA000000112233, Tag 2} pkt [100 bytes, 50 pkt/sec]
    Output  eth 1/1  [15] vlan pcp 1 + [28] vlan pcp 3 + [7] vlan pcp 5

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 meter-mod cmd=add,flags=0x6,meter=1 set_color:rate=10,burst=5,exp_id=0x1018,exp_type=3,mode=3,color_aware=0,color=1 set_color:rate=20,burst=10,exp_id=0x1018,exp_type=3,mode=3,color_aware=0,color=2
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x20001 apply:set_field=ofdpa_color_actions_index:1 goto:65 meter:1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=2,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:5
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=1,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:3
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=65,cmd=add,prio=651 ofdpa_color=0,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:1
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "meter-mod cmd=add,flags=0x6,meter=1 set_color:rate=10,burst=5,exp_id=0x1018,exp_type=3,mode=3,color_aware=0,color=1 set_color:rate=20,burst=10,exp_id=0x1018,exp_type=3,mode=3,color_aware=0,color=2")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:55 write:group=0x2000"+str(output_port)+" apply:set_field=ofdpa_color_actions_index:1 goto:65 meter:1")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=2,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:5")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=1,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:3")
        apply_dpctl_mod(self, config, "flow-mod table=65,cmd=add,prio=651 ofdpa_color=0,ofdpa_color_actions_index=1 apply:set_field=vlan_pcp:1")

        input_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      ip_src=toIpV4Str(0xc0a80164),
                                      ip_dst=toIpV4Str(0xc0a80202),
                                      dl_vlan_enable=True,
                                      vlan_vid=2,
                                      vlan_pcp=0)

        output_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      ip_src=toIpV4Str(0xc0a80164),
                                      ip_dst=toIpV4Str(0xc0a80202),
                                      dl_vlan_enable=True,
                                      vlan_vid=2,
                                      vlan_pcp=1)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)



