
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
# Copyright (c) 2012, 2013 CPqD
# Copyright (c) 2012, 2013 Ericsson
# Copyright (c) 2015 Research Education and Advanced Network New Zealand Ltd.
"""
Basic test cases

Test cases in other modules depend on this functionality.
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time
from oftest.testutils import *



class case1(base_tests.SimpleDataPlane):
    """
    packet come from port 1 (DIP=192.168.1.100 and DMAC=00:00:00:00:00:10, VLAN=100), 
    forward to port 2 untag
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    

        #l2-interface-grup_port1_vlann100_untag
        grouptype = 0
        vlanid = 100
        of_port=1
        group_id = of_port + (vlanid << 16) + (grouptype << 28)
        actions = [
            ofp.action.pop_vlan(),
            ofp.action.output(of_port),
        ]
        buckets = [
            ofp.bucket(actions=actions),
        ]
        request = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id=group_id,
            buckets=buckets
        )
        self.controller.message_send(request) 
        #l2-interface-grup_port2_vlann100_untag
        grouptype = 0
        vlanid = 100
        of_port=2
        group_id = of_port + (vlanid << 16) + (grouptype << 28)
        actions = [
            ofp.action.pop_vlan(),
            ofp.action.output(of_port),
        ]
        buckets = [
            ofp.bucket(actions=actions),
        ]
        request = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id=group_id,
            buckets=buckets
        )
        self.controller.message_send(request)     

        #10_add_port1_allow_rx_tag_vid_100
        match = ofp.match()
        of_port=1
        vlanid=100
        match.oxm_list.append(ofp.oxm.in_port(of_port))
        match.oxm_list.append(ofp.oxm.vlan_vid(0x1000|vlanid))
        request = ofp.message.flow_add(
            table_id=10,
            cookie=42,
            match=match,
            instructions=[
              ofp.instruction.goto_table(20)
            ],
            priority=0)
        logging.info("Set vlan-1 tagged on port %d, and goto table 20" % of_port)
        self.controller.message_send(request)
        """        
        #50_mac_0000000010_vlan_100
        grouptype = 0
        vlanid = 100
        out_port=2
        group_id = out_port + (vlanid << 16) + (grouptype << 28)
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_dst([0x00, 0x00, 0x00, 0x00, 0x00, 0x10]))
        match.oxm_list.append(ofp.oxm.vlan_vid(vlanid))
        request = ofp.message.flow_add(
                table_id=50,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(group_id)]),
                        ofp.instruction.goto_table(60)
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)

        logging.info("Inserting Bridge flow sending matching packets to port %d", out_port)
        self.controller.message_send(request)
        do_barrier(self.controller)        
        """
        #60_acl

        grouptype = 0
        vlanid = 100
        out_port=2
        group_id = out_port + (vlanid << 16) + (grouptype << 28)
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_dst([0x00, 0x00, 0x00, 0x00, 0x00, 0x10]))
        match.oxm_list.append(ofp.oxm.vlan_vid(vlanid))
        match.oxm_list.append(ofp.oxm.eth_type(0x0800))        
        match.oxm_list.append(ofp.oxm.ipv4_dst_masked(0xc0010164, 32))        
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(
                        actions=[
                            ofp.action.group(group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)

        logging.info("Inserting ACL flow sending matching packets to port %d", out_port)
        self.controller.message_send(request)
        do_barrier(self.controller)        

        #send packet on port 1
        in_port=1
        out_port=2
        parsed_pkt = simple_tcp_packet(pktlen=104, 
                                       eth_dst='00:00:00:00:00:10', 
                                       dl_vlan_enable=True,
                                       vlan_vid=100,
                                       ip_dst='192.168.1.100')
        pkt = str(parsed_pkt)
        logging.info("Send packet on port %d, out port %d", in_port, out_port)
        self.dataplane.send(in_port, pkt)
        #construct verify packet content
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst='00:00:00:00:00:10', 
                                       ip_dst='192.168.1.100')
        verify_packet(self, parsed_pkt, out_port)
        
        verify_no_other_packets(self)   

        #send packet on port 1, again but diff DST IP
        in_port=1
        out_port=2
        parsed_pkt = simple_tcp_packet(pktlen=104, 
                                       eth_dst='00:00:00:00:00:10', 
                                       dl_vlan_enable=True,
                                       vlan_vid=100,
                                       ip_dst='192.168.1.200')
        pkt = str(parsed_pkt)
        logging.info("Send packet on port %d, out port %d", in_port, out_port)
        self.dataplane.send(in_port, pkt)
        #construct verify packet content
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst='00:00:00:00:00:10', 
                                       ip_dst='192.168.1.200')
        verify_no_packet(self, parsed_pkt, out_port)
        
        verify_no_other_packets(self)  
        

class case2(base_tests.SimpleDataPlane):
    """
    packet come from port 1 (SIP=192.168.1.100 and SMAC=00:00:00:00:00:20, VLAN=200, TCP), 
    forward to port 2 VLAN 300
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    

        #l2-interface-grup_port1_vlann200_untag
        grouptype = 0
        vlanid = 200
        of_port=1
        group_id = of_port + (vlanid << 16) + (grouptype << 28)
        actions = [
            ofp.action.pop_vlan(),
            ofp.action.output(of_port),
        ]
        buckets = [
            ofp.bucket(actions=actions),
        ]
        request = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id=group_id,
            buckets=buckets
        )
        self.controller.message_send(request) 
        #l2-interface-grup_port2_vlann300
        grouptype = 0
        vlanid = 300
        of_port=2
        group_id = of_port + (vlanid << 16) + (grouptype << 28)
        actions = [
            ofp.action.output(of_port),
        ]
        buckets = [
            ofp.bucket(actions=actions),
        ]
        request = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id=group_id,
            buckets=buckets
        )
        self.controller.message_send(request)     

        #rewrite_group_vlan_200_to_300, use l2-interface-grup_port2_vlann300 group_id
        grouptype = 1
        vlanid = 300
        rw_group_id = 2 + (grouptype << 28)
        
        action=[]
        action.append(ofp.action.set_field(ofp.oxm.vlan_vid(vlanid)))
        action.append(ofp.action.group(group_id))        
        buckets = [ofp.bucket(actions=action)]   
        request = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id=rw_group_id,
            buckets=buckets
        )
        self.controller.message_send(request)     
                
        #10_add_port1_allow_rx_tag_vid_200
        match = ofp.match()
        of_port=1
        vlanid=200
        match.oxm_list.append(ofp.oxm.in_port(of_port))
        match.oxm_list.append(ofp.oxm.vlan_vid(0x1000|vlanid))
        request = ofp.message.flow_add(
            table_id=10,
            cookie=42,
            match=match,
            instructions=[
              ofp.instruction.goto_table(20)
            ],
            priority=0)
        logging.info("Set vlan-1 tagged on port %d, and goto table 20" % of_port)
        self.controller.message_send(request)
        
       
        #60_acl
        grouptype = 1
        vlanid = 200
        rw_group_id = 2 + (grouptype << 28)
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(1))
        match.oxm_list.append(ofp.oxm.eth_src([0x00, 0x00, 0x00, 0x00, 0x00, 0x20]))
        match.oxm_list.append(ofp.oxm.vlan_vid(vlanid))
        match.oxm_list.append(ofp.oxm.eth_type(0x0800))        
        match.oxm_list.append(ofp.oxm.ipv4_src(0xc0a80164))
        match.oxm_list.append(ofp.oxm.ip_proto(6))
        
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(
                        actions=[
                            ofp.action.group(rw_group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)

        self.controller.message_send(request)
        do_barrier(self.controller)        

        #send packet on port 1
        in_port=1
        out_port=2
        parsed_pkt = simple_tcp_packet(pktlen=104, 
                                       eth_src='00:00:00:00:00:20', 
                                       dl_vlan_enable=True,
                                       vlan_vid=200,
                                       ip_src='192.168.1.100')
        pkt = str(parsed_pkt)
        logging.info("Send packet on port %d, out port %d", in_port, out_port)
        self.dataplane.send(in_port, pkt)
        #construct verify packet content
        parsed_pkt = simple_tcp_packet(pktlen=104, 
                                       eth_src='00:00:00:00:00:20', 
                                       dl_vlan_enable=True,
                                       vlan_vid=300,                                       
                                       ip_src='192.168.1.100')
        verify_packet(self, parsed_pkt, out_port)
        
        verify_no_other_packets(self)   

        #send packet on port 1, again but diff SRC IP
        in_port=1
        out_port=2
        parsed_pkt = simple_tcp_packet(pktlen=104, 
                                       eth_src='00:00:00:00:00:20', 
                                       dl_vlan_enable=True,
                                       vlan_vid=100,
                                       ip_src='192.168.1.200')
        pkt = str(parsed_pkt)
        logging.info("Send packet on port %d, out port %d", in_port, out_port)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, pkt, out_port)
        
        verify_no_other_packets(self)         