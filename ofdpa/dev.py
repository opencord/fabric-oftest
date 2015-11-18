"""
Flow Test
Test each flow table can set entry, and packet rx correctly.
1) L3UcastRoute
2) QinQ
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class L2Flood(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return

        vlan_id=1
        mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        for port in config["port_map"].keys():
            #add l2 interface group
            add_one_l2_interface_grouop(self.controller, port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            #add Bridgin table exact match
            group_id = encode_l2_interface_group_id(vlan_id, port)
            mac[5]=port
            add_bridge_flow(self.controller, mac, vlan_id, group_id, True)

        do_barrier(self.controller)

        for outport in config["port_map"].keys():
            mac[5]=outport
            dst_mac=':'.join(['%02X' % x for x in mac])
            for inport in config["port_map"].keys():
             if inport is not outport:
               mac[5]=inport
               src_mac = ':'.join(['%02X' % x for x in mac])
               parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=1, eth_dst=dst_mac,
                                       eth_src=src_mac, ip_src="192.168.1.1", ip_dst='192.168.1.2')
               pkt=str(parsed_pkt)
               self.dataplane.send(inport, pkt)
               verify_packet(self, pkt, outport)
               verify_no_other_packets(self)

class L2Unicast(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return

        vlan_id=1
        mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        for port in config["port_map"].keys():
            #add l2 interface group
            add_one_l2_interface_grouop(self.controller, port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            #add Bridgin table exact match
            group_id = encode_l2_interface_group_id(vlan_id, port)
            mac[5]=port
            add_bridge_flow(self.controller, mac, vlan_id, group_id, True)
        
        do_barrier(self.controller)

        for outport in config["port_map"].keys():
            mac[5]=outport
            dst_mac=':'.join(['%02X' % x for x in mac])
            for inport in config["port_map"].keys():
             if inport is not outport:
               mac[5]=inport
               src_mac = ':'.join(['%02X' % x for x in mac])
               parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=1, eth_dst=dst_mac,
                                       eth_src=src_mac, ip_src="192.168.1.1", ip_dst='192.168.1.2')
               pkt=str(parsed_pkt)
               self.dataplane.send(inport, pkt)
               verify_packet(self, pkt, outport)
               verify_no_other_packets(self)
 


class qinq(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)   
        
        in_port = config["port_map"].keys()[0]
        out_port = config["port_map"].keys()[1]        
        out_vlan=10
        #add_vlan_table_flow_pvid(self.controller, in_port, None, out_vlan, False)
        add_vlan_table_flow_pvid(self.controller, in_port, 1,out_vlan, False)        
        group_id, msg=add_one_l2_interface_grouop(self.controller, out_port, out_vlan,  True, False) 
        #add acl 
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))    
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000) 
        self.controller.message_send(request)  

        #input tag packet
        parsed_pkt = simple_tcp_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=1)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
    
        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=108, out_dl_vlan_enable=True, out_vlan_vid=10,
                                                in_dl_vlan_enable=True, in_vlan_vid=1)
        verify_packet(self, str(parsed_pkt), out_port)

class VlanFlow(base_tests.SimpleProtocol): 
    def runTest(self):
        logging.info("Installing ACL rule")

class FlowStats(base_tests.SimpleProtocol):
    """
    Flow stats multipart transaction
    Only verifies we get a reply.
    """
    def runTest(self):
        logging.info("Sending flow stats request")
        stats = get_flow_stats(self, ofp.match())
        logging.info("Received %d flow stats entries", len(stats))
        for entry in stats:
            logging.info(entry.show())


class ACLStats(base_tests.SimpleProtocol):
    """
    Flow stats multipart transaction
    Only verifies we get a reply.
    """
    def runTest(self):
        logging.info("Installing ACL rule")
        #delete_all_flows(self.controller)
        #delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=10
        #add_vlan_table_flow_pvid(self.controller, in_port, None, out_vlan, False)
        #add_vlan_table_flow_pvid(self.controller, in_port, 1,out_vlan, False)
        group_id, msg=add_one_l2_interface_grouop(self.controller, out_port, out_vlan,  True, False)
        inst=[ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],

        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=inst,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        #self.controller.message_send(request)

        logging.info("Sending flow stats request")
        stats = get_flow_stats(self, match)
        logging.info("Received %d flow stats entries", len(stats))
        verify_flow_stats=[ofp.flow_stats_entry(
                               table_id=60
                               #cookie=42,
                               #match=match,
                               #instructions=inst,
                               #priority=1000
)]
        self.assertEquals(stats, verify_flow_stats)


#class LearningPacketIn()git 
