"""
Flow Test

Test each flow table can set entry, and packet rx correctly.
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class qinq(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)   
        
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]        
        out_vlan=10
        add_vlan_table_flow_pvid(self.controller, in_port, None, out_vlan, False)
        add_vlan_table_flow_pvid(self.controller, in_port, 1,out_vlan, False)        
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, out_vlan,  True, False)
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
     
        #input untag packet

        parsed_pkt = simple_tcp_packet(pktlen=100)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
    
        parsed_pkt = simple_tcp_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=10)
        verify_packet(self, str(parsed_pkt), out_port)

        #input tag packet
        parsed_pkt = simple_tcp_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=1)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
    
        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=108, out_dl_vlan_enable=True, out_vlan_vid=10,
                                                in_dl_vlan_enable=True, in_vlan_vid=1)
        verify_packet(self, str(parsed_pkt), out_port)
