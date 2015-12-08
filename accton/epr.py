import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

"""
This file test case is copied from NTC EPR bug
"""

class pvidClear(base_tests.SimpleDataPlane):
    """
    AOS5700-54X-00620
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
        port1=ports[0]
        port2=ports[1]
        
        vlan_id = 10

        gid_p1, req_msg_p1 = add_one_l2_interface_group(self.controller, port=port1, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
        gid_p2, req_msg_p2 = add_one_l2_interface_group(self.controller, port=port2, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
        #add ACL flow, in port1 out port2
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(port1))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(gid_p2)]
                    )
            ],
            priority=1)
        #install flow
        self.controller.message_send(request)        
        #add ACL flow, in port2 out port1
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(port2))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(gid_p1)]
                    )
            ],
            priority=1)
        #install flow
        self.controller.message_send(request)    
        
        #send packet and verify packet
        parsed_pkt = simple_tcp_packet()
        self.dataplane.send(port1, str(parsed_pkt))
        verify_no_packet(self, str(parsed_pkt), port2)         
        self.dataplane.send(port2, str(parsed_pkt))        
        verify_no_packet(self, str(parsed_pkt), port1)        

        
        #add vlan flow table
        add_vlan_table_flow(self.controller, [port1, port2], vlan_id=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_UNTAG)
        #send packet and verify packet
        parsed_pkt = simple_tcp_packet()
        self.dataplane.send(port1, str(parsed_pkt))
        verify_packet(self, str(parsed_pkt), port2)        
        self.dataplane.send(port2, str(parsed_pkt))        
        verify_packet(self, str(parsed_pkt), port1)
         
        #remove vlan table flow        
        del_vlan_table_flow(self.controller, [port1, port2], vlan_id=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_UNTAG)
        #send packet and verify packet
        parsed_pkt = simple_tcp_packet()
        self.dataplane.send(port1, str(parsed_pkt))
        verify_no_packet(self, str(parsed_pkt), port2)
        self.dataplane.send(port2, str(parsed_pkt))
        verify_no_packet(self, str(parsed_pkt), port1)
        
        
        
            
