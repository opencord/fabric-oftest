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
from accton_util import *

class case1(base_tests.SimpleDataPlane):
    """
    pakcet from port 1 (tag/untag) ouptut to port 2 with vlan 10
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)     
    
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]

        add_one_vlan_table_flow(self.controller, in_port, vlan_id=1, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_BOTH, send_barrier=False)
        add_one_l2_interface_group(self.controller, out_port, 10,  True, False)
        msg=add_l2_rewrite_group(self.controller, out_port, 10, 1, None, None)        
        
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
        
        parsed_pkt = simple_tcp_packet(pktlen=100)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
    
        parsed_pkt = simple_tcp_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=10)
        verify_packet(self, str(parsed_pkt), out_port)