import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *


class RedirectArpToSpecifyPortOrController(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	

        test_vid =1
        #add vlan flow to pass vlan verification
        add_l2_interface_grouop(self.controller, test_ports, vlan_id=test_vid, is_tagged=False, send_barrier=False)
        add_vlan_table_flow(self.controller, test_ports, vlan_id=test_vid, flag=VLAN_TABLE_FLAG_ONLY_BOTH, send_barrier=False)
        
        #get a port to be the flood destination port, 
        #remember test_ports already mius FLOOD_TO_PORT
        FLOOD_TO_PORT = test_ports.pop();
        l2_mcast_group=add_l2_mcast_group(self.controller, [FLOOD_TO_PORT], vlanid=test_vid, mcast_grp_index=1)
		
		#match ether_type=arp and da=bcast

        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x0806)) #match arp ethertype
        match.oxm_list.append(ofp.oxm.eth_dst([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])) #match DA is bcast		
        request = ofp.message.flow_add(
                      table_id=60,
                      cookie=42,
                      match=match,
                      instructions=[ofp.instruction.write_actions(
                                    actions=[ofp.action.group(l2_mcast_group.group_id)
                                             ,ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER)
                                            ])
                                   ],
                      buffer_id=ofp.OFP_NO_BUFFER,
                      priority=1) 

        self.controller.message_send(request)
		
        arp=simple_arp_packet()
        
        for port in test_ports:
            self.dataplane.send(port, str(arp))
            verify_packet(self, str(arp), FLOOD_TO_PORT)  
            verify_packet_in(self, str(arp), port, ofp.OFPR_ACTION)
            verify_no_other_packets(self)

