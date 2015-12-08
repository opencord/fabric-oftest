import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *


class NoVlanOnlyAclOutputPort(base_tests.SimpleDataPlane):
    """
    In OFDPA, ACL can save the packet it was dropped vlan table
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
        input_port=ports[0]
        output_port=ports[1]
        vlan_id = 10
        dmac = [0x00, 0x12, 0x34, 0x56, 0x78, 0x9a]
        gid, req_msg = add_one_l2_interface_group(self.controller, port=output_port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
        #add ACL flow to output port
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(input_port))
        match.oxm_list.append(ofp.oxm.eth_dst(dmac))
        match.oxm_list.append(ofp.oxm.vlan_vid(0x1000+vlan_id))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(gid)]
                    )
            ],
            priority=1)
        #install flow
        self.controller.message_send(request)        

        dmac_str = convertMACtoStr(dmac)
        #send packet
        parsed_pkt = simple_tcp_packet(eth_dst=dmac_str, vlan_vid=vlan_id, dl_vlan_enable=True)
        self.dataplane.send(input_port, str(parsed_pkt))
        #verify packet
        verify_packet(self, str(parsed_pkt), output_port)        

        
        
        
        
        
        
        