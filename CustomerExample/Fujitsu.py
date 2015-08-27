import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class PacketInMiss(base_tests.SimpleDataPlane):
    """
    Test packet in function for a table-miss flow

    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    
    NOTE: Verify This case the oft option shall not use --switch-ip
    """

    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        
        # table 10: vlan
        # send to table 20
        add_vlan_table_flow(self.controller, config["port_map"].keys(), 1)

        # group table
        # set up untag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, 1)

        verify_port = config["port_map"].keys()[0]
        
        # create match
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(verify_port))        
        match.oxm_list.append(ofp.oxm.eth_type(0x0800))                
        match.oxm_list.append(ofp.oxm.ipv4_dst_masked(0xa0a0a0a, 0xffffffff))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=ofp.OFPP_CONTROLLER,
                            max_len=ofp.OFPCML_NO_BUFFER)]),
            ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1)

        logging.info("Inserting packet in flow to controller")
        self.controller.message_send(request)
        do_barrier(self.controller)

        
        logging.info("PacketInMiss test, port %d", verify_port)
        parsed_pkt = simple_tcp_packet(pktlen=100, ip_dst="10.10.10.10")
        pkt = str(parsed_pkt)    
        self.dataplane.send(verify_port, pkt)

        #AOS current packet in will not have vlan tag
        verify_packet_in(self, pkt, verify_port, ofp.OFPR_ACTION)

        verify_no_other_packets(self)
