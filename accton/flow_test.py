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

class L2McastFlow(base_tests.SimpleDataPlane):
    """
    Test output function for an exact-match flow

    Add some multicast flows
    Then, for all ports, verifies that sending a matching packet
    to a multicast match results in an output to all ports.
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        # table 10: vlan
        # send to table 20
        add_vlan_table_flow(self.controller, config["port_map"].keys(), 1)

        # group table
        # set up untag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)

        # set up multicast group
        add_l2_mcast_group(self.controller, config["port_map"].keys(), 1, 1)
        
        test_macs = [[0x01, 0x00, 0x5e, 0xff, 0xff, 0xff]]

        for test_mac in test_macs:
            group_id = encode_l2_mcast_group_id(1, 1)
            add_bridge_flow(self.controller, test_mac, 1, group_id, True)

        for test_mac in test_macs:
            mactest = ':'.join(['%02X' % x for x in test_mac])

            for in_port in ports:
                # change dest based on port number
                parsed_pkt = simple_tcp_packet(eth_dst=mactest)
                pkt = str(parsed_pkt)
                logging.info("OutputExact test, from port %d to mac %s", in_port, mactest)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport == in_port: #tx port won't rx packet, unless L3 mcast routing
                        continue
                    verify_packet(self, pkt, ofport)
                verify_no_other_packets(self)

class L2UnicastFlow(base_tests.SimpleDataPlane):
    """
    Test output function for an exact-match flow

    For each port A, adds a flow directing matching packets to that port.
    Then, for all other ports B != A, verifies that sending a matching packet
    to B results in an output to A.
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        # table 10: vlan
        # send to table 20
        add_vlan_table_flow(self.controller, config["port_map"].keys(), 1)

        # group table
        # set up untag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, 1)

        for out_port in ports:
            group_id = encode_l2_interface_group_id(1, out_port)
            add_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, out_port], 1, group_id, True)

            for in_port in ports:
                if in_port == out_port:
                    continue
                # change dest based on port number
                parsed_pkt = simple_tcp_packet(eth_dst='00:12:34:56:78:%02X' % out_port)
                pkt = str(parsed_pkt)
                logging.info("OutputExact test, ports %d to %d", in_port, out_port)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)
                        
                verify_no_other_packets(self)

class PacketInMiss(base_tests.SimpleDataPlane):
    """
    Test packet in function for a table-miss flow

    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    """

    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        
        parsed_pkt = simple_tcp_packet(pktlen=100)
        parsed_vlan_pkt = simple_tcp_packet(pktlen=104, 
                      vlan_vid=0x1001, dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        vlan_pkt = str(parsed_vlan_pkt)
        # table 10: vlan
        # send to table 20
        add_vlan_table_flow(self.controller, config["port_map"].keys(), 1)

        # group table
        # set up untag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, 1)

        # create match
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.vlan_vid(0x1001))
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

        for of_port in config["port_map"].keys():
            logging.info("PacketInMiss test, port %d", of_port)
            self.dataplane.send(of_port, pkt)

            #AOS current packet in will not have vlan tag
            #verify_packet_in(self, vlan_pkt, of_port, ofp.OFPR_ACTION)
            verify_packet_in(self, pkt, of_port, ofp.OFPR_ACTION)
            verify_no_other_packets(self)

