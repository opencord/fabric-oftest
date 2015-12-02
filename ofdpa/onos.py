"""
Flow Test
1) PacketInSrcMacMiss
2) L2FloodTagged
3) L2Flood Tagged Unknown Src
4) L2 Unicast Tagged
5) L3 Unicast Tagged
6) MTU 1500
7) MTU 4100
8) MTU 4500
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class PacketInSrcMacMiss(base_tests.SimpleDataPlane):
    """
    Test packet in function on a src-mac miss
    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    #todo verify you stop receiving after adding rule
    """

    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        parsed_vlan_pkt = simple_tcp_packet(pktlen=104,
                      vlan_vid=0x1001, dl_vlan_enable=True)
        vlan_pkt = str(parsed_vlan_pkt)

        add_vlan_table_flow(self.controller, config["port_map"].keys(), 1)

        # group table
        # set up untag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  True, 1)

        for of_port in config["port_map"].keys():
            logging.info("PacketInMiss test, port %d", of_port)
            self.dataplane.send(of_port, vlan_pkt)

            verify_packet_in(self, vlan_pkt, of_port, ofp.OFPR_NO_MATCH)

            verify_no_other_packets(self)

class L2FloodTagged(base_tests.SimpleDataPlane):
    """
    Test L2 flood to a vlan
    Send a packet with unknown dst_mac and check if the packet is flooded to all ports except inport
    #todo take in account unknown src 
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        add_vlan_table_flow(self.controller, ports, 1)

        # set up tagged groups for each port
        add_l2_interface_grouop(self.controller, ports, 1,  True, 1)

        msg=add_l2_flood_group(self.controller, ports, 1, 1)
        add_bridge_flow(self.controller, None, 1, msg.group_id, True)
        # Installing flows to avoid packet-in
        for port in ports:
            group_id = encode_l2_interface_group_id(1, port)
            add_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, port], 1, group_id, True)
        do_barrier(self.controller)

        #verify flood
        for ofport in ports:
            # change dest based on port number
            mac_src= '00:12:34:56:78:%02X' % ofport
            parsed_pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=1, eth_dst='00:12:34:56:78:9a', eth_src=mac_src)
            pkt = str(parsed_pkt)
            self.dataplane.send(ofport, pkt)
            #self won't rx packet
            verify_no_packet(self, pkt, ofport)
            #others will rx packet
            tmp_ports=list(ports)
            tmp_ports.remove(ofport)
            verify_packets(self, pkt, tmp_ports)

        verify_no_other_packets(self)

class L2FloodTaggedUnknownSrc(base_tests.SimpleDataPlane):
    """
    Test L2 flood to a vlan
    Send a packet with unknown dst_mac and check if the packet is flooded to all ports except inport
    #todo take in account unknown src 
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        add_vlan_table_flow(self.controller, ports, 1)

        # set up tagged groups for each port
        add_l2_interface_grouop(self.controller, ports, 1,  True, 1)

        msg=add_l2_flood_group(self.controller, ports, 1, 1)
        add_bridge_flow(self.controller, None, 1, msg.group_id, True)

        parsed_pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=1, eth_dst='00:12:34:56:78:9a')
        pkt = str(parsed_pkt)
        #verify flood
        for ofport in ports:
            self.dataplane.send(ofport, pkt)
            #self won't rx packet
            verify_no_packet(self, pkt, ofport)
            #others will rx packet
            tmp_ports=list(ports)
            tmp_ports.remove(ofport)
            verify_packets(self, pkt, tmp_ports)

        verify_no_other_packets(self)

class L2UnicastTagged(base_tests.SimpleDataPlane):
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

        add_vlan_table_flow(self.controller, config["port_map"].keys())

        # set up tag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1, True, 1)

        for port in ports:
            group_id = encode_l2_interface_group_id(1, port)
            add_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, port], 1, group_id, True)
        do_barrier(self.controller)

        for out_port in ports:
            # change dest based on port number
            mac_dst= '00:12:34:56:78:%02X' % out_port
            for in_port in ports:
                if in_port == out_port:
                    continue
                # change source based on port number to avoid packet-ins from learning
                mac_src= '00:12:34:56:78:%02X' % in_port
                parsed_pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=1, eth_dst=mac_dst, eth_src=mac_src)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)

                verify_no_other_packets(self)


class Mtu4500(base_tests.SimpleDataPlane):

    def runTest(self):
        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        add_vlan_table_flow(self.controller, config["port_map"].keys())

        # set up tag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1, True, 1)

        for port in ports:
            group_id = encode_l2_interface_group_id(1, port)
            add_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, port], 1, group_id, True)
        do_barrier(self.controller)

        for out_port in ports:
            # change dest based on port number
            mac_dst= '00:12:34:56:78:%02X' % out_port
            for in_port in ports:
                if in_port == out_port:
                    continue
                # change source based on port number to avoid packet-ins from learning
                mac_src= '00:12:34:56:78:%02X' % in_port
                parsed_pkt = simple_tcp_packet(pktlen=4500,dl_vlan_enable=True, vlan_vid=1, eth_dst=mac_dst, eth_src=mac_src)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)

                verify_no_other_packets(self)


class Mtu1500(base_tests.SimpleDataPlane):

    def runTest(self):
        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        add_vlan_table_flow(self.controller, config["port_map"].keys())

        # set up tag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1, True, 1)

        for port in ports:
            group_id = encode_l2_interface_group_id(1, port)
            add_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, port], 1, group_id, True)
        do_barrier(self.controller)

        for out_port in ports:
            # change dest based on port number
            mac_dst= '00:12:34:56:78:%02X' % out_port
            for in_port in ports:
                if in_port == out_port:
                    continue
                # change source based on port number to avoid packet-ins from learning
                mac_src= '00:12:34:56:78:%02X' % in_port
                parsed_pkt = simple_tcp_packet(pktlen=1500,dl_vlan_enable=True, vlan_vid=1, eth_dst=mac_dst, eth_src=mac_src)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)

                verify_no_other_packets(self)


class Mtu4000(base_tests.SimpleDataPlane):
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

        add_vlan_table_flow(self.controller, config["port_map"].keys())

        # set up tag groups for each port
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1, True, 1)

        for port in ports:
            group_id = encode_l2_interface_group_id(1, port)
            add_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, port], 1, group_id, True)
        do_barrier(self.controller)

        for out_port in ports:
            # change dest based on port number
            mac_dst= '00:12:34:56:78:%02X' % out_port
            for in_port in ports:
                if in_port == out_port:
                    continue
                # change source based on port number to avoid packet-ins from learning
                mac_src= '00:12:34:56:78:%02X' % in_port
                parsed_pkt = simple_tcp_packet(pktlen=4000,dl_vlan_enable=True, vlan_vid=1, eth_dst=mac_dst, eth_src=mac_src)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)

                verify_no_other_packets(self)

class L3UcastTagged(base_tests.SimpleDataPlane):
    """
    Port1(vlan1, 0x00, 0x00, 0x00, 0x22, 0x22, 0x01, 192.168.1.1) , 
    Port2(vlan2, 0x00, 0x00, 0x00, 0x22, 0x22, 0x02, 19.168.2.1)
    """
    def runTest(self):          
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return
        
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip=0xc0a80001
        ports = config["port_map"].keys()
        for port in ports:
            #add l2 interface group
            vlan_id=port
            add_one_l2_interface_grouop(self.controller, port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
            dst_mac[5]=vlan_id
            l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=intf_src_mac, dst_mac=dst_mac)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            #add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac, vlan_id)           
            #add unicast routing flow
            dst_ip = dip + (vlan_id<<8)           
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0, l3_msg.group_id)

            #add entries in the Bridging table to avoid packet-in from mac learning
            group_id = encode_l2_interface_group_id(vlan_id, port)
            add_bridge_flow(self.controller, dst_mac, vlan_id, group_id, True)
        
        do_barrier(self.controller)  
        
        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            mac_src='00:00:00:22:22:%02X' % in_port
            ip_src='192.168.%02d.1' % in_port
            for out_port in ports:
                if in_port == out_port:
                     continue
                ip_dst='192.168.%02d.1' % out_port
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=in_port,
                    eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src,
                    ip_dst=ip_dst)            
                pkt=str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                #build expect packet
                mac_dst='00:00:00:22:22:%02X' % out_port
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=out_port, 
                                       eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63,
                                       ip_src=ip_src, ip_dst=ip_dst)
                pkt=str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)

