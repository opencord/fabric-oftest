
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


"""
"""
import Queue

from oftest import config
import logging
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *
import inspect

@disabled
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
        add_l2_interface_group(self.controller, config["port_map"].keys(), 1, True, 1)

        for port in ports:
            add_one_l2_interface_group(self.controller, port, 1, True, False)
            add_one_vlan_table_flow(self.controller, port, 1, flag=VLAN_TABLE_FLAG_ONLY_TAG)
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



class LPMDirect(base_tests.SimpleDataPlane):
    """
	    Insert IP packet
	    Receive MPLS packet
    """
    def runTest(self):
        Groups=Queue.LifoQueue()
        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip=0xc0a80001
        index=1
        ports = config["port_map"].keys()
        for port in ports:
            #add l2 interface group
            vlan_id=port
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port, vlan_id, True, True)
            dst_mac[5]=vlan_id
            #add MPLS interface group
            mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid, dst_mac, intf_src_mac, vlan_id, port)
            #add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                                             index=port, ref_gid= mpls_gid, push_mpls_header=True, set_mpls_label=port, set_bos=1, set_ttl=32)
            #ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [mpls_label_gid])
            Groups._put(l2_gid)
            Groups._put(mpls_gid)
            Groups._put(mpls_label_gid)
            do_barrier(self.controller)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG)
            #add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac, vlan_id)
            #add routing flow
            dst_ip = dip + (vlan_id<<8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0xffffff00, mpls_label_gid)
            #add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0xffffff00, ecmp_msg.group_id)
        port = ports[0]
        #add l2 interface group
        vlan_id=port
        l2_gid = encode_l2_interface_group_id(vlan_id, port)
        dst_mac[5]=vlan_id
        #add MPLS interface group
        mpls_gid = encode_mpls_interface_group_id(0, port)
        #add MPLS L3 VPN group
        mpls_label_gid = encode_mpls_label_group_id(OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=port)
        #ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [mpls_label_gid])
        do_barrier(self.controller)
        #add routing flow
        dst_ip = 0x0
        add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0x0, mpls_label_gid)
        #add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0x0, ecmp_msg.group_id)

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
                label = (out_port, 0, 1, 32)
                exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=out_port, ip_ttl=63, ip_src=ip_src,
                                      ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac, label=[label])
                pkt=str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
                ip_dst='1.168.%02d.1' % ports[0]
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=in_port,
                                               eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst)
                pkt=str(parsed_pkt)
                #self.dataplane.send(in_port, pkt)
                #build expect packet
                mac_dst='00:00:00:22:22:%02X' % ports[0]
                label = (ports[0], 0, 1, 32)
                exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=ports[0], ip_ttl=63, ip_src=ip_src,
                                      ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac, label=[label])
                pkt=str(exp_pkt)
                #verify_packet(self, pkt, ports[0])
                #verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller,Groups)

class LPM(base_tests.SimpleDataPlane):
    """
	    Insert IP packet
	    Receive MPLS packet
    """
    def runTest(self):
        Groups=Queue.LifoQueue()
        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip=0xc0a80001
        index=1
        ports = config["port_map"].keys()
        for port in ports:
            #add l2 interface group
            vlan_id=port
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port, vlan_id, True, True)
            dst_mac[5]=vlan_id
            #add MPLS interface group
            mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid, dst_mac, intf_src_mac, vlan_id, port)
            #add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                                                                  index=port, ref_gid= mpls_gid, push_mpls_header=True, set_mpls_label=port, set_bos=1, set_ttl=32)
            ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [mpls_label_gid])
            Groups._put(l2_gid)
            Groups._put(mpls_gid)
            Groups._put(mpls_label_gid)
            Groups._put(ecmp_msg.group_id)
            do_barrier(self.controller)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_TAG)
            #add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac, vlan_id)
            #add routing flow
            dst_ip = dip + (vlan_id<<8)
            #add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0xffffff00, mpls_label_gid, vrf=2)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0xffffff00, ecmp_msg.group_id)
            #add entries in the Bridging table to avoid packet-in from mac learning
            group_id = encode_l2_interface_group_id(vlan_id, port)
            add_bridge_flow(self.controller, dst_mac, vlan_id, group_id, True)
        port = ports[0]
        #add l2 interface group
        vlan_id=port
        l2_gid = encode_l2_interface_group_id(vlan_id, port)
        dst_mac[5]=vlan_id
        #add MPLS interface group
        mpls_gid = encode_mpls_interface_group_id(0, port)
        #add MPLS L3 VPN group
        mpls_label_gid = encode_mpls_label_group_id(OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=port)
        ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [mpls_label_gid])
        Groups._put(ecmp_msg.group_id)
        do_barrier(self.controller)
        #add routing flow
        dst_ip = 0x0
        #add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0x0, mpls_label_gid, vrf=2)
        add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0x0, ecmp_msg.group_id)

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
                label = (out_port, 0, 1, 32)
                exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=out_port, ip_ttl=63, ip_src=ip_src,
                                      ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac, label=[label])
                pkt=str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
                ip_dst='1.168.%02d.1' % ports[0]
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=in_port,
                                               eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst)
                pkt=str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                #build expect packet
                mac_dst='00:00:00:22:22:%02X' % ports[0]
                label = (ports[0], 0, 1, 32)
                exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=ports[0], ip_ttl=63, ip_src=ip_src,
                                      ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac, label=[label])
                pkt=str(exp_pkt)
                verify_packet(self, pkt, ports[0])
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller,Groups)

@disabled
class L2FloodTaggedUnknownSrc(base_tests.SimpleDataPlane):
    """
    Test L2 flood to a vlan
    Send a packet with unknown dst_mac and check if the packet is flooded to all ports except inport
    #todo take in account unknown src
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        ports = sorted(config["port_map"].keys())
        for port in ports:
            add_one_l2_interface_group(self.controller, port, 1, True, False)
            add_one_vlan_table_flow(self.controller, port, 1, flag=VLAN_TABLE_FLAG_ONLY_TAG)

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

@disabled
class PacketInIPTable(base_tests.SimpleDataPlane):
    """
    Test packet in function on IPTABLE
    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    #todo verify you stop receiving after adding rule
    """

    def runTest(self):

        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip=0xc0a80001
        ports = sorted(config["port_map"].keys())
        Groups = Queue.LifoQueue()

        for port in ports:
            #add l2 interface group
            vlan_id=port
            add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
            dst_mac[5]=vlan_id
            l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=intf_src_mac, dst_mac=dst_mac)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id,  flag=VLAN_TABLE_FLAG_ONLY_TAG)
            #add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac, vlan_id)
            #add unicast routing flow
            dst_ip = dip + (vlan_id<<8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0xffffff00, l3_msg.group_id, send_ctrl=True)
            Groups.put(l3_msg.group_id)

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
                verify_packet_in(self, pkt, in_port, ofp.OFPR_ACTION)
                #verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)

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

        ports = sorted(config["port_map"].keys())
        for port in ports:
            add_one_l2_interface_group(self.controller, port, 1, True, False)
            add_one_vlan_table_flow(self.controller, port, 1, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        parsed_vlan_pkt = simple_tcp_packet(pktlen=104,
                                            vlan_vid=0x1001, dl_vlan_enable=True)
        vlan_pkt = str(parsed_vlan_pkt)

        for of_port in config["port_map"].keys():
            logging.info("PacketInMiss test, port %d", of_port)
            self.dataplane.send(of_port, vlan_pkt)

            verify_packet_in(self, vlan_pkt, of_port, ofp.OFPR_NO_MATCH)

            verify_no_other_packets(self)
