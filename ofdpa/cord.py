"""
The following tests are being done here
1) PacketInSrcMacMiss
2) VlanSupport
3) L2FloodQinQ
4) L2FloodTagged
5) L2Flood Tagged Unknown Src
6) L2 Unicast Tagged
7) MTU 1500
8) MTU 4100
9) MTU 4500
10) L3UnicastTagged
11) L3VPNMPLS
12) MPLS Termination
"""

from oftest import config
import logging
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class VlanSupport(base_tests.SimpleDataPlane):
    """
    Test L2 forwarding of both, untagged and double-tagged packets
    Sends a packet and expects the same packet on the other port
    Repeats for double tagged
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        ports = sorted(config["port_map"].keys())
        # group table
        # set up untag groups for each port
        add_l2_interface_group(self.controller, config["port_map"].keys(), 4093, False, 1)
        for port in ports:
            add_one_vlan_table_flow(self.controller, port, 4093, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            group_id = encode_l2_interface_group_id(4093, port)
            add_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, port], 4093, group_id, True)
            #add flow match for vlan 300
            add_one_l2_interface_group(self.controller, port, 300, True, False)
            add_one_vlan_table_flow(self.controller, port, 300, flag=VLAN_TABLE_FLAG_ONLY_TAG)
        msg=add_l2_flood_group(self.controller, ports, 300, 1)
        add_bridge_flow(self.controller, None, 300, msg.group_id, True)
        msg=add_l2_flood_group(self.controller, ports, 4093, 1)
        add_bridge_flow(self.controller, None, 4093, msg.group_id, True)
        do_barrier(self.controller)

        for out_port in ports:
            # change dest based on port number
            mac_dst= '00:12:34:56:78:%02X' % out_port

            for in_port in ports:
                if in_port == out_port:
                    continue
                # change source based on port number to avoid packet-ins from learning
                mac_src= '00:12:34:56:78:%02X' % in_port
                #sends an untagged packet
                parsed_pkt = simple_tcp_packet(dl_vlan_enable=False, vlan_vid=4093, eth_dst=mac_dst, eth_src=mac_src)
                pkt = str(parsed_pkt)
                logging.info("OutputExact test, ports %d to %d", in_port, out_port)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport is out_port:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)

                verify_no_other_packets(self)
                # sends a double tagged packet
                parsed_pkt = simple_tcp_packet_two_vlan(pktlen=108, out_dl_vlan_enable=True, out_vlan_vid=300,
                                                in_dl_vlan_enable=True, in_vlan_vid=10, eth_dst='00:12:34:56:78:9a', eth_src=mac_src)
                pkt = str(parsed_pkt)
                logging.info("OutputExact test, ports %d to %d", in_port, out_port)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport is in_port:
                        verify_no_packet(self, pkt, ofport)
                    else:
                        verify_packet(self, pkt, ofport)

                verify_no_other_packets(self)

class UniqueMplsTermination(base_tests.SimpleDataPlane):
    """
        Insert IP packet
        Receive MPLS packet
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return

        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        mcast_mac = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]

        dip=0xc0a80001
        index=1
        ports = config["port_map"].keys()
        for port in ports:
            #add l2 interface group
            vlan_id=port
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port, vlan_id, True, False)
            dst_mac[5]=vlan_id
            #add L3 Unicast  group
            l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=intf_src_mac, dst_mac=dst_mac)
            #add L3 ecmp group
            ecmp_msg = add_l3_ecmp_group(self.controller, port, [l3_msg.group_id])
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG)
            #add termination flow
            add_termination_flow(self.controller, port, 0x8847, intf_src_mac, vlan_id, goto_table=24)
            #add routing flow
            dst_ip = dip + (vlan_id<<8)
            add_mpls_flow(self.controller, ecmp_msg.group_id, port)
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

                label = (out_port, 0, 1, 32)
                parsed_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=in_port, ip_src=ip_src,
                             ip_dst=ip_dst, eth_dst=switch_mac, eth_src=mac_src, label=[label])
                pkt=str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                #build expect packet
                mac_dst='00:00:00:22:22:%02X' % out_port
                mcast='01:00:5e:00:00:01'
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=out_port,
                    eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=31, ip_src=ip_src, ip_dst=ip_dst)
                pkt=str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)  
