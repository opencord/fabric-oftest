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

class Mtu4500(base_tests.SimpleDataPlane):

    def runTest(self):
        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

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
                parsed_pkt = simple_tcp_packet(pktlen=4500,dl_vlan_enable=True, vlan_vid=1, eth_dst=mac_dst, eth_src=mac_src)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)

                verify_no_other_packets(self)

class L3McastToVPN(base_tests.SimpleDataPlane):
    """
    Mcast routing
    """
    def runTest(self):
        """
        port1 (vlan 1)-> port 2 (vlan 2)
        """
        #delete_all_flows(self.controller)
        #delete_all_groups(self.controller)

        if len(config["port_map"]) <3:
            logging.info("Port count less than 2, can't run this case")
            return

        vlan_id =1
        port2_out_vlan=2
        port3_out_vlan=3
        in_vlan=1 #macast group vid shall use input vlan diffe from l3 interface use output vlan
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        intf_src_mac_str=':'.join(['%02X' % x for x in intf_src_mac])
        dst_mac=[0x01, 0x00, 0x5e, 0x01, 0x01, 0x01]
        dst_mac_str=':'.join(['%02X' % x for x in dst_mac])
        port1_mac=[0x00, 0x11, 0x11, 0x11, 0x11, 0x11]
        port1_mac_str=':'.join(['%02X' % x for x in port1_mac])
        src_ip=0xc0a80101
        src_ip_str="192.168.1.1"
        dst_ip=0xe0010101
        dst_ip_str="224.1.1.1"

        port1=config["port_map"].keys()[0]
        port2=config["port_map"].keys()[1]
        port3=config["port_map"].keys()[2]

        #add l2 interface group
        for port in config["port_map"].keys():
            add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG)
            vlan_id +=1

        #add termination flow
        add_termination_flow(self.controller, port1, 0x0800, [0x01, 0x00, 0x5e, 0x00, 0x00, 0x00], vlan_id)

        #add MPLS interface group
        l2_gid = encode_l2_interface_group_id(port2_out_vlan, port2)
        mpls_gid2, mpls_msg = add_mpls_intf_group(self.controller, l2_gid, dst_mac, intf_src_mac, port2_out_vlan, port2)
        l2_gid3 = encode_l2_interface_group_id(port3_out_vlan, port3)
        mpls_gid3, mpls_msg = add_mpls_intf_group(self.controller, l2_gid3, dst_mac, intf_src_mac, port3_out_vlan, port3)
        #add L3VPN groups
        mpls_label_gid2, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                     index=(0x20000+port2), ref_gid= mpls_gid2, push_mpls_header=True, set_mpls_label=port2, set_bos=1, cpy_ttl_outward=True)
        mpls_label_gid3, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                     index=(0x10000+port3), ref_gid= mpls_gid3, push_mpls_header=True, set_mpls_label=port3, set_bos=1, cpy_ttl_outward=True)



        mcat_group_msg=add_l3_mcast_group(self.controller, in_vlan,  2, [0x92020022 , 0x92010023])
        add_mcast4_routing_flow(self.controller, in_vlan, src_ip, 0, dst_ip, mcat_group_msg.group_id)

        parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=1,
                                       eth_dst=dst_mac_str,
                                       eth_src=port1_mac_str,
                                       ip_ttl=64,
                                       ip_src=src_ip_str,
                                       ip_dst=dst_ip_str)
        pkt=str(parsed_pkt)
        self.dataplane.send(port1, pkt)
        label = (in_vlan, 0, 1, 63)
        parsed_pkt = mpls_packet(pktlen=100,
                                       eth_dst=dst_mac_str,
                                       eth_src=intf_src_mac_str,
                                       ip_ttl=63,
                                       ip_src=src_ip_str, label= [label],
                                       ip_dst=dst_ip_str)
        pkt=str(parsed_pkt)
        verify_packet(self, pkt, port2)
        verify_packet(self, pkt, port3)
        verify_no_other_packets(self)


