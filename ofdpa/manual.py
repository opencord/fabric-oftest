
from oftest import config
import logging
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class McastLeaf1(base_tests.SimpleDataPlane):
    def runTest(self):
        """
        port1 (vlan 300)-> All Ports (vlan 300)
        """
        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return

        vlan_id =300
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

        port1=32
        port2=33

        switch_mac = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x00]

        portlist=[32, 33, 34, 36]

        #add l2 interface group
        l2_intf_group_list=[]
        for port in portlist:
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=4)
            #if port == port2:
            #    continue
            l2_intf_gid, msg=add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
            l2_intf_group_list.append(l2_intf_gid)

        #add termination flow
        add_termination_flow(self.controller, port1, 0x0800, switch_mac, vlan_id)

        #add l3 interface group
        mcat_group_msg=add_l3_mcast_group(self.controller, vlan_id,  2, l2_intf_group_list)
        add_mcast4_routing_flow(self.controller, vlan_id, src_ip, 0, dst_ip, mcat_group_msg.group_id)
        parsed_pkt = simple_udp_packet(pktlen=100,
                                       dl_vlan_enable=True,
                                       vlan_vid=vlan_id,
                                       eth_dst=dst_mac_str,
                                       eth_src=port1_mac_str,
                                       ip_ttl=64,
                                       ip_src=src_ip_str,
                                       ip_dst=dst_ip_str)
        pkt=str(parsed_pkt)
        self.dataplane.send(port1, pkt)
        for port in config["port_map"].keys():
            if port == port1:
                 verify_no_packet(self, pkt, port)
                 continue
            verify_packet(self, pkt, port)
        verify_no_other_packets(self)
        

class Leaf1(base_tests.SimpleDataPlane):

    def runTest(self):
     #Add flows correspondent to Leaf1
     switch_mac=[0x00, 0x00, 0x00, 0x01, 0xea, 0xf1]
     dst_mac= [0x00, 0x00, 0x00, 0x12, 0x34, 0x01]
     id=0x1eaf
     #Add L3Unicast to Host
     port, vlan_id = 33, 4093
     ##add L2 Interface Group
     add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
     ##add L3 Unicast Group
     l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=id, src_mac=switch_mac, 
                                dst_mac=dst_mac)
     add_one_vlan_table_flow(self.controller, of_port=port, vlan_id=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
     ##add Termination Flow
     add_termination_flow(self.controller, port, 0x0800, switch_mac, vlan_id)
     ##add unicast routing flow
     dst_ip=0x0a000001
     mask=0xffffff00
     add_unicast_routing_flow(self.controller, 0x0800, dst_ip, mask, l3_msg.group_id)

     port = 32
     l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
     add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
     add_termination_flow(self.controller, port, 0x0800, switch_mac, vlan_id)

     #Add L3VPN initiation
     dst_mac = [0x00, 0x00, 0x00, 0x55, 0x55, 0x55]
     #add MPLS interface group
     mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid, dst_mac, switch_mac, vlan_id, port)
     ##add L3VPN interface
     mpls_label_gid, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
	 index=id, ref_gid= mpls_gid, push_mpls_header=True, set_mpls_label=20, set_bos=1, cpy_ttl_outward=True)
     ecmp_msg=add_l3_ecmp_group(self.controller, port, [mpls_label_gid])
     ##add unicast routing flow
     dst_ip=0x14000001
     add_unicast_routing_flow(self.controller, 0x0800, dst_ip, mask, ecmp_msg.group_id)
   
     do_barrier(self.controller)

class Leaf2(base_tests.SimpleDataPlane):

    def runTest(self):
     #Add flows correspondent to Leaf1
     switch_mac=[0x00, 0x00, 0x00, 0x01, 0xea, 0xf2]
     dst_mac= [0x00, 0x00, 0x00, 0x12, 0x34, 0x02]
     id=0x2eaf
     #Add L3Unicast to Host
     port, vlan_id = 33, 4093
     ##add L2 Interface Group
     add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
     ##add L3 Unicast Group
     l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=id, src_mac=switch_mac,
                                dst_mac=dst_mac)
     add_one_vlan_table_flow(self.controller, of_port=port, vlan_id=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
     ##add Termination Flow
     add_termination_flow(self.controller, port, 0x0800, switch_mac, vlan_id)
     ##add unicast routing flow
     dst_ip=0x14000001
     mask=0xffffff00
     add_unicast_routing_flow(self.controller, 0x0800, dst_ip, mask, l3_msg.group_id)

     port = 32
     l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
     add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
     add_termination_flow(self.controller, port, 0x0800, switch_mac, vlan_id)

     #Add L3VPN initiation
     dst_mac = [0x00, 0x00, 0x00, 0x55, 0x55, 0x55]
     #add MPLS interface group
     mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid, dst_mac, switch_mac, vlan_id, port)
     ##add L3VPN interface
     mpls_label_gid, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
         index=id, ref_gid= mpls_gid, push_mpls_header=True, set_mpls_label=20, set_bos=1, cpy_ttl_outward=True)
     ecmp_msg=add_l3_ecmp_group(self.controller, id, [mpls_label_gid])
     ##add unicast routing flow
     dst_ip=0x0a000001
     add_unicast_routing_flow(self.controller, 0x0800, dst_ip, mask, ecmp_msg.group_id)

     do_barrier(self.controller)

class Spine(base_tests.SimpleDataPlane):

  def runTest(self):  
     #add Spine Flows
     switch_mac = [0x00, 0x00, 0x00, 0x55, 0x55, 0x55]
     dst_mac = [0x00, 0x00, 0x00, 0x01, 0xea, 0xf1]
     id = 0x55
     #Add MPLS termination 
     port, vlan_id=31, 4093 
     ##add L2 Interface Group
     add_one_l2_interface_group(self.controller, port,  vlan_id=vlan_id, is_tagged=False, send_barrier=False)
     ##add L3 Unicast Group
     l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=id, src_mac=switch_mac,
                                dst_mac=dst_mac)
     ecmp_msg = add_l3_ecmp_group(self.controller, port, [l3_msg.group_id])
     add_one_vlan_table_flow(self.controller, of_port=port, vlan_id=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
     add_termination_flow(self.controller, port, 0x8847, switch_mac, vlan_id, goto_table=24)
     add_mpls_flow(self.controller, ecmp_msg.group_id, 10)
     
     dst_mac = [0x00, 0x00, 0x00, 0x01, 0xea, 0xf2]
     #Add MPLS termination
     port=32
     ##add L2 Interface Group
     add_one_l2_interface_group(self.controller, port,  vlan_id=vlan_id, is_tagged=False, send_barrier=False)
     ##add L3 Unicast Group
     id=id+1
     l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=id, src_mac=switch_mac,
                                dst_mac=dst_mac)
     ecmp_msg = add_l3_ecmp_group(self.controller, port, [l3_msg.group_id])
     add_one_vlan_table_flow(self.controller, of_port=port, vlan_id=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
     add_termination_flow(self.controller, port, 0x8847, switch_mac, vlan_id, goto_table=24)
     add_mpls_flow(self.controller, ecmp_msg.group_id, 20)

class TestLeaf1(base_tests.SimpleDataPlane):

  def runTest(self): 
        host_mac='00:00:00:12:34:01'
        ip_src='10.0.0.1'
        ip_dst='20.0.0.2'
        switch_mac='00:00:00:01:ea:f1'
        parsed_pkt = simple_tcp_packet(pktlen=100, ip_src=ip_src,
                      ip_dst=ip_dst, eth_dst=switch_mac, eth_src=host_mac, ip_ttl=33)
        pkt=str(parsed_pkt)
        self.dataplane.send(33, pkt)

        #build expect packet
        next_hop_mac='00:00:00:55:55:55' 
        switch_mac='00:00:00:01:ea:f1'
        label = (20, 0, 1, 32)
        exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=100, label=[label], 
               eth_dst=next_hop_mac, eth_src=switch_mac, ip_ttl=32, ip_src=ip_src, ip_dst=ip_dst)
        pkt=str(exp_pkt)
        verify_packet(self, pkt, 37)

class TestSpine(base_tests.SimpleDataPlane):

  def runTest(self):
        ip_src='10.0.0.1'
        ip_dst='20.0.0.2'

        #build outgoing packet
        spine_mac='00:00:00:55:55:55'
        switch_mac='00:00:00:01:ea:f2'
        leaf1= '00:00:00:01:ea:f1' 
        label = (20, 0, 1, 32)
        parsed_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=100, label=[label],
               eth_dst=spine_mac, eth_src=leaf1, ip_ttl=32, ip_src=ip_src, ip_dst=ip_dst)
        pkt=str(parsed_pkt)
        self.dataplane.send(33, pkt)

        exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=20, ip_src=ip_src,
                        ip_dst=ip_dst, eth_dst=switch_mac, eth_src=spine_mac, ip_ttl=31)
        pkt=str(exp_pkt)
        verify_packet(self, pkt, 37)

class TestLeaf2(base_tests.SimpleDataPlane):

  def runTest(self):
        host_mac='00:00:00:55:55:55'
        ip_src='10.0.0.1'
        ip_dst='20.0.0.3'
        switch_mac='00:00:00:01:ea:f1'
        parsed_pkt = simple_tcp_packet(pktlen=100, ip_src=ip_src,
                      ip_dst=ip_dst, eth_dst=switch_mac, eth_src=host_mac, ip_ttl=33)
        pkt=str(parsed_pkt)
        self.dataplane.send(33, pkt)
        switch_mac='00:00:00:01:ea:f2'
        host_mac='00:00:00:12:34:02'
        exp_pkt = simple_tcp_packet(pktlen=100, ip_src=ip_src,
                        ip_dst=ip_dst, eth_dst=host_mac, eth_src=switch_mac, ip_ttl=30)
        pkt=str(exp_pkt)
        verify_packet(self, pkt, 37)



