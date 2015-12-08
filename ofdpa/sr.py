
from oftest import config
import logging
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class Leaf1(base_tests.SimpleDataPlane):

    def runTest(self):
     #Add flows correspondent to Leaf1
     switch_mac=[0x00, 0x00, 0x00, 0x01, 0xea, 0xf1]
     dst_mac= [0x00, 0x00, 0x00, 0x12, 0x34, 0x01]
     #Add L3Unicast to Host
     port, vlan_id = 33, 10
     ##add L2 Interface Group
     add_one_l2_interface_grouop(self.controller, port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
     ##add L3 Unicast Group
     l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=switch_mac, 
                                dst_mac=dst_mac)
     add_one_vlan_table_flow(self.controller, of_port=port, vlan_id=vlan_id, vrf=vlan_id,
                             flag=VLAN_TABLE_FLAG_ONLY_TAG)
     ##add Termination Flow
     add_termination_flow(self.controller, port, 0x0800, switch_mac, vlan_id)
     ##add unicast routing flow
     dst_ip=0x0a000001
     mask=0xffffff00
     add_unicast_routing_flow(self.controller, 0x0800, dst_ip, mask, l3_msg.group_id, vrf=10)
     #add entries in the Bridging table to avoid packet-in from mac learning
     group_id = encode_l2_interface_group_id(vlan_id, port)
     add_bridge_flow(self.controller, dst_mac, vlan_id, group_id, True)

     port = 32
     add_one_l2_interface_grouop(self.controller, port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
     add_one_vlan_table_flow(self.controller, port, vlan_id, vrf=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG)
     add_termination_flow(self.controller, port, 0x0800, switch_mac, vlan_id)
     do_barrier(self.controller)

     #Add L3VPN initiation
     dst_mac = [0x00, 0x00, 0x00, 0x55, 0x55, 0x55]
     vlan_id = 100
     ##add L2 Interface Group
     l2_gid, l2_msg = add_one_l2_interface_grouop(self.controller, port, vlan_id=vlan_id, is_tagged=True, send_barrier=False) 
     #add MPLS interface group
     mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid, dst_mac, switch_mac, vlan_id, port)
     ##add L3VPN interface
     mpls_label_gid, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
	 index=port, ref_gid= mpls_gid, push_mpls_header=True, set_mpls_label=20, set_bos=1, set_ttl=32)
     ##add unicast routing flow
     dst_ip=0x14000001
     add_unicast_routing_flow(self.controller, 0x0800, dst_ip, mask, mpls_label_gid, vrf=10)
   
     #add entries in the Bridging table to avoid packet-in from mac learning
     group_id = encode_l2_interface_group_id(vlan_id, port)
     add_bridge_flow(self.controller, dst_mac, vlan_id, group_id, True)
 
     do_barrier(self.controller)

class Leaf2(base_tests.SimpleDataPlane):

  def runTest(self):  
     #Add flows correspondent to Leaf2
     switch_mac=[0x00, 0x00, 0x00, 0x01, 0xea, 0xf2]
     dst_mac= [0x00, 0x00, 0x00, 0x12, 0x34, 0x02]
     #Add L3Unicast to Host
     port, vlan_id=33, 20
     ##add L2 Interface Group
     add_one_l2_interface_grouop(self.controller, port,  vlan_id=vlan_id, is_tagged=True, send_barrier=False) 
     ##add L3 Unicast Group
     l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=switch_mac,
                                dst_mac=dst_mac)
     add_one_vlan_table_flow(self.controller, port, vlan_id, vrf=20, flag=VLAN_TABLE_FLAG_ONLY_TAG)
     ##add Termination Flow
     add_termination_flow(self.controller, port, 0x0800, switch_mac, vlan_id)
     ##add unicast routing flow
     dst_ip=0x14000001
     mask=0xffffff00
     add_unicast_routing_flow(self.controller, 0x0800, dst_ip, mask, l3_msg.group_id, vrf=vlan_id)
     #add entries in the Bridging table to avoid packet-in from mac learning
     group_id = encode_l2_interface_group_id(vlan_id, port)
     add_bridge_flow(self.controller, dst_mac, vlan_id, group_id, True)

     port = 32
     add_one_l2_interface_grouop(self.controller, port,  vlan_id=vlan_id, is_tagged=True, send_barrier=False) 
     add_one_vlan_table_flow(self.controller, port, vlan_id, vrf=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG)
     add_termination_flow(self.controller, port, 0x0800, switch_mac, vlan_id)
     do_barrier(self.controller)

     #Add L3VPN initiation
     dst_mac= [0x00, 0x00, 0x00, 0x55, 0x55, 0x55]
     vlan_id = 100
     ##add L2 Interface Group
     l2_gid, l2_msg = add_one_l2_interface_grouop(self.controller, port,  vlan_id=vlan_id, is_tagged=True, send_barrier=False) 
     #add MPLS interface group
     mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid, dst_mac, switch_mac, vlan_id, port)
     ##add L3VPN interface
     mpls_label_gid, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,  
         index=port, ref_gid= mpls_gid, push_mpls_header=True, set_mpls_label=10, set_bos=1, set_ttl=32)
     ##add unicast routing flow
     dst_ip=0x0a000001
     add_unicast_routing_flow(self.controller, 0x0800, dst_ip, mask, mpls_label_gid, vrf=20)
     #add entries in the Bridging table to avoid packet-in from mac learning
     group_id = encode_l2_interface_group_id(vlan_id, port)
     add_bridge_flow(self.controller, dst_mac, vlan_id, group_id, True)

class Spine(base_tests.SimpleDataPlane):

  def runTest(self):  
     #add Spine Flows
     switch_mac = [0x00, 0x00, 0x00, 0x55, 0x55, 0x55]
     dst_mac = [0x00, 0x00, 0x00, 0x01, 0xea, 0xf1]
     #Add MPLS termination 
     port, vlan_id=31, 10 
     ##add L2 Interface Group
     add_one_l2_interface_grouop(self.controller, port,  vlan_id=vlan_id, is_tagged=True, send_barrier=False) 
     ##add L3 Unicast Group
     l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=switch_mac,
                                dst_mac=dst_mac)
     ecmp_msg = add_l3_ecmp_group(self.controller, port, [l3_msg.group_id])
     vlan_id=100
     add_one_vlan_table_flow(self.controller, of_port=port, vlan_id=100, flag=VLAN_TABLE_FLAG_ONLY_TAG)
     add_termination_flow(self.controller, port, 0x8847, switch_mac, vlan_id, goto_table=24)
     add_mpls_flow(self.controller, ecmp_msg.group_id, 10)
     #add entries in the Bridging table to avoid packet-in from mac learning
     group_id = encode_l2_interface_group_id(100, port)
     add_bridge_flow(self.controller, dst_mac, 100, group_id, True)
     
     dst_mac = [0x00, 0x00, 0x00, 0x01, 0xea, 0xf2]
     #Add MPLS termination
     port, vlan_id=32, 20
     ##add L2 Interface Group
     add_one_l2_interface_grouop(self.controller, port,  vlan_id=vlan_id, is_tagged=True, send_barrier=False) 
     ##add L3 Unicast Group
     l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=switch_mac,
                                dst_mac=dst_mac)
     ecmp_msg = add_l3_ecmp_group(self.controller, port, [l3_msg.group_id])
     add_one_vlan_table_flow(self.controller, of_port=port, vlan_id=100, flag=VLAN_TABLE_FLAG_ONLY_TAG)
     vlan_id=100
     add_termination_flow(self.controller, port, 0x8847, switch_mac, vlan_id, goto_table=24)
     add_mpls_flow(self.controller, ecmp_msg.group_id, 20)
     #add entries in the Bridging table to avoid packet-in from mac learning
     group_id = encode_l2_interface_group_id(100, port)
     add_bridge_flow(self.controller, dst_mac, 100, group_id, True)

class TestLeaf1(base_tests.SimpleDataPlane):

  def runTest(self): 
        host_mac='00:00:00:12:34:01'
        ip_src='10.0.0.1'
        ip_dst='20.0.0.2'
        switch_mac='00:00:00:01:ea:f1'
        parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=10, ip_src=ip_src,
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
        parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=10, ip_src=ip_src,
                      ip_dst=ip_dst, eth_dst=switch_mac, eth_src=host_mac, ip_ttl=33)
        pkt=str(parsed_pkt)
        self.dataplane.send(33, pkt)
        switch_mac='00:00:00:01:ea:f2'
        host_mac='00:00:00:12:34:02'
        exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=20, ip_src=ip_src,
                        ip_dst=ip_dst, eth_dst=host_mac, eth_src=switch_mac, ip_ttl=30)
        pkt=str(exp_pkt)
        verify_packet(self, pkt, 37)



