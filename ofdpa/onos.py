"""
Flow Test
Test each flow table can set entry, and packet rx correctly.
1) L3UcastRoute
2) QinQ
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class L2Unicast(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return

        vlan_id=1
        mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        for port in config["port_map"].keys():
            #add l2 interface group
            add_one_l2_interface_grouop(self.controller, port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            #add Bridgin table exact match
            group_id = encode_l2_interface_group_id(vlan_id, port)
            mac[5]=port
            add_bridge_flow(self.controller, mac, vlan_id, group_id, True)

        do_barrier(self.controller)

        for outport in config["port_map"].keys():
            mac[5]=outport
            dst_mac=':'.join(['%02X' % x for x in mac])
            for inport in config["port_map"].keys():
             if inport is not outport:
               mac[5]=inport
               src_mac = ':'.join(['%02X' % x for x in mac])
               parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True, vlan_vid=1, eth_dst=dst_mac,
                                       eth_src=src_mac, ip_src="192.168.1.1", ip_dst='192.168.1.2')
               pkt=str(parsed_pkt)
               self.dataplane.send(inport, pkt)
               verify_packet(self, pkt, outport)
               verify_no_other_packets(self)


class L3UcastRoute(base_tests.SimpleDataPlane):
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
        
        vlan_id=1
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip=0xc0a80001
        for port in config["port_map"].keys():
            #add l2 interface group
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
            
            vlan_id += 1
        
        do_barrier(self.controller)  
        
        port1=config["port_map"].keys()[0]
        port2=config["port_map"].keys()[1]
        #port 1 to port 2        
        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        dst_mac[5]=1
        port1_mac=':'.join(['%02X' % x for x in dst_mac])

        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       dl_vlan_enable=True,
                                       vlan_vid=1,
                                       eth_dst=switch_mac,
                                       eth_src=port1_mac,
                                       ip_ttl=64,
                                       ip_src="192.168.1.1",
                                       ip_dst='192.168.2.1')
        pkt=str(parsed_pkt)
        self.dataplane.send(port1, pkt)
        #build expect packet
        dst_mac[5]=2
        port2_mac=':'.join(['%02X' % x for x in dst_mac])  
        exp_pkt = simple_tcp_packet(pktlen=100,
                                       dl_vlan_enable=True,
                                       vlan_vid=2, 
                                       eth_dst=port2_mac,
                                       eth_src=switch_mac,
                                       ip_ttl=63,
                                       ip_src="192.168.1.1",
                                       ip_dst='192.168.2.1')        
        pkt=str(exp_pkt)
        verify_packet(self, pkt, port2)
        verify_no_other_packets(self)

        #port 2 to port 1
        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        dst_mac[5]=2
        port2_mac=':'.join(['%02X' % x for x in dst_mac])  

        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       dl_vlan_enable=True,
                                       vlan_vid=2, 
                                       eth_dst=switch_mac,
                                       eth_src=port2_mac,
                                       ip_ttl=64,
                                       ip_src="192.168.2.1",
                                       ip_dst='192.168.1.1')
        pkt=str(parsed_pkt)                                       
        self.dataplane.send(port2, pkt)
        #build expect packet
        dst_mac[5]=1
        port1_mac=':'.join(['%02X' % x for x in dst_mac])  
        exp_pkt = simple_tcp_packet(pktlen=100,
                                       dl_vlan_enable=True,
                                       vlan_vid=1,
                                       eth_dst=port1_mac,
                                       eth_src=switch_mac,
                                       ip_ttl=63,
                                       ip_src="192.168.2.1",
                                       ip_dst='192.168.1.1')        
        pkt=str(exp_pkt) 
        verify_packet(self, pkt, port1)
        verify_no_other_packets(self)    

