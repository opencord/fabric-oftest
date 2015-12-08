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
        
        test_macs = [[0x01, 0x00, 0x5e, 0x0f, 0xff, 0xff]]

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
        add_vlan_table_flow(self.controller, config["port_map"].keys())

        # group table
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
                logging.info("OutputExact test, ports %d to %d", in_port, out_port)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)
                        
                verify_no_other_packets(self)

class L2Flood(base_tests.SimpleDataPlane):
    """
    Test L2 unknown unicast flooding and broadcast flood
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        # table 10: vlan
        # send to table 20
        add_vlan_table_flow(self.controller, ports, 1)

        # group table
        # set up untag groups for each port
        add_l2_interface_grouop(self.controller, ports, 1,  False, 1)

        input_port = ports.pop()
        flood_ports= ports
    
        #no fllod group create, veriy all drop
        parsed_pkt = simple_tcp_packet(eth_dst='00:12:34:56:78:9a')
        pkt = str(parsed_pkt)
        self.dataplane.send(input_port, pkt)
        verify_no_other_packets(self)
        parsed_pkt = simple_tcp_packet(eth_dst='FF:FF:FF:FF:FF:FF')
        pkt = str(parsed_pkt)
        self.dataplane.send(input_port, pkt)
        verify_no_other_packets(self)        
        #add flood groupo    
        msg=add_l2_flood_group(self.controller, flood_ports, 1, 1)
        add_bridge_flow(self.controller, None, 1, msg.group_id, True)
        #verify flood 
        parsed_pkt = simple_tcp_packet(eth_dst='00:12:34:56:78:9a')
        pkt = str(parsed_pkt)
        self.dataplane.send(input_port, pkt)
        for ofport in flood_ports:
            verify_packet(self, pkt, ofport)

        verify_no_other_packets(self)
               
        for ofport in flood_ports:
            self.dataplane.send(ofport, pkt)
            #self won't rx packet
            verify_no_packet(self, pkt, ofport)
            #others will rx packet
            tmp_ports=[]
            for tmp in flood_ports:
                if tmp != ofport:
                    tmp_ports.append(tmp)                
            verify_packets(self, pkt, tmp_ports)
            
        verify_no_other_packets(self)

        parsed_pkt = simple_tcp_packet(eth_dst='FF:FF:FF:FF:FF:FF')
        pkt = str(parsed_pkt)
        self.dataplane.send(input_port, pkt)
        for ofport in flood_ports:
            verify_packet(self, pkt, ofport)        
        
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
            if config["cicada_poject"]:
                verify_packet_in(self, vlan_pkt, of_port, ofp.OFPR_ACTION)
            else:
                verify_packet_in(self, pkt, of_port, ofp.OFPR_ACTION)

            verify_no_other_packets(self)

class PacketOut(base_tests.SimpleDataPlane):
    """
    Verify action Flood, ALL, in port
    """

    def runTest(self):
        if config["cicada_poject"]:
            pass
            
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        
        parsed_pkt = simple_tcp_packet(pktlen=100)
        parsed_vlan_pkt = simple_tcp_packet(pktlen=104, 
                      vlan_vid=0x1002, dl_vlan_enable=True)
                      
        pkt = str(parsed_pkt)
        vlan_pkt = str(parsed_vlan_pkt)
       
        
        #packet out flood, untag packet
        self.controller.message_send(ofp.message.packet_out(in_port=ofp.OFPP_CONTROLLER,
                                                            buffer_id=ofp.OFP_NO_BUFFER,
                                                            actions=[ofp.action.output(
                                                                     port=ofp.OFPP_FLOOD)],
                                                            data=pkt)) 

        for of_port in config["port_map"].keys():
            verify_packet(self, pkt, of_port)

        verify_no_other_packets(self)

        #packet out flood, tag packet, because it can't identify vlan has which port
        #so we do as all action.
        self.controller.message_send(ofp.message.packet_out(in_port=ofp.OFPP_CONTROLLER,
                                                            buffer_id=ofp.OFP_NO_BUFFER,
                                                            actions=[ofp.action.output(
                                                                     port=ofp.OFPP_FLOOD)],
                                                            data=vlan_pkt)) 

        for of_port in config["port_map"].keys():
            verify_packet(self, vlan_pkt, of_port)

        verify_no_other_packets(self)

        #packet out all
        self.controller.message_send(ofp.message.packet_out(in_port=ofp.OFPP_CONTROLLER,
                                                            buffer_id=ofp.OFP_NO_BUFFER,
                                                            actions=[ofp.action.output(
                                                                     port=ofp.OFPP_FLOOD)],
                                                            data=pkt)) 

        for of_port in config["port_map"].keys():
            verify_packet(self, pkt, of_port)

        verify_no_other_packets(self)        
        
        #packet out to in port
        in_port = config["port_map"].keys()[0]
        self.controller.message_send(ofp.message.packet_out(in_port=in_port,
                                                            buffer_id=ofp.OFP_NO_BUFFER,
                                                            actions=[ofp.action.output(
                                                                     port=in_port)],
                                                            data=pkt)) 

        verify_packet(self, pkt, in_port)
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
            add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
            dst_mac[5]=vlan_id
            l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=intf_src_mac, dst_mac=dst_mac)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            #add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac, vlan_id)           
            #add unicast routing flow
            dst_ip = dip + (vlan_id<<8)           
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0, l3_msg.group_id)            
            vlan_id += 1
        
        do_barrier(self.controller)  
        
        port1=config["port_map"].keys()[0]
        port2=config["port_map"].keys()[1]
        #port 1 to port 2        
        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        dst_mac[5]=1
        port1_mac=':'.join(['%02X' % x for x in dst_mac])

        parsed_pkt = simple_tcp_packet(pktlen=100, 
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
                                       eth_dst=port1_mac,
                                       eth_src=switch_mac,
                                       ip_ttl=63,
                                       ip_src="192.168.2.1",
                                       ip_dst='192.168.1.1')        
        pkt=str(exp_pkt) 
        verify_packet(self, pkt, port1)
        verify_no_other_packets(self)    

class L3UcastRouteOnSamVLANSamPort(base_tests.SimpleDataPlane):
    """
    Port1(vlan1, 0x00, 0x00, 0x00, 0x22, 0x22, 0x01, 192.168.1.1) , 
    Port1(vlan1, 0x00, 0x00, 0x00, 0x22, 0x22, 0x02, 19.168.2.1)
    """	
    def runTest(self):          
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        port = config["port_map"].keys()[0]
		
        vlan_id=1
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        port_mac1=[0x00, 0x00, 0x00, 0x22, 0x22, 0x01]
        port_mac2=[0x00, 0x00, 0x00, 0x22, 0x22, 0x02]
        port_ip1=0xc0a80101        
        port_ip1_str=convertIP4toStr(port_ip1)
        port_ip2=0xc0a80201
        port_ip2_str=convertIP4toStr(port_ip2)
		#add l2 interface group
        add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
		#add vlan flow table
        add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
		#add termination flow
        add_termination_flow(self.controller, port, 0x0800, intf_src_mac, vlan_id)           

        """192.168.1.1->192.168.2.1"""
        l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=1, src_mac=intf_src_mac, dst_mac=port_mac2)
        add_unicast_routing_flow(self.controller, 0x0800, port_ip2, 0, l3_msg.group_id)            
        """192.168.1.1->192.168.2.1"""
        l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=2, src_mac=intf_src_mac, dst_mac=port_mac1)
        add_unicast_routing_flow(self.controller, 0x0800, port_ip1, 0, l3_msg.group_id)            
 
        do_barrier(self.controller)  
		
        """send packet to verify"""
        """192.168.1.1->192.168.2.1"""        
        switch_mac_str = convertMACtoStr(intf_src_mac)
        port_mac1_str  = convertMACtoStr(port_mac1)
        port_mac2_str  = convertMACtoStr(port_mac2)
        ttl=64
		#send packet
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac_str,
                                       eth_src=port_mac1_str,
                                       ip_ttl=ttl,
                                       ip_src=port_ip1_str,
                                       ip_dst=port_ip2_str)
        pkt=str(parsed_pkt)
        self.dataplane.send(port, pkt)
        #build expect packet
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=port_mac2_str,
                                       eth_src=switch_mac_str,
                                       ip_ttl=(ttl-1),
                                       ip_src=port_ip1_str,
                                       ip_dst=port_ip2_str)
        pkt=str(exp_pkt)
        verify_packet(self, pkt, port)
        verify_no_other_packets(self)

        """192.168.2.1->192.168.1.1"""
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac_str,
                                       eth_src=port_mac2_str,
                                       ip_ttl=ttl,
                                       ip_src=port_ip2_str,
                                       ip_dst=port_ip1_str)
        pkt=str(parsed_pkt)                                       
        self.dataplane.send(port, pkt)
        #build expect packet
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=port_mac1_str,
                                       eth_src=switch_mac_str,
                                       ip_ttl=(ttl-1),
                                       ip_src=port_ip2_str,
                                       ip_dst=port_ip1_str)        
        pkt=str(exp_pkt) 
        verify_packet(self, pkt, port)
        verify_no_other_packets(self)    

class L3UcastRouteOnDiffVLANSamPort(base_tests.SimpleDataPlane):
    """
    Port1(vlan1, 0x00, 0x00, 0x00, 0x22, 0x22, 0x01, 192.168.1.1) , 
    Port1(vlan2, 0x00, 0x00, 0x00, 0x22, 0x22, 0x02, 19.168.2.1)
    """	
    def runTest(self):          
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        port = config["port_map"].keys()[0]
		
        port_vlan_id1=1
        port_vlan_id2=2
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        port_mac1=[0x00, 0x00, 0x00, 0x22, 0x22, 0x01]
        port_mac2=[0x00, 0x00, 0x00, 0x22, 0x22, 0x02]
        port_ip1=0xc0a80101
        port_ip1_str=convertIP4toStr(port_ip1)
        port_ip2=0xc0a80201
        port_ip2_str=convertIP4toStr(port_ip2)
		#add l2 interface group
        add_one_l2_interface_group(self.controller, port, vlan_id=port_vlan_id1, is_tagged=True, send_barrier=False)
        add_one_l2_interface_group(self.controller, port, vlan_id=port_vlan_id2, is_tagged=True, send_barrier=False)
		#add vlan flow table
        add_one_vlan_table_flow(self.controller, port, port_vlan_id1, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
        add_one_vlan_table_flow(self.controller, port, port_vlan_id2, flag=VLAN_TABLE_FLAG_ONLY_BOTH)		
		#add termination flow
        add_termination_flow(self.controller, port, 0x0800, intf_src_mac, port_vlan_id1)           
        add_termination_flow(self.controller, port, 0x0800, intf_src_mac, port_vlan_id2)           
		
        """192.168.1.1->192.168.2.1"""
        l3_msg=add_l3_unicast_group(self.controller, port, vlanid=port_vlan_id2, id=1, src_mac=intf_src_mac, dst_mac=port_mac2)
        add_unicast_routing_flow(self.controller, 0x0800, port_ip2, 0, l3_msg.group_id)            
        """192.168.1.1->192.168.2.1"""
        l3_msg=add_l3_unicast_group(self.controller, port, vlanid=port_vlan_id1, id=2, src_mac=intf_src_mac, dst_mac=port_mac1)
        add_unicast_routing_flow(self.controller, 0x0800, port_ip1, 0, l3_msg.group_id)            
 
        do_barrier(self.controller)  
		
        """send packet to verify"""  
        """192.168.1.1->192.168.2.1"""        
        switch_mac_str =convertMACtoStr(intf_src_mac)
        port_mac1_str= convertMACtoStr(port_mac1)
        port_mac2_str= convertMACtoStr(port_mac2)
        ttl=64
		#send packet
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac_str,
                                       eth_src=port_mac1_str,
									   dl_vlan_enable=True,
									   vlan_vid=port_vlan_id1,									   
                                       ip_ttl=ttl,
                                       ip_src=port_ip1_str,
                                       ip_dst=port_ip2_str)
        pkt=str(parsed_pkt)
        self.dataplane.send(port, pkt)
        #build expect packet
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=port_mac2_str,
                                       eth_src=switch_mac_str,
									   dl_vlan_enable=True,
									   vlan_vid=port_vlan_id2,									   
                                       ip_ttl=(ttl-1),
                                       ip_src=port_ip1_str,
                                       ip_dst=port_ip2_str)
        pkt=str(exp_pkt)
        verify_packet(self, pkt, port)
        verify_no_other_packets(self)

        """192.168.2.1->192.168.1.1"""
        switch_mac = convertMACtoStr(intf_src_mac)
        port_mac2_str=convertMACtoStr(port_mac2)

        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac_str,
                                       eth_src=port_mac2_str,
									   dl_vlan_enable=True,
									   vlan_vid=port_vlan_id2,									   
                                       ip_ttl=ttl,
                                       ip_src=port_ip2_str,
                                       ip_dst=port_ip1_str)
        pkt=str(parsed_pkt)                                       
        self.dataplane.send(port, pkt)
        #build expect packet
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=port_mac1_str,
                                       eth_src=switch_mac_str,
									   dl_vlan_enable=True,
									   vlan_vid=port_vlan_id1,
                                       ip_ttl=(ttl-1),
                                       ip_src=port_ip2_str,
                                       ip_dst=port_ip1_str)        
        pkt=str(exp_pkt) 
        verify_packet(self, pkt, port)
        verify_no_other_packets(self)    
		
class L3UcastVrfRouteOnSamVLANSamPort(base_tests.SimpleDataPlane):
    """
    Port1(vlan1, VRF1, 0x00, 0x00, 0x00, 0x22, 0x22, 0x01, 192.168.1.1) , 
    Port1(vlan1, VRF1, 0x00, 0x00, 0x00, 0x22, 0x22, 0x02, 19.168.2.1)
    Port1(vlan2, VRF2, 0x00, 0x00, 0x00, 0x22, 0x22, 0x01, 192.168.1.1) , 
    Port1(vlan2, VRF2, 0x00, 0x00, 0x00, 0x22, 0x22, 0x02, 19.168.2.1)
    
    """	
    def runTest(self):          
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        port = config["port_map"].keys()[0]
		
        vrf1=1
        vrf2=2
        vrf1_vlan_id=1
        vrf2_vlan_id=2
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        port_mac1=[0x00, 0x00, 0x00, 0x22, 0x22, 0x01]
        port_mac2=[0x00, 0x00, 0x00, 0x22, 0x22, 0x02]
        port_ip1=0xc0a80101        
        port_ip1_str=convertIP4toStr(port_ip1)
        port_ip2=0xc0a80201
        port_ip2_str=convertIP4toStr(port_ip2)
		#add l2 interface group
        add_one_l2_interface_group(self.controller, port, vlan_id=vrf1_vlan_id, is_tagged=True, send_barrier=False)
        add_one_l2_interface_group(self.controller, port, vlan_id=vrf2_vlan_id, is_tagged=True, send_barrier=False)
		#add vlan flow table
        add_one_vlan_table_flow(self.controller, port, vrf1_vlan_id, vrf=vrf1, flag=VLAN_TABLE_FLAG_ONLY_TAG)
        add_one_vlan_table_flow(self.controller, port, vrf2_vlan_id, vrf=vrf2, flag=VLAN_TABLE_FLAG_ONLY_TAG)
        
		#add termination flow
        add_termination_flow(self.controller, 0, 0x0800, intf_src_mac, vrf1_vlan_id)
        add_termination_flow(self.controller, 0, 0x0800, intf_src_mac, vrf2_vlan_id)
        
        """192.168.1.1->192.168.2.1"""
        l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vrf1_vlan_id, id=1, src_mac=intf_src_mac, dst_mac=port_mac2)
        add_unicast_routing_flow(self.controller, 0x0800, port_ip2, 0, l3_msg.group_id, vrf1)
        l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vrf2_vlan_id, id=2, src_mac=intf_src_mac, dst_mac=port_mac2)
        add_unicast_routing_flow(self.controller, 0x0800, port_ip2, 0, l3_msg.group_id, vrf2)
        
        """192.168.1.1->192.168.2.1"""
        l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vrf1_vlan_id, id=3, src_mac=intf_src_mac, dst_mac=port_mac1)
        add_unicast_routing_flow(self.controller, 0x0800, port_ip1, 0, l3_msg.group_id, vrf1)
        l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vrf2_vlan_id, id=4, src_mac=intf_src_mac, dst_mac=port_mac1)
        add_unicast_routing_flow(self.controller, 0x0800, port_ip1, 0, l3_msg.group_id, vrf2)
        
        do_barrier(self.controller)  
	
        """send packet to verify on VRF vrf1"""
        """192.168.1.1->192.168.2.1"""        
        switch_mac_str = convertMACtoStr(intf_src_mac)
        port_mac1_str  = convertMACtoStr(port_mac1)
        port_mac2_str  = convertMACtoStr(port_mac2)
        ttl=64
		#send packet
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac_str,
                                       eth_src=port_mac1_str,
                                       dl_vlan_enable=True,
                                       vlan_vid=vrf1_vlan_id,
                                       ip_ttl=ttl,
                                       ip_src=port_ip1_str,
                                       ip_dst=port_ip2_str)
        pkt=str(parsed_pkt)
        self.dataplane.send(port, pkt)
        #build expect packet
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=port_mac2_str,
                                       eth_src=switch_mac_str,
                                       dl_vlan_enable=True,
                                       vlan_vid=vrf1_vlan_id,                                       
                                       ip_ttl=(ttl-1),
                                       ip_src=port_ip1_str,
                                       ip_dst=port_ip2_str)
        pkt=str(exp_pkt)
        verify_packet(self, pkt, port)
        verify_no_other_packets(self)

        """192.168.2.1->192.168.1.1"""
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac_str,
                                       eth_src=port_mac2_str,
                                       dl_vlan_enable=True,
                                       vlan_vid=vrf1_vlan_id,                                       
                                       ip_ttl=ttl,
                                       ip_src=port_ip2_str,
                                       ip_dst=port_ip1_str)
        pkt=str(parsed_pkt)                                       
        self.dataplane.send(port, pkt)
        #build expect packet
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=port_mac1_str,
                                       eth_src=switch_mac_str,
                                       dl_vlan_enable=True,
                                       vlan_vid=vrf1_vlan_id,                                       
                                       ip_ttl=(ttl-1),
                                       ip_src=port_ip2_str,
                                       ip_dst=port_ip1_str)        
        pkt=str(exp_pkt) 
        verify_packet(self, pkt, port)
        verify_no_other_packets(self)    
       
		
        """send packet to verify on VRF vrf2"""
        """192.168.1.1->192.168.2.1"""        
        switch_mac_str = convertMACtoStr(intf_src_mac)
        port_mac1_str  = convertMACtoStr(port_mac1)
        port_mac2_str  = convertMACtoStr(port_mac2)
        ttl=64
		#send packet
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac_str,
                                       eth_src=port_mac1_str,
                                       dl_vlan_enable=True,
                                       vlan_vid=vrf2_vlan_id,
                                       ip_ttl=ttl,
                                       ip_src=port_ip1_str,
                                       ip_dst=port_ip2_str)
        pkt=str(parsed_pkt)
        self.dataplane.send(port, pkt)
        #build expect packet
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=port_mac2_str,
                                       eth_src=switch_mac_str,
                                       dl_vlan_enable=True,
                                       vlan_vid=vrf2_vlan_id,                                       
                                       ip_ttl=(ttl-1),
                                       ip_src=port_ip1_str,
                                       ip_dst=port_ip2_str)
        pkt=str(exp_pkt)
        verify_packet(self, pkt, port)
        verify_no_other_packets(self)

        """192.168.2.1->192.168.1.1"""
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac_str,
                                       eth_src=port_mac2_str,
                                       dl_vlan_enable=True,
                                       vlan_vid=vrf2_vlan_id,                                       
                                       ip_ttl=ttl,
                                       ip_src=port_ip2_str,
                                       ip_dst=port_ip1_str)
        pkt=str(parsed_pkt)                                       
        self.dataplane.send(port, pkt)
        #build expect packet
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=port_mac1_str,
                                       eth_src=switch_mac_str,
                                       dl_vlan_enable=True,
                                       vlan_vid=vrf2_vlan_id,                                       
                                       ip_ttl=(ttl-1),
                                       ip_src=port_ip2_str,
                                       ip_dst=port_ip1_str)        
        pkt=str(exp_pkt) 
        verify_packet(self, pkt, port)
        verify_no_other_packets(self)          
        
        
		  
                
class L3UcastECMP(base_tests.SimpleDataPlane):
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
            add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
            dst_mac[5]=vlan_id
            l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=intf_src_mac, dst_mac=dst_mac)            
            ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [l3_msg.group_id])
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            #add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac, vlan_id)           
            #add unicast routing flow
            dst_ip = dip + (vlan_id<<8)
            #ECMP shall have prefix not 32
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0xffffff00, ecmp_msg.group_id)            
            vlan_id += 1
        
        do_barrier(self.controller)  
        
        port1=config["port_map"].keys()[0]
        port2=config["port_map"].keys()[1]
        #port 1 to port 2        
        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        dst_mac[5]=1
        port1_mac=':'.join(['%02X' % x for x in dst_mac])

        parsed_pkt = simple_tcp_packet(pktlen=100, 
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
                                       eth_dst=port1_mac,
                                       eth_src=switch_mac,
                                       ip_ttl=63,
                                       ip_src="192.168.2.1",
                                       ip_dst='192.168.1.1')        
        pkt=str(exp_pkt) 
        verify_packet(self, pkt, port1)
        verify_no_other_packets(self)    

                
class L3UcastECMP2(base_tests.SimpleDataPlane):
    """
    Port1(vlan1, 0x00, 0x00, 0x00, 0x22, 0x22, 0x01, 192.168.1.1) , 
    Port2(vlan2, 0x00, 0x00, 0x00, 0x22, 0x22, 0x02, 19.168.2.1)
    Portn(vlann, 0x00, 0x00, 0x00, 0x22, 0x22, 0x0n, 19.168.n.1)    
    """
    
    def runTest(self):          
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        if len(config["port_map"]) <3:
            logging.info("Port count less than 3, can't run this case")
            return
        
        vlan_id=1
        intf_src_mac=[0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        same_dst_mac=[0x00, 0x00, 0x00, 0x22, 0x22, 0x22]

        l3_ucast_gips=[]        
        tx_port = config["port_map"].keys()[0]        
        for port in config["port_map"].keys():
            #add l2 interface group
            add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
            if tx_port != port:            
                l3_msg=add_l3_unicast_group(self.controller, port, vlanid=vlan_id, id=vlan_id, src_mac=intf_src_mac, dst_mac=same_dst_mac)            
                l3_ucast_gips.append(l3_msg.group_id)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            #add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac, vlan_id)           
            vlan_id += 1

        tx_dip=0x0a0a0a0a
        tx_sip=0x0b0a0a0a             
        ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, l3_ucast_gips)            
        #ECMP shall have prefix not 32
        add_unicast_routing_flow(self.controller, 0x0800, tx_dip, 0xffffff00, ecmp_msg.group_id)            

        do_barrier(self.controller)          

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        packet_src_mac="00:00:33:44:55:66"
        #from unknown src ip to unknown dst ip, to verify ecmp
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac,
                                       eth_src=packet_src_mac,
                                       ip_ttl=64,
                                       ip_src=convertIP4toStr(tx_sip),
                                       ip_dst=convertIP4toStr(tx_dip))
        self.dataplane.send(tx_port, str(parsed_pkt))
        #build expect packet
        dst_mac=':'.join(['%02X' % x for x in same_dst_mac])
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                   eth_dst=dst_mac,
                                   eth_src=switch_mac,
                                   ip_ttl=63,
                                   ip_src=convertIP4toStr(tx_sip),
                                   ip_dst=convertIP4toStr(tx_dip)) 
                                       
        verify_packet(self, exp_pkt, config["port_map"].keys()[2])
        verify_no_other_packets(self)
        tx_sip=tx_sip+0x01000000  
        #from unknown scr ip to unknown dst ip, to verify ecmp
        parsed_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst=switch_mac,
                                       eth_src=packet_src_mac,
                                       ip_ttl=64,
                                       ip_src=convertIP4toStr(tx_sip),
                                       ip_dst=convertIP4toStr(tx_dip))
        self.dataplane.send(tx_port, str(parsed_pkt))
        #build expect packet
        dst_mac=':'.join(['%02X' % x for x in same_dst_mac])
        exp_pkt = simple_tcp_packet(pktlen=100, 
                                   eth_dst=dst_mac,
                                   eth_src=switch_mac,
                                   ip_ttl=63,
                                   ip_src=convertIP4toStr(tx_sip),
                                   ip_dst=convertIP4toStr(tx_dip)) 
                                       
        verify_packet(self, exp_pkt, config["port_map"].keys()[1])
        verify_no_other_packets(self)

class L3McastRoute1(base_tests.SimpleDataPlane):
    """
    Mcast routing, From VLAN 1 to VLAN 2
    """
    def runTest(self):          
        """
        port1 (vlan 1)-> port 2 (vlan 2)
        """
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

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
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)            
            vlan_id +=1            

        #add termination flow
        add_termination_flow(self.controller, port1, 0x0800, [0x01, 0x00, 0x5e, 0x00, 0x00, 0x00], vlan_id)

        #add l3 interface group
        port2_ucast_msg=add_l3_interface_group(self.controller, port2, port2_out_vlan, 2, intf_src_mac)
        port3_ucast_msg=add_l3_interface_group(self.controller, port3, port3_out_vlan, 3, intf_src_mac)        
        mcat_group_msg=add_l3_mcast_group(self.controller, in_vlan,  2, [port2_ucast_msg.group_id, port3_ucast_msg.group_id])
        add_mcast4_routing_flow(self.controller, in_vlan, src_ip, 0, dst_ip, mcat_group_msg.group_id)               
        
        parsed_pkt = simple_udp_packet(pktlen=100, 
                                       eth_dst=dst_mac_str,
                                       eth_src=port1_mac_str,
                                       ip_ttl=64,
                                       ip_src=src_ip_str,
                                       ip_dst=dst_ip_str)
        pkt=str(parsed_pkt)
        self.dataplane.send(port1, pkt)            
        parsed_pkt = simple_udp_packet(pktlen=100, 
                                       eth_dst=dst_mac_str,
                                       eth_src=intf_src_mac_str,
                                       ip_ttl=63,
                                       ip_src=src_ip_str,
                                       ip_dst=dst_ip_str)
        pkt=str(parsed_pkt)            
        verify_packet(self, pkt, port2)
        verify_packet(self, pkt, port3)        
        verify_no_other_packets(self)               

class L3McastRoute2(base_tests.SimpleDataPlane):
    """
    Mcast routing, but on same vlan (l2mcast)
    """
    def runTest(self):          
        """
        port1 (vlan 1)-> port 2 (vlan 1)
        """
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        
        if len(config["port_map"]) <2:
            logging.info("Port count less than 2, can't run this case")
            return

        vlan_id =1
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

        
        #add l2 interface group
        l2_intf_group_list=[]
        for port in config["port_map"].keys():
            if port != port1 and port !=port2:
                continue
            l2_intf_gid, msg=add_one_l2_interface_group(self.controller, port, vlan_id=vlan_id, is_tagged=False, send_barrier=False)
            l2_intf_group_list.append(l2_intf_gid)
            #add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH)            

        #add termination flow
        add_termination_flow(self.controller, port1, 0x0800, [0x01, 0x00, 0x5e, 0x00, 0x00, 0x00], vlan_id)

        #add l3 interface group
        mcat_group_msg=add_l3_mcast_group(self.controller, vlan_id,  2, l2_intf_group_list)
        add_mcast4_routing_flow(self.controller, vlan_id, src_ip, 0, dst_ip, mcat_group_msg.group_id)               

        parsed_pkt = simple_udp_packet(pktlen=100, 
                                       eth_dst=dst_mac_str,
                                       eth_src=port1_mac_str,
                                       ip_ttl=64,
                                       ip_src=src_ip_str,
                                       ip_dst=dst_ip_str)
        pkt=str(parsed_pkt)
        self.dataplane.send(port1, pkt)            
        verify_packet(self, pkt, port2)
        verify_no_other_packets(self)               
            

            
