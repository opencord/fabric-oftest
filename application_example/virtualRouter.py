"""
This case test VM routing on same VNID
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

NW1_ACCESS_LPORT=0x10001
NW2_ACCESS_LPORT=0x10002        
NW1_NEWORK_LPORT=0x10003
NW2_NEWORK_LPORT=0x10003        

NW1_VRF=1
NW2_VRF=2
NW_VRF=[NW1_VRF, NW2_VRF]
SWITCH_VRF=0
assert(NW1_VRF!=SWITCH_VRF)
assert(NW2_VRF!=SWITCH_VRF)
NW1_VNID=1
NW2_VNID=2
NW_VNID=[NW1_VNID, NW2_VNID]


NW1_VLAN = 2
NW2_VLAN = 3
NW_VLAN=[NW1_VLAN, NW2_VLAN]
SWITCH_VLAN=1

#SWITCH_INTF_MAC = from feature.replay, because each switch is not the same, 
#                  current we just can use switch CPU MAC, due to tunnel terminator 
#                  have no way to set mac
#SWITCH_INTF_MAC_STR
SWITCH_IP=0XC0A80101 #192.168.1.1
SWITCH_IP_STR=convertIP4toStr(SWITCH_IP)
#H1 for NW1, H2 for NW2
#remember for chip limitaion, it can't have nexthop 
#has same vid, port but diff dst_mac
VXLAN_TNL_H1_IP=0XC0A80202#192.168.2.2
VXLAN_TNL_H1_IP_STR=convertIP4toStr(VXLAN_TNL_H1_IP)
VXLAN_TNL_H1_MAC=[0x00, 0x31, 0x31, 0x31, 0x31, 0x31] #like router MAC
VXLAN_TNL_H1_MAC_STR=convertMACtoStr(VXLAN_TNL_H1_MAC)
VXLAN_TNL_H2_IP=0XC0A80303#192.168.3.3
VXLAN_TNL_H2_IP_STR=convertIP4toStr(VXLAN_TNL_H2_IP)
VXLAN_TNL_H2_MAC=[0x00, 0x31, 0x31, 0x31, 0x31, 0x31] #like router MAC
VXLAN_TNL_H2_MAC_STR=convertMACtoStr(VXLAN_TNL_H2_MAC)
VXLAN_TNL_H_R_MAC=[0x00, 0x31, 0x31, 0x31, 0x31, 0x31]
VXLAN_TNL_H_R_MAC_STR=convertMACtoStr(VXLAN_TNL_H_R_MAC)
VXLAN_TNL_H_R_NHP_ID=1

NW1_VM1_IP = 0XC0A80101
NW1_VM1_IP_STR = convertIP4toStr(NW1_VM1_IP)
NW1_VM1_MAC=[0x00, 0x11, 0x11, 0x11, 0x11, 0x11]
NW1_VM1_MAC_STR=convertMACtoStr(NW1_VM1_MAC)
NW1_VM2_IP = 0XC0A80201
NW1_VM2_IP_STR = convertIP4toStr(NW1_VM2_IP)
NW1_VM2_MAC=[0x00, 0x12, 0x12, 0x12, 0x12, 0x12]
NW1_VM2_MAC_STR=convertMACtoStr(NW1_VM2_MAC)
NW2_VM1_IP = 0XC0A80101
NW2_VM1_IP_STR = convertIP4toStr(NW2_VM1_IP)
NW2_VM1_MAC=[0x00, 0x21, 0x21, 0x21, 0x21, 0x21]
NW2_VM1_MAC_STR=convertMACtoStr(NW2_VM1_MAC)
NW2_VM2_IP = 0XC0A80201        
NW2_VM2_IP_STR = convertIP4toStr(NW2_VM2_IP)
NW2_VM2_MAC=[0x00, 0x22, 0x22, 0x22, 0x22, 0x22]
NW2_VM2_MAC_STR=convertMACtoStr(NW2_VM2_MAC)        

NW1_GW_MAC=[0x00, 0x00, 0x00, 0x00, 0x11, 0x11]
NW1_GW_MAC_STR=convertMACtoStr(NW1_GW_MAC)
NW1_ROUTE1             =NW1_VM1_IP
NW1_ROUTE1_STR         =NW1_VM1_IP_STR
NW1_ROUTE1_NEXT_HOP_MAC=NW1_VM1_MAC
NW1_ROUTE2             =NW1_VM2_IP
NW1_ROUTE2_NEXT_HOP_MAC=NW1_VM2_MAC
NW1_ROUTE2_STR         =NW1_VM2_IP_STR
NW1_GW_ROUTE    =[NW1_ROUTE1, NW1_ROUTE2]
NW1_GW_ROUTE_STR=[NW1_ROUTE1_STR, NW1_ROUTE2_STR]
NW1_GW_ROUTE_NHP=[NW1_ROUTE1_NEXT_HOP_MAC, NW1_ROUTE2_NEXT_HOP_MAC]

NW2_GW_MAC=[0x00, 0x00, 0x00, 0x00, 0x22, 0x22]
NW2_GW_MAC_STR=convertMACtoStr(NW2_GW_MAC)
NW2_ROUTE1             =NW2_VM1_IP
NW2_ROUTE1_STR         =NW2_VM1_IP_STR
NW2_ROUTE1_NEXT_HOP_MAC=NW2_VM1_MAC
NW2_ROUTE2             =NW2_VM2_IP
NW2_ROUTE2_STR         =NW2_VM1_IP_STR
NW2_ROUTE2_NEXT_HOP_MAC=NW2_VM2_MAC
NW2_GW_ROUT_STR=[NW2_ROUTE1_STR, NW2_ROUTE2_STR]

NW_GW_MAC=[NW1_GW_MAC, NW2_GW_MAC]
NW_GW_MAC_STR=[NW1_GW_MAC_STR, NW2_GW_MAC_STR]


#make sure array has same length
assert(len(NW_GW_MAC) == len(NW_GW_MAC_STR))
assert(len(NW_GW_MAC) == len(NW_VLAN))

class vrouterSameVNIRouting(base_tests.SimpleDataPlane):
    """
    Topology:
    === switch inner pipeline
    --- switch forn port physical link    
    R: router
    NP:netowrk port
    AP:Access port
    LP:loopback port
    H1(VM1/VM2) --  R ----------- NP ==== AP --- LP
    H2 --
    
    VM1(192.168.1.1, NW1_VNID) <--> VM2(192.168.2.1, NW1_VNID)    
    VM1(192.168.1.1, NW2_VNID) <--> VM2(192.168.2.1, NW2_VNID)    
    
    Inner operation:
      (decap/encap vxlan header)NP==(bridge inner DMAC)==AP(VNID->VLANID)----(VLANID->VRF)LP
      
     
    
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
                
        ACCESS_PORT=config["port_map"].keys()[0]
        NETWORK_PORT=config["port_map"].keys()[1]
        LOOPBACK_PORT=config["port_map"].keys()[2]
        print "access %ld, network %ld, loopback %ld"%(ACCESS_PORT, NETWORK_PORT, LOOPBACK_PORT)        
        """ add vxlan config"""
        feature_reply=get_featureReplay(self)	
        SWITCH_INTF_MAC_STR, SWITCH_INTF_MAC=getSwitchCpuMACFromDPID(feature_reply.datapath_id)
        #add vni        
        vni_config_xml=get_vni_config_xml(vni_id=NW1_VNID, mcast_ipv4=None, next_hop_id=None)
        logging.info("config VNI %lx", NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        vni_config_xml=get_vni_config_xml(vni_id=NW2_VNID, mcast_ipv4=None, next_hop_id=None)
        logging.info("config VNI %lx", NW2_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        #add access port
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=NW1_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=NW1_VLAN, vnid=NW1_VNID)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", NW1_ACCESS_LPORT, ACCESS_PORT, NW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=NW2_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=NW2_VLAN, vnid=NW2_VNID)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", NW2_ACCESS_LPORT, ACCESS_PORT, NW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)       
        #create next hop and network port for H1
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
		                                          dst_mac=VXLAN_TNL_H_R_MAC_STR, 
												  phy_port=NETWORK_PORT, 
												  vlan=SWITCH_VLAN)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", VXLAN_TNL_H_R_NHP_ID, VXLAN_TNL_H_R_MAC_STR, NETWORK_PORT, SWITCH_VLAN);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)   
        #create network port        
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=NW1_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=NW1_VNID)												
        logging.info("config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", NW1_NEWORK_LPORT, NW1_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=NW2_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=NW2_VNID)												
        logging.info("config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", NW2_NEWORK_LPORT, NW2_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
        
        """add routing flow"""    
        #add port table to have vxlan ability
        add_port_table_flow(self.controller)
        #add l2 interface group
        add_one_l2_interface_group(self.controller, NETWORK_PORT, vlan_id=SWITCH_VLAN, is_tagged=True, send_barrier=False)
        for i in range(len(NW_VLAN)):        
            add_one_l2_interface_group(self.controller, LOOPBACK_PORT, vlan_id=NW_VLAN[i], is_tagged=True, send_barrier=False)

		#add vlan flow table
        add_one_vlan_table_flow(self.controller, NETWORK_PORT, SWITCH_VLAN, vrf=SWITCH_VRF, flag=VLAN_TABLE_FLAG_ONLY_BOTH)

        for i in range(len(NW_VLAN)):
            add_one_vlan_table_flow(self.controller, LOOPBACK_PORT, NW_VLAN[i], vrf=NW_VRF[i], flag=VLAN_TABLE_FLAG_ONLY_TAG)
        #add vxlan bridge flow
        add_overlay_bridge_flow(self.controller, NW1_GW_MAC, NW1_VNID, NW1_ACCESS_LPORT, False, False)
        add_overlay_bridge_flow(self.controller, NW2_GW_MAC, NW2_VNID, NW2_ACCESS_LPORT, False, False)
        add_overlay_bridge_flow(self.controller, NW1_VM1_MAC, NW1_VNID, NW1_NEWORK_LPORT, False, False)
        add_overlay_bridge_flow(self.controller, NW1_VM2_MAC, NW1_VNID, NW1_NEWORK_LPORT, False, False)        
        add_overlay_bridge_flow(self.controller, NW2_VM1_MAC, NW2_VNID, NW2_NEWORK_LPORT, False, False)
        add_overlay_bridge_flow(self.controller, NW2_VM2_MAC, NW2_VNID, NW2_NEWORK_LPORT, False, False)
        
		#add termination flow
        add_termination_flow(self.controller, NETWORK_PORT, 0x0800, SWITCH_INTF_MAC, SWITCH_VLAN)
        for i in range(len(NW_VLAN)):
            add_termination_flow(self.controller, LOOPBACK_PORT, 0x0800, NW_GW_MAC[i], NW_VLAN[i])        

        """
        Add Network Route, NW1
        192.168.1.1
        192.168.2.1
        """
        l3_msg=add_l3_unicast_group(self.controller, LOOPBACK_PORT, vlanid=NW1_VLAN, id=0x1001, src_mac=NW1_GW_MAC, dst_mac=NW1_ROUTE1_NEXT_HOP_MAC)
        add_unicast_routing_flow(self.controller, 0x0800, NW1_ROUTE1, 0, l3_msg.group_id, NW1_VRF)
        l3_msg=add_l3_unicast_group(self.controller, LOOPBACK_PORT, vlanid=NW1_VLAN, id=0x1002, src_mac=NW1_GW_MAC, dst_mac=NW1_ROUTE2_NEXT_HOP_MAC)
        add_unicast_routing_flow(self.controller, 0x0800, NW1_ROUTE2, 0, l3_msg.group_id, NW1_VRF)
        """
        Add Network Route, NW2
        192.168.1.1
        192.168.2.1
        """
        l3_msg=add_l3_unicast_group(self.controller, LOOPBACK_PORT, vlanid=NW2_VLAN, id=0x2001, src_mac=NW2_GW_MAC, dst_mac=NW2_ROUTE1_NEXT_HOP_MAC)
        add_unicast_routing_flow(self.controller, 0x0800, NW2_ROUTE1, 0, l3_msg.group_id, NW2_VRF)
        l3_msg=add_l3_unicast_group(self.controller, LOOPBACK_PORT, vlanid=NW2_VLAN, id=0x2002, src_mac=NW2_GW_MAC, dst_mac=NW2_ROUTE2_NEXT_HOP_MAC)
        add_unicast_routing_flow(self.controller, 0x0800, NW2_ROUTE2, 0, l3_msg.group_id, NW2_VRF)
        

        """
        Send paket to verify, NW1
        """        
        #tx packet on network lport
        inner_pkt = simple_udp_packet(pktlen=100
                                      , eth_src = NW1_VM1_MAC_STR
                                      , eth_dst=NW1_GW_MAC_STR
                                      , ip_dst =NW1_VM2_IP_STR 
                                      , ip_src =NW1_VM1_IP_STR
                                      , ip_ttl =64)
        vxlan_pkt = simple_vxlan_packet(eth_dst=SWITCH_INTF_MAC_STR
                                        ,eth_src=VXLAN_TNL_H_R_MAC_STR
                                        ,vnid=NW1_VNID
                                        ,ip_dst= SWITCH_IP_STR
                                        ,ip_src=VXLAN_TNL_H1_IP_STR
                                        ,inner_payload=inner_pkt)
        self.dataplane.send(NETWORK_PORT, str(vxlan_pkt))
        #verify rx on access port
        inner_pkt = simple_udp_packet(pktlen=104
                                      , eth_src= NW1_VM1_MAC_STR
                                      , eth_dst=NW1_GW_MAC_STR
                                      , dl_vlan_enable=True
                                      , vlan_vid=NW1_VLAN
                                      , ip_dst =NW1_VM2_IP_STR 
                                      , ip_src =NW1_VM1_IP_STR
                                      , ip_ttl =64)
        verify_packet(self, str(inner_pkt), ACCESS_PORT)
        verify_no_other_packets(self)
        
        #tx on loopback port
        self.dataplane.send(LOOPBACK_PORT, str(inner_pkt))
        #verify rx on loopback port
        inner_pkt = simple_udp_packet(pktlen=104
                                      , eth_src=NW1_GW_MAC_STR
                                      , eth_dst=NW1_VM2_MAC_STR
                                      , dl_vlan_enable=True
                                      , vlan_vid=NW1_VLAN                                      
                                      , ip_dst =NW1_VM2_IP_STR
                                      , ip_src =NW1_VM1_IP_STR
                                      , ip_ttl =63)
        verify_packet(self, str(inner_pkt), LOOPBACK_PORT)
        verify_no_other_packets(self)
        #tx on access port
        self.dataplane.send(ACCESS_PORT, str(inner_pkt))        
        #verify rx on network port
        inner_pkt = simple_udp_packet(pktlen=100
                                      , eth_src=NW1_GW_MAC_STR
                                      , eth_dst=NW1_VM2_MAC_STR
                                      , ip_dst =NW1_VM2_IP_STR
                                      , ip_src =NW1_VM1_IP_STR
                                      , ip_ttl =63)
        vxlan_pkt = simple_vxlan_packet(eth_src=SWITCH_INTF_MAC_STR
                                        ,eth_dst=VXLAN_TNL_H_R_MAC_STR
                                        ,vnid=NW1_VNID
                                        ,ip_dst=VXLAN_TNL_H1_IP_STR
                                        ,ip_src=SWITCH_IP_STR
                                        ,inner_payload=inner_pkt)        
        verify_packet(self, inner_pkt, NETWORK_PORT)
        verify_no_other_packets(self) 


        """
        Send paket to verify, NW2
        """        
        #tx packet on network lport
        inner_pkt = simple_udp_packet(pktlen=100
                                      , eth_src = NW2_VM1_MAC_STR
                                      , eth_dst=NW2_GW_MAC_STR
                                      , ip_dst =NW2_VM2_IP_STR 
                                      , ip_src =NW2_VM1_IP_STR
                                      , ip_ttl =64)
        vxlan_pkt = simple_vxlan_packet(eth_dst=SWITCH_INTF_MAC_STR
                                        ,eth_src=VXLAN_TNL_H_R_MAC_STR
                                        ,vnid=NW2_VNID
                                        ,ip_dst= SWITCH_IP_STR
                                        ,ip_src=VXLAN_TNL_H1_IP_STR
                                        ,inner_payload=inner_pkt)
        self.dataplane.send(NETWORK_PORT, str(vxlan_pkt))
        #verify rx on access port
        inner_pkt = simple_udp_packet(pktlen=104
                                      , eth_src= NW2_VM1_MAC_STR
                                      , eth_dst=NW2_GW_MAC_STR
                                      , dl_vlan_enable=True
                                      , vlan_vid=NW2_VLAN
                                      , ip_dst =NW2_VM2_IP_STR 
                                      , ip_src =NW2_VM1_IP_STR
                                      , ip_ttl =64)
        verify_packet(self, str(inner_pkt), ACCESS_PORT)
        verify_no_other_packets(self)
        
        #tx on loopback port
        self.dataplane.send(LOOPBACK_PORT, str(inner_pkt))
        #verify rx on loopback port
        inner_pkt = simple_udp_packet(pktlen=104
                                      , eth_src=NW2_GW_MAC_STR
                                      , eth_dst=NW2_VM2_MAC_STR
                                      , dl_vlan_enable=True
                                      , vlan_vid=NW2_VLAN                                      
                                      , ip_dst =NW2_VM2_IP_STR
                                      , ip_src =NW2_VM1_IP_STR
                                      , ip_ttl =63)
        verify_packet(self, str(inner_pkt), LOOPBACK_PORT)
        verify_no_other_packets(self)
        #tx on access port
        self.dataplane.send(ACCESS_PORT, str(inner_pkt))        
        #verify rx on network port
        inner_pkt = simple_udp_packet(pktlen=100
                                      , eth_src=NW2_GW_MAC_STR
                                      , eth_dst=NW2_VM2_MAC_STR
                                      , ip_dst =NW2_VM2_IP_STR
                                      , ip_src =NW2_VM1_IP_STR
                                      , ip_ttl =63)
        vxlan_pkt = simple_vxlan_packet(eth_src=SWITCH_INTF_MAC_STR
                                        ,eth_dst=VXLAN_TNL_H_R_MAC_STR
                                        ,vnid=NW2_VNID
                                        ,ip_dst=VXLAN_TNL_H1_IP_STR
                                        ,ip_src=SWITCH_IP_STR
                                        ,inner_payload=inner_pkt)        
        verify_packet(self, inner_pkt, NETWORK_PORT)
        verify_no_other_packets(self) 

        """clear all flow/group and configuration
        """
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        """ del vxlan config"""
        #delete access port
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=NW1_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=NW1_VLAN, vnid=NW1_VNID, operation="delete")
        logging.info("delete config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", NW1_ACCESS_LPORT, ACCESS_PORT, NW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=NW2_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=NW2_VLAN, vnid=NW2_VNID, operation="delete")
        logging.info("delete config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", NW2_ACCESS_LPORT, ACCESS_PORT, NW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)       
        #delete network port        
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=NW1_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=NW1_VNID, operation="delete")												
        logging.info("delete config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", NW1_NEWORK_LPORT, NW1_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        if NW1_NEWORK_LPORT != NW2_NEWORK_LPORT:
            vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                    lport=NW2_NEWORK_LPORT, 
                                                    src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                    next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                    vnid=NW2_VNID, operation="delete")												
            logging.info("delete config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", NW2_NEWORK_LPORT, NW2_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
            assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        #delete next hop and network port for H1
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
		                                          dst_mac=VXLAN_TNL_H_R_MAC_STR, 
												  phy_port=NETWORK_PORT, 
												  vlan=SWITCH_VLAN, operation="delete")        
        logging.info("delete config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", VXLAN_TNL_H_R_NHP_ID, VXLAN_TNL_H_R_MAC_STR, NETWORK_PORT, SWITCH_VLAN);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)                   
        #del vni
        vni_config_xml=get_vni_config_xml(vni_id=NW1_VNID, mcast_ipv4=None, next_hop_id=None, operation="delete")
        logging.info("delete config VNI %lx", NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        vni_config_xml=get_vni_config_xml(vni_id=NW2_VNID, mcast_ipv4=None, next_hop_id=None, operation="delete")
        logging.info("delete config VNI %lx", NW2_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

#for routing on different VNID, it can't have same subnet.
TNW1_ACCESS_LPORT=0x10001
TNW2_ACCESS_LPORT=0x10002        
TNW1_NEWORK_LPORT=0x10003
TNW2_NEWORK_LPORT=0x10004        

TNW1_VRF=2 #all shall the same
TNW2_VRF=2
TNW_VRF=[TNW1_VRF, TNW2_VRF]
TSWITCH_VRF=0 #let switch different from VM
assert(TNW2_VRF!=TSWITCH_VRF)
assert(TNW1_VRF!=TSWITCH_VRF)

TNW1_VNID=1
TNW2_VNID=2
TNW_VNID=[TNW1_VNID, TNW2_VNID]

TNW1_VLAN = 2
TNW2_VLAN = 3
TNW_VLAN=[TNW1_VLAN, TNW2_VLAN]
assert(TNW1_VLAN!=SWITCH_VLAN)
assert(TNW2_VLAN!=SWITCH_VLAN)
#the subnet shall not the same, because they all NW use same VRF
TNW1_VM1_IP = 0XC0A80101  #192.168.1.1
TNW1_VM1_IP_STR = convertIP4toStr(TNW1_VM1_IP)
TNW1_VM1_MAC=[0x00, 0x11, 0x11, 0x11, 0x11, 0x11]
TNW1_VM1_MAC_STR=convertMACtoStr(TNW1_VM1_MAC)
TNW1_VM2_IP = 0XC0A80201  #192.168.2.1
TNW1_VM2_IP_STR = convertIP4toStr(TNW1_VM2_IP)
TNW1_VM2_MAC=[0x00, 0x12, 0x12, 0x12, 0x12, 0x12]
TNW1_VM2_MAC_STR=convertMACtoStr(TNW1_VM2_MAC)
TNW2_VM1_IP = 0XC0A80301  #192.168.3.1
TNW2_VM1_IP_STR = convertIP4toStr(TNW2_VM1_IP)
TNW2_VM1_MAC=[0x00, 0x21, 0x21, 0x21, 0x21, 0x21]
TNW2_VM1_MAC_STR=convertMACtoStr(TNW2_VM1_MAC)
TNW2_VM2_IP = 0XC0A80401  #192.168.4.1     
TNW2_VM2_IP_STR = convertIP4toStr(TNW2_VM2_IP)
TNW2_VM2_MAC=[0x00, 0x22, 0x22, 0x22, 0x22, 0x22]
TNW2_VM2_MAC_STR=convertMACtoStr(TNW2_VM2_MAC)        

TNW1_GW_MAC=[0x00, 0x00, 0x00, 0x00, 0x11, 0x11]
TNW1_GW_MAC_STR=convertMACtoStr(TNW1_GW_MAC)
TNW1_ROUTE1             =TNW1_VM1_IP
TNW1_ROUTE1_STR         =TNW1_VM1_IP_STR
TNW1_ROUTE1_NEXT_HOP_MAC=TNW1_VM1_MAC
TNW1_ROUTE2             =TNW1_VM2_IP
TNW1_ROUTE2_NEXT_HOP_MAC=TNW1_VM2_MAC
TNW1_ROUTE2_STR         =TNW1_VM2_IP_STR
TNW1_GW_ROUTE    =[TNW1_ROUTE1, TNW1_ROUTE2]
TNW1_GW_ROUTE_STR=[TNW1_ROUTE1_STR, TNW1_ROUTE2_STR]
TNW1_GW_ROUTE_NHP=[TNW1_ROUTE1_NEXT_HOP_MAC, TNW1_ROUTE2_NEXT_HOP_MAC]

TNW2_GW_MAC=[0x00, 0x00, 0x00, 0x00, 0x22, 0x22]
TNW2_GW_MAC_STR=convertMACtoStr(TNW2_GW_MAC)
TNW2_ROUTE1             =TNW2_VM1_IP
TNW2_ROUTE1_STR         =TNW2_VM1_IP_STR
TNW2_ROUTE1_NEXT_HOP_MAC=TNW2_VM1_MAC
TNW2_ROUTE2             =TNW2_VM2_IP
TNW2_ROUTE2_STR         =TNW2_VM1_IP_STR
TNW2_ROUTE2_NEXT_HOP_MAC=TNW2_VM2_MAC
TNW2_GW_ROUT_STR=[TNW2_ROUTE1_STR, TNW2_ROUTE2_STR]

TNW_GW_MAC=[TNW1_GW_MAC, TNW2_GW_MAC]
TNW_GW_MAC_STR=[TNW1_GW_MAC_STR, TNW2_GW_MAC_STR]


        
class vrouterDiffVnidRouting(base_tests.SimpleDataPlane):
    """
    Topology:
    === switch inner pipeline
    --- switch forn port physical link    
    R: router
    NP:netowrk port
    AP:Access port
    LP:loopback port
    H1(VM1/VM2) --  R ----------- NP ==== AP --- LP
    H2 --
    
    VM1(192.168.1.1, NW1_VNID) <--> VM2(192.168.2.1, NW1_VNID)    
    VM1(192.168.1.1, NW2_VNID) <--> VM2(192.168.2.1, NW2_VNID)    
    
    Inner operation:
      (decap/encap vxlan header)NP==(bridge inner DMAC)==AP(VNID->VLANID)----(VLANIDx->same VRF)LP

    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
                
        ACCESS_PORT=config["port_map"].keys()[0]
        NETWORK_PORT=config["port_map"].keys()[1]
        LOOPBACK_PORT=config["port_map"].keys()[2]
        print "access %ld, network %ld, loopback %ld"%(ACCESS_PORT, NETWORK_PORT, LOOPBACK_PORT)        
        """ add vxlan config"""
        feature_reply=get_featureReplay(self)	
        SWITCH_INTF_MAC_STR, SWITCH_INTF_MAC=getSwitchCpuMACFromDPID(feature_reply.datapath_id)
        #add vni        
        vni_config_xml=get_vni_config_xml(vni_id=TNW1_VNID, mcast_ipv4=None, next_hop_id=None)
        logging.info("config VNI %lx", TNW1_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        vni_config_xml=get_vni_config_xml(vni_id=TNW2_VNID, mcast_ipv4=None, next_hop_id=None)
        logging.info("config VNI %lx", TNW2_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        #add access port
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=TNW1_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=TNW1_VLAN, vnid=TNW1_VNID)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", TNW1_ACCESS_LPORT, ACCESS_PORT, TNW1_VLAN, TNW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=TNW2_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=TNW2_VLAN, vnid=TNW2_VNID)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", TNW2_ACCESS_LPORT, ACCESS_PORT, TNW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)       
        #create next hop and network port for H1
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
		                                          dst_mac=VXLAN_TNL_H_R_MAC_STR, 
												  phy_port=NETWORK_PORT, 
												  vlan=SWITCH_VLAN)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", VXLAN_TNL_H_R_NHP_ID, VXLAN_TNL_H_R_MAC_STR, NETWORK_PORT, SWITCH_VLAN);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)   
        #create network port        
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=TNW1_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=TNW1_VNID)												
        logging.info("config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", TNW1_NEWORK_LPORT, TNW1_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=TNW2_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=TNW2_VNID)												
        logging.info("config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", TNW2_NEWORK_LPORT, TNW2_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
        
        
        """add routing flow"""    
        #add port table to have vxlan ability
        add_port_table_flow(self.controller)
        #add l2 interface group
        add_one_l2_interface_group(self.controller, NETWORK_PORT, vlan_id=SWITCH_VLAN, is_tagged=True, send_barrier=False)
        for i in range(len(TNW_VLAN)):        
            add_one_l2_interface_group(self.controller, LOOPBACK_PORT, vlan_id=TNW_VLAN[i], is_tagged=True, send_barrier=False)

		#add vlan flow table
        add_one_vlan_table_flow(self.controller, NETWORK_PORT, SWITCH_VLAN, vrf=SWITCH_VRF, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
        for i in range(len(TNW_VLAN)):
            add_one_vlan_table_flow(self.controller, LOOPBACK_PORT, TNW_VLAN[i], vrf=TNW_VRF[i], flag=VLAN_TABLE_FLAG_ONLY_TAG)
            
        #add vxlan bridge flow
        add_overlay_bridge_flow(self.controller, TNW1_GW_MAC, TNW1_VNID, TNW1_ACCESS_LPORT, False, False)
        add_overlay_bridge_flow(self.controller, TNW2_GW_MAC, TNW2_VNID, TNW2_ACCESS_LPORT, False, False)
        add_overlay_bridge_flow(self.controller, TNW1_VM1_MAC, TNW1_VNID, TNW1_NEWORK_LPORT, False, False)
        add_overlay_bridge_flow(self.controller, TNW1_VM2_MAC, TNW1_VNID, TNW1_NEWORK_LPORT, False, False)        
        add_overlay_bridge_flow(self.controller, TNW2_VM1_MAC, TNW2_VNID, TNW2_NEWORK_LPORT, False, False)
        add_overlay_bridge_flow(self.controller, TNW2_VM2_MAC, TNW2_VNID, TNW2_NEWORK_LPORT, False, False)
        
		#add termination flow
        add_termination_flow(self.controller, NETWORK_PORT, 0x0800, SWITCH_INTF_MAC, SWITCH_VLAN)
        for i in range(len(TNW_VLAN)):
            add_termination_flow(self.controller, LOOPBACK_PORT, 0x0800, TNW_GW_MAC[i], TNW_VLAN[i])        

        """
        Add Network Route, TNW1
        192.168.1.1
        192.168.2.1
        """
        l3_msg=add_l3_unicast_group(self.controller, LOOPBACK_PORT, vlanid=TNW1_VLAN, id=0x1001, src_mac=TNW1_GW_MAC, dst_mac=TNW1_ROUTE1_NEXT_HOP_MAC)
        add_unicast_routing_flow(self.controller, 0x0800, TNW1_ROUTE1, 0, l3_msg.group_id, TNW1_VRF)
        l3_msg=add_l3_unicast_group(self.controller, LOOPBACK_PORT, vlanid=TNW1_VLAN, id=0x1002, src_mac=TNW1_GW_MAC, dst_mac=TNW1_ROUTE2_NEXT_HOP_MAC)
        add_unicast_routing_flow(self.controller, 0x0800, TNW1_ROUTE2, 0, l3_msg.group_id, TNW1_VRF)
        """
        Add Network Route, TNW2
        192.168.1.1
        192.168.2.1
        """
        l3_msg=add_l3_unicast_group(self.controller, LOOPBACK_PORT, vlanid=TNW2_VLAN, id=0x2001, src_mac=TNW1_GW_MAC, dst_mac=TNW2_ROUTE1_NEXT_HOP_MAC)
        add_unicast_routing_flow(self.controller, 0x0800, TNW2_ROUTE1, 0, l3_msg.group_id, TNW2_VRF)
        l3_msg=add_l3_unicast_group(self.controller, LOOPBACK_PORT, vlanid=TNW2_VLAN, id=0x2002, src_mac=TNW2_GW_MAC, dst_mac=TNW2_ROUTE2_NEXT_HOP_MAC)
        add_unicast_routing_flow(self.controller, 0x0800, TNW2_ROUTE2, 0, l3_msg.group_id, TNW2_VRF)
        

        """
        Send paket to verify, TNW1
        """        
        #tx packet on network lport
        inner_pkt = simple_udp_packet(pktlen=100
                                      , eth_src = TNW1_VM1_MAC_STR
                                      , eth_dst=TNW1_GW_MAC_STR
                                      , ip_dst =TNW1_VM2_IP_STR 
                                      , ip_src =TNW1_VM1_IP_STR
                                      , ip_ttl =64)
        vxlan_pkt = simple_vxlan_packet(eth_dst=SWITCH_INTF_MAC_STR
                                        ,eth_src=VXLAN_TNL_H_R_MAC_STR
                                        ,vnid=TNW1_VNID
                                        ,ip_dst= SWITCH_IP_STR
                                        ,ip_src=VXLAN_TNL_H1_IP_STR
                                        ,inner_payload=inner_pkt)
        self.dataplane.send(NETWORK_PORT, str(vxlan_pkt))
        #verify rx on access port
        inner_pkt = simple_udp_packet(pktlen=104
                                      , eth_src= TNW1_VM1_MAC_STR
                                      , eth_dst=TNW1_GW_MAC_STR
                                      , dl_vlan_enable=True
                                      , vlan_vid=TNW1_VLAN
                                      , ip_dst =TNW1_VM2_IP_STR 
                                      , ip_src =TNW1_VM1_IP_STR
                                      , ip_ttl =64)
        verify_packet(self, str(inner_pkt), ACCESS_PORT)
        verify_no_other_packets(self)
        
        #tx on loopback port
        self.dataplane.send(LOOPBACK_PORT, str(inner_pkt))
        #verify rx on loopback port
        inner_pkt = simple_udp_packet(pktlen=104
                                      , eth_src=TNW1_GW_MAC_STR
                                      , eth_dst=TNW1_VM2_MAC_STR
                                      , dl_vlan_enable=True
                                      , vlan_vid=TNW1_VLAN                                      
                                      , ip_dst =TNW1_VM2_IP_STR
                                      , ip_src =TNW1_VM1_IP_STR
                                      , ip_ttl =63)
        verify_packet(self, str(inner_pkt), LOOPBACK_PORT)
        verify_no_other_packets(self)
        #tx on access port
        self.dataplane.send(ACCESS_PORT, str(inner_pkt))        
        #verify rx on network port
        inner_pkt = simple_udp_packet(pktlen=100
                                      , eth_src=TNW1_GW_MAC_STR
                                      , eth_dst=TNW1_VM2_MAC_STR
                                      , ip_dst =TNW1_VM2_IP_STR
                                      , ip_src =TNW1_VM1_IP_STR
                                      , ip_ttl =63)
        vxlan_pkt = simple_vxlan_packet(eth_src=SWITCH_INTF_MAC_STR
                                        ,eth_dst=VXLAN_TNL_H_R_MAC_STR
                                        ,vnid=TNW1_VNID
                                        ,ip_dst=VXLAN_TNL_H1_IP_STR
                                        ,ip_src=SWITCH_IP_STR
                                        ,inner_payload=inner_pkt)        
        verify_packet(self, inner_pkt, NETWORK_PORT)
        verify_no_other_packets(self) 


        """
        Send paket to verify, NW2
        """        
        #tx packet on network lport
        inner_pkt = simple_udp_packet(pktlen=100
                                      , eth_src = TNW2_VM1_MAC_STR
                                      , eth_dst=TNW2_GW_MAC_STR
                                      , ip_dst =TNW2_VM2_IP_STR 
                                      , ip_src =TNW2_VM1_IP_STR
                                      , ip_ttl =64)
        vxlan_pkt = simple_vxlan_packet(eth_dst=SWITCH_INTF_MAC_STR
                                        ,eth_src=VXLAN_TNL_H_R_MAC_STR
                                        ,vnid=TNW2_VNID
                                        ,ip_dst= SWITCH_IP_STR
                                        ,ip_src=VXLAN_TNL_H1_IP_STR
                                        ,inner_payload=inner_pkt)
        self.dataplane.send(NETWORK_PORT, str(vxlan_pkt))
        #verify rx on access port
        inner_pkt = simple_udp_packet(pktlen=104
                                      , eth_src= TNW2_VM1_MAC_STR
                                      , eth_dst=TNW2_GW_MAC_STR
                                      , dl_vlan_enable=True
                                      , vlan_vid=TNW2_VLAN
                                      , ip_dst =TNW2_VM2_IP_STR 
                                      , ip_src =TNW2_VM1_IP_STR
                                      , ip_ttl =64)
        verify_packet(self, str(inner_pkt), ACCESS_PORT)
        verify_no_other_packets(self)
        
        #tx on loopback port
        self.dataplane.send(LOOPBACK_PORT, str(inner_pkt))
        #verify rx on loopback port
        inner_pkt = simple_udp_packet(pktlen=104
                                      , eth_src=TNW2_GW_MAC_STR
                                      , eth_dst=TNW2_VM2_MAC_STR
                                      , dl_vlan_enable=True
                                      , vlan_vid=TNW2_VLAN                                      
                                      , ip_dst =TNW2_VM2_IP_STR
                                      , ip_src =TNW2_VM1_IP_STR
                                      , ip_ttl =63)
        verify_packet(self, str(inner_pkt), LOOPBACK_PORT)
        verify_no_other_packets(self)
        #tx on access port
        self.dataplane.send(ACCESS_PORT, str(inner_pkt))        
        #verify rx on network port
        inner_pkt = simple_udp_packet(pktlen=100
                                      , eth_src=TNW2_GW_MAC_STR
                                      , eth_dst=TNW2_VM2_MAC_STR
                                      , ip_dst =TNW2_VM2_IP_STR
                                      , ip_src =TNW2_VM1_IP_STR
                                      , ip_ttl =63)
        vxlan_pkt = simple_vxlan_packet(eth_src=SWITCH_INTF_MAC_STR
                                        ,eth_dst=VXLAN_TNL_H_R_MAC_STR
                                        ,vnid=TNW2_VNID
                                        ,ip_dst=VXLAN_TNL_H1_IP_STR
                                        ,ip_src=SWITCH_IP_STR
                                        ,inner_payload=inner_pkt)        
        verify_packet(self, inner_pkt, NETWORK_PORT)
        verify_no_other_packets(self) 

        
        """clear all flow/group and configuration
        """
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        """ del vxlan config"""
        #delete access port
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=TNW1_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=TNW1_VLAN, vnid=TNW1_VNID, operation="delete")
        logging.info("delete config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", TNW1_ACCESS_LPORT, ACCESS_PORT, TNW1_VLAN, TNW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=TNW2_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=TNW2_VLAN, vnid=TNW2_VNID, operation="delete")
        logging.info("delete config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", TNW2_ACCESS_LPORT, ACCESS_PORT, TNW1_VLAN, TNW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)       
        #delete network port        
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=TNW1_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=TNW1_VNID, operation="delete")												
        logging.info("delete config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", TNW1_NEWORK_LPORT, TNW1_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=TNW2_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=TNW2_VNID, operation="delete")												
        logging.info("delete config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", TNW2_NEWORK_LPORT, TNW2_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
        #delete next hop and network port for H1
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
		                                          dst_mac=VXLAN_TNL_H_R_MAC_STR, 
												  phy_port=NETWORK_PORT, 
												  vlan=SWITCH_VLAN, operation="delete")        
        logging.info("delete config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", VXLAN_TNL_H_R_NHP_ID, VXLAN_TNL_H_R_MAC_STR, NETWORK_PORT, SWITCH_VLAN);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)                   
        #del vni
        vni_config_xml=get_vni_config_xml(vni_id=TNW1_VNID, mcast_ipv4=None, next_hop_id=None, operation="delete")
        logging.info("delete config VNI %lx", TNW1_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        vni_config_xml=get_vni_config_xml(vni_id=TNW2_VNID, mcast_ipv4=None, next_hop_id=None, operation="delete")
        logging.info("delete config VNI %lx", TNW2_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

class vrouterNetconfSetUnset(base_tests.SimpleDataPlane):
    def runTest(self):
        ACCESS_PORT=config["port_map"].keys()[0]
        NETWORK_PORT=config["port_map"].keys()[1]
        LOOPBACK_PORT=config["port_map"].keys()[2]
        print "access %ld, network %ld, loopback %ld"%(ACCESS_PORT, NETWORK_PORT, LOOPBACK_PORT)        
        """ add vxlan config"""
        feature_reply=get_featureReplay(self)	
        SWITCH_INTF_MAC_STR, SWITCH_INTF_MAC=getSwitchCpuMACFromDPID(feature_reply.datapath_id)
        #add vni        
        vni_config_xml=get_vni_config_xml(vni_id=NW1_VNID, mcast_ipv4=None, next_hop_id=None)
        logging.info("config VNI %lx", NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        vni_config_xml=get_vni_config_xml(vni_id=NW2_VNID, mcast_ipv4=None, next_hop_id=None)
        logging.info("config VNI %lx", NW2_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        #add access port
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=NW1_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=NW1_VLAN, vnid=NW1_VNID)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", NW1_ACCESS_LPORT, ACCESS_PORT, NW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=NW2_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=NW2_VLAN, vnid=NW2_VNID)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", NW2_ACCESS_LPORT, ACCESS_PORT, NW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)       
        #create next hop and network port for H1
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
		                                          dst_mac=VXLAN_TNL_H_R_MAC_STR, 
												  phy_port=NETWORK_PORT, 
												  vlan=SWITCH_VLAN)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", VXLAN_TNL_H_R_NHP_ID, VXLAN_TNL_H_R_MAC_STR, NETWORK_PORT, SWITCH_VLAN);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)   
        #create network port        
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=NW1_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=NW1_VNID)												
        logging.info("config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", NW1_NEWORK_LPORT, NW1_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=NW2_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=NW2_VNID)												
        logging.info("config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", NW2_NEWORK_LPORT, NW2_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
                
        """clear all flow/group and configuration
        """
        """ del vxlan config"""
        #delete access port
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=NW1_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=NW1_VLAN, vnid=NW1_VNID, operation="delete")
        logging.info("delete config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", NW1_ACCESS_LPORT, ACCESS_PORT, NW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=NW2_ACCESS_LPORT, phy_port=ACCESS_PORT, 
                                        vlan=NW2_VLAN, vnid=NW2_VNID, operation="delete")
        logging.info("delete config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", NW2_ACCESS_LPORT, ACCESS_PORT, NW1_VLAN, NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)       
        #delete network port        
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=NW1_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=NW1_VNID, operation="delete")												
        logging.info("delete config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", NW1_NEWORK_LPORT, NW1_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=NW2_NEWORK_LPORT, 
                                                src_ip=SWITCH_IP_STR, dst_ip=VXLAN_TNL_H1_IP_STR,
                                                next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
                                                vnid=NW2_VNID, operation="delete")												
        logging.info("delete config VTEP 0x%lx, VNID=%lu, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", NW2_NEWORK_LPORT, NW2_VNID, SWITCH_IP, VXLAN_TNL_H1_IP_STR, VXLAN_TNL_H_R_NHP_ID);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
        #delete next hop and network port for H1
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=VXLAN_TNL_H_R_NHP_ID, 
		                                          dst_mac=VXLAN_TNL_H_R_MAC_STR, 
												  phy_port=NETWORK_PORT, 
												  vlan=SWITCH_VLAN, operation="delete")        
        logging.info("delete config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", VXLAN_TNL_H_R_NHP_ID, VXLAN_TNL_H_R_MAC_STR, NETWORK_PORT, SWITCH_VLAN);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)                   
        #del vni
        vni_config_xml=get_vni_config_xml(vni_id=NW1_VNID, mcast_ipv4=None, next_hop_id=None, operation="delete")
        logging.info("delete config VNI %lx", NW1_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        vni_config_xml=get_vni_config_xml(vni_id=NW2_VNID, mcast_ipv4=None, next_hop_id=None, operation="delete")
        logging.info("delete config VNI %lx", NW2_VNID);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
