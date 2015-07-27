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
import oftest.parse as decode
       
class VxlanConfigNetconf(base_tests.SimpleDataPlane):
    """
    Verify netconf to configure Vxlan port
	"""
    def runTest(self):
        if config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")		
            return
			
        #paramaters
        access_port_vid=1
        access_phy_port=1
        access_lport=0x10001
        vnid=103
        next_hop_id=1
        next_hop_id_mcast=2
        dst_mac="00:00:11:22:22:11"
        mcast_ipv4="224.1.1.1"
        dst_mac_mcast="01:00:5e:01:01:01"
        network_port_phy_port=2
        network_lport=0x10002
        network_port_vlan=2
        network_port_sip="192.168.1.1"
        network_port_dip="192.168.2.1"

		#get datapath_id from feature message
        feature_reply=get_featureReplay(self)	
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == False)                
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == False)                                                  
        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, 
                                          mcast_ipv4=mcast_ipv4, 
                                          next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == False)
            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport, phy_port=access_phy_port, 
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_phy_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == False)

        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport, 
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == False)            
            
        get_edit_config(config["switch_ip"])

		#exit verification so clear all configuration
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport, phy_port=access_phy_port, 
												vlan=access_port_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == False)
        
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=network_lport, 
												src_ip=network_port_sip, dst_ip=network_port_dip, 
												next_hop_id=next_hop_id, 
												vnid=vnid, operation="delete")												
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == False)

        vni_config_xml=get_vni_config_xml(vni_id=vnid, 
                                          mcast_ipv4=mcast_ipv4, 
                                          next_hop_id=next_hop_id_mcast, operation="delete")
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == False)

        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == False)

        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == False)            

        get_edit_config(config["switch_ip"])
        
class OverlayFloodGroup(base_tests.SimpleDataPlane):
    """
	create two lport
	"""
    def runTest(self):
        """
        first verify flood over unicast, 
        second verify flood over mcast
        """
        if config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")		
            return
			
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        #paramaters
        access_port_vid=1
        access_phy_port=1
        access_lport=0x10001
        vnid=103
        next_hop_id=1
        next_hop_id_mcast=2
        dst_mac="00:00:11:22:22:11"
        mcast_ipv4="224.1.1.1"
        dst_mac_mcast="01:00:5e:01:01:01"
        network_port_phy_port=2
        network_lport=0x10002
        network_port_vlan=2
        network_port_sip="192.168.1.1"
        network_port_dip="192.168.2.1"
		
        feature_reply=get_featureReplay(self)	
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)                                                  
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=mcast_ipv4, next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport, phy_port=access_phy_port, 
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_phy_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport, 
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        #add flow over unicast group
        msg=add_l2_overlay_flood_over_unicast_tunnel_group(self.controller, vnid, [access_lport, network_lport], 1)
        #verify
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        verify_group_stats=(ofp.group_desc_stats_entry(
    	                    group_type=msg.group_type,
						    group_id=msg.group_id,
						    buckets=msg.buckets))

        self.assertEquals(stats, [verify_group_stats])
        #clear all group
        delete_all_groups(self.controller)
		#
		#flood over mcast
        msg=add_l2_overlay_flood_over_mcast_tunnel_group(self.controller, vnid, [access_lport, network_lport], 1)

        stats = get_stats(self, ofp.message.group_desc_stats_request())
 
        verify_group_stats=(ofp.group_desc_stats_entry(
    	                    group_type=msg.group_type,
						    group_id=msg.group_id,
						    buckets=msg.buckets))

        self.assertEquals(stats, [verify_group_stats])
        #clear all group
        delete_all_groups(self.controller)
		#exit verification so clear all configuration
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport, phy_port=access_phy_port, 
												vlan=access_port_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=network_lport, 
												src_ip=network_port_sip, dst_ip=network_port_dip, 
												next_hop_id=next_hop_id, 
												vnid=vnid, operation="delete")												
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=None, next_hop_id=None, operation="delete")
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)            

class OverlayMcastGroup(base_tests.SimpleDataPlane):
    """
	create two lport
	"""
    def runTest(self):
        if config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")		
            return
			
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        #paramaters
        access_port_vid=1
        access_phy_port=1
        access_lport=0x10001
        vnid=103
        next_hop_id=1
        next_hop_id_mcast=2
        dst_mac="00:00:11:22:22:11"
        mcast_ipv4="224.1.1.1"
        dst_mac_mcast="01:00:5e:01:01:01"
        network_port_phy_port=2
        network_lport=0x10002
        network_port_vlan=2
        network_port_sip="192.168.1.1"
        network_port_dip="192.168.2.1"
		
        feature_reply=get_featureReplay(self)	
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)                                                  
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=mcast_ipv4, next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport, phy_port=access_phy_port, 
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_phy_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport, 
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        #add flow over unicast group
        msg=msg=add_l2_overlay_mcast_over_unicast_tunnel_group(self.controller, vnid, [access_lport, network_lport], 1)
        #verify
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        verify_group_stats=(ofp.group_desc_stats_entry(
    	                    group_type=msg.group_type,
						    group_id=msg.group_id,
						    buckets=msg.buckets))

        self.assertEquals(stats, [verify_group_stats])
        #clear all group
        delete_all_groups(self.controller)
		#
		#flood over mcast
        msg=add_l2_overlay_mcast_over_mcast_tunnel_group(self.controller, vnid, [access_lport, network_lport], 1)

        stats = get_stats(self, ofp.message.group_desc_stats_request())
 
        verify_group_stats=(ofp.group_desc_stats_entry(
    	                    group_type=msg.group_type,
						    group_id=msg.group_id,
						    buckets=msg.buckets))

        self.assertEquals(stats, [verify_group_stats])
        #clear all group
        delete_all_groups(self.controller)
		#exit verification so clear all configuration
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport, phy_port=access_phy_port, 
												vlan=access_port_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=network_lport, 
												src_ip=network_port_sip, dst_ip=network_port_dip, 
												next_hop_id=next_hop_id, 
												vnid=vnid, operation="delete")												
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=None, next_hop_id=None, operation="delete")
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)            
										        
class AccessToNetworkDLFMcast(base_tests.SimpleDataPlane):
    def runTest(self):
        """
        first verify flood over unicast, 
        second verify flood over mcast
        """
        if 	config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")		
            return
			
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
  
        access_port1_vid=1
        access_phy_port1=config["port_map"].keys()[0]
        access_lport1=0x10001
        access_port2_vid=0
        access_phy_port2=config["port_map"].keys()[1]
        access_lport2=0x10002
        vnid=10
        next_hop_id=1
        next_hop_id_mcast=2
        dst_mac="00:00:11:22:22:11"
        mcast_ipv4="224.1.1.1"
        dst_mac_mcast="01:00:5e:01:01:01"
        network_port_phy_port=config["port_map"].keys()[2]
        network_lport=0x10003
        network_port_vlan=2
        network_port_sip="192.168.1.1"
        network_port_dip="192.168.2.1"

        feature_reply=get_featureReplay(self)	
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)
        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=mcast_ipv4, next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport1, phy_port=access_phy_port1, 
                                        vlan=access_port1_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport1, access_phy_port1, access_port1_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport2, phy_port=access_phy_port2, 
                                        vlan=access_port2_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport2, access_phy_port2, access_port2_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)            
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport, 
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        #get_edit_config(config["switch_ip"])
        
        #add port table to have vxlan ability
        add_port_table_flow(self.controller)

        #for network port need l2 interface group to decide vlan tag or not
        add_one_l2_interface_grouop(self.controller, network_port_phy_port, vlan_id=network_port_vlan)        

		#add DLF bridge flow
        msg=add_l2_overlay_flood_over_mcast_tunnel_group(self.controller, vnid, [access_lport1, access_lport2, network_lport], 1)        
        add_overlay_bridge_flow(self.controller, None, vnid, msg.group_id, True, True)
        
        #send packet on access port
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:00:11:11:11:11',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)

        #verify packet on access port		
        parsed_pkt = simple_udp_packet(pktlen=92, eth_dst='00:00:11:11:11:11')
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, access_phy_port2)
        #vxlan packet IP header have some parmater decide by HW,
        #we can easy to check VxLAN IP header
        verify_packet(self, pkt, network_port_phy_port)        
        verify_no_other_packets(self)

        add_overlay_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, 0x9a], vnid, network_lport, False, True)        
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:12:34:56:78:9a',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)
        #verify packet on network port		
        parsed_pkt = simple_udp_packet(pktlen=92, eth_dst='00:12:34:56:78:9a')
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, network_port_phy_port)        
        verify_no_other_packets(self)
        
		#exit verification so clear all configuration
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport1, phy_port=access_phy_port1, 
												vlan=access_port1_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport2, phy_port=access_phy_port2, 
												vlan=access_port2_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)            
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=network_lport, 
												src_ip=network_port_sip, dst_ip=network_port_dip, 
												next_hop_id=next_hop_id, 
												vnid=vnid, operation="delete")												
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=None, next_hop_id=None, operation="delete")
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

class AccessToNetworkDLFUcast(base_tests.SimpleDataPlane):
    def runTest(self):
        """
        first verify flood over unicast, 
        second verify flood over mcast
        """
        if 	config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")		
            return
			
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
  
        access_port1_vid=1
        access_phy_port1=config["port_map"].keys()[0]
        access_lport1=0x10001
        access_port2_vid=0
        access_phy_port2=config["port_map"].keys()[1]
        access_lport2=0x10002
        vnid=10
        next_hop_id=1
        next_hop_id_mcast=2
        dst_mac="00:00:11:22:22:11"
        mcast_ipv4="224.1.1.1"
        dst_mac_mcast="01:00:5e:01:01:01"
        network_port_phy_port=config["port_map"].keys()[2]
        network_lport=0x10003
        network_port_vlan=2
        network_port_sip="192.168.1.1"
        network_port_dip="192.168.2.1"

        feature_reply=get_featureReplay(self)	
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)
        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=mcast_ipv4, next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport1, phy_port=access_phy_port1, 
                                        vlan=access_port1_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport1, access_phy_port1, access_port1_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport2, phy_port=access_phy_port2, 
                                        vlan=access_port2_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport2, access_phy_port2, access_port2_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)            
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport, 
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        #get_edit_config(config["switch_ip"])
        
        #add port table to have vxlan ability
        add_port_table_flow(self.controller)

        #for network port need l2 interface group to decide vlan tag or not
        add_one_l2_interface_grouop(self.controller, network_port_phy_port, vlan_id=network_port_vlan)        

		#add DLF bridge flow
        msg=add_l2_overlay_flood_over_unicast_tunnel_group(self.controller, vnid, [access_lport1, access_lport2, network_lport], 1)        
        add_overlay_bridge_flow(self.controller, None, vnid, msg.group_id, True, True)
        
        #send packet on access port
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:00:11:11:11:11',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)

        #verify packet on access port		
        parsed_pkt = simple_udp_packet(pktlen=92, eth_dst='00:00:11:11:11:11')
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, access_phy_port2)
        #vxlan packet IP header have some parmater decide by HW,
        #we can easy to check VxLAN IP header
        verify_packet(self, pkt, network_port_phy_port)        
        verify_no_other_packets(self)

        add_overlay_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, 0x9a], vnid, network_lport, False, True)        
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:12:34:56:78:9a',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)
        #verify packet on network port		
        parsed_pkt = simple_udp_packet(pktlen=92, eth_dst='00:12:34:56:78:9a')
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, network_port_phy_port)        
        verify_no_other_packets(self)
        
		#exit verification so clear all configuration
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport1, phy_port=access_phy_port1, 
												vlan=access_port1_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport2, phy_port=access_phy_port2, 
												vlan=access_port2_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)            
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=network_lport, 
												src_ip=network_port_sip, dst_ip=network_port_dip, 
												next_hop_id=next_hop_id, 
												vnid=vnid, operation="delete")												
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=None, next_hop_id=None, operation="delete")
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

class AccessWithAccess(base_tests.SimpleDataPlane):
   def runTest(self):
        """
        first verify flood over unicast, 
        second verify flood over mcast
        """
        if 	config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")		
            return
			
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
  
        access_port1_vid=1
        access_phy_port1=config["port_map"].keys()[0]
        access_lport1=0x10001
        access_port2_vid=0
        access_phy_port2=config["port_map"].keys()[1]
        access_lport2=0x10002
        access_port3_vid=3
        access_phy_port3=config["port_map"].keys()[2]
        access_lport3=0x10003
        vnid=10
        next_hop_id_mcast=1
        mcast_ipv4="224.1.1.1"
        dst_mac_mcast="01:00:5e:01:01:01"
        
        feature_reply=get_featureReplay(self)	
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=access_phy_port3, 
												  vlan=access_port3_vid)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id_mcast, dst_mac_mcast, access_phy_port3, access_port3_vid);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)

        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=mcast_ipv4, next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport1, phy_port=access_phy_port1, 
                                        vlan=access_port1_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport1, access_phy_port1, access_port1_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport2, phy_port=access_phy_port2, 
                                        vlan=access_port2_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport2, access_phy_port2, access_port2_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)            
        
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport3, phy_port=access_phy_port3, 
                                        vlan=access_port3_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport3, access_phy_port3, access_port3_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)            

        
        #add port table to have vxlan ability
        add_port_table_flow(self.controller)

		#add DLF bridge flow
        msg=add_l2_overlay_flood_over_mcast_tunnel_group(self.controller, vnid, [access_lport1, access_lport2, access_lport3], 1)        
        add_overlay_bridge_flow(self.controller, None, vnid, msg.group_id, True, True)
        
        #send packet on access port
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:00:11:11:11:11',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)

        #verify packet on access port 2, vid=0, so untag
        parsed_pkt = simple_udp_packet(pktlen=92, eth_dst='00:00:11:11:11:11')
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, access_phy_port2)
        #verify packet on access port 3
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:00:11:11:11:11',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port3_vid)
        pkt = str(parsed_pkt)
        verify_packet(self, pkt, access_phy_port3) 
        verify_no_other_packets(self)
        
        add_overlay_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, 0x9a], vnid, access_lport2, False, True)        
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:12:34:56:78:9a',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)
        #verify packet on access port		
        parsed_pkt = simple_udp_packet(pktlen=92, eth_dst='00:12:34:56:78:9a')
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, access_phy_port2)        
        verify_no_other_packets(self)


        add_overlay_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, 0xaa], vnid, access_lport3, False, True)
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:12:34:56:78:aa',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)
        #verify packet on access port		
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:12:34:56:78:aa',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port3_vid)
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, access_phy_port3)
        verify_no_other_packets(self)

        
        
		#exit verification so clear all configuration
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport1, phy_port=access_phy_port1, 
												vlan=access_port1_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport2, phy_port=access_phy_port2, 
												vlan=access_port2_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport3, phy_port=access_phy_port3, 
                                        vlan=access_port3_vid, vnid=vnid, operation="delete")
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport3, access_phy_port3, access_port3_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)   
        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=None, next_hop_id=None, operation="delete")
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=access_phy_port3, 
												  vlan=access_port3_vid, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

class AccessWithNetwork(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        
class NetworkToNetwork(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)        