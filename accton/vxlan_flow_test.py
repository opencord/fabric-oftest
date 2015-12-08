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

        xml_before=get_edit_config(config["switch_ip"])
		#get datapath_id from feature message
        feature_reply=get_featureReplay(self)	
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id_mcast, dst_mac_mcast, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)                
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id, 
		                                          dst_mac=dst_mac, 
												  phy_port=network_port_phy_port, 
												  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)                                                  
        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, 
                                          mcast_ipv4=mcast_ipv4, 
                                          next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport, phy_port=access_phy_port, 
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_phy_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport, 
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)            
            
        get_edit_config(config["switch_ip"])

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

        vni_config_xml=get_vni_config_xml(vni_id=vnid, 
                                          mcast_ipv4=mcast_ipv4, 
                                          next_hop_id=next_hop_id_mcast, operation="delete")
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

        xml_after=get_edit_config(config["switch_ip"])
        #logging.info("xml_before\n %s", xml_before)
        #logging.info("xml_after\n %s", xml_after)
        #netopeer may have problem on xml process
        #assert(xml_before == xml_after)
        
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
        add_one_l2_interface_group(self.controller, network_port_phy_port, vlan_id=network_port_vlan)

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
        add_one_l2_interface_group(self.controller, network_port_phy_port, vlan_id=network_port_vlan)

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

class AccessWithAccessDiffPortVlan(base_tests.SimpleDataPlane):
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

        
class AccessWithAccessSamePortDiffVlan(base_tests.SimpleDataPlane):
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
        access_port2_vid=2
        access_phy_port2= access_phy_port1
        access_lport2=0x10002
        access_port3_vid=3
        access_phy_port3=access_phy_port1
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
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:00:11:11:11:11',
                                       dl_vlan_enable = True,
                                       vlan_vid = access_port2_vid)
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
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:12:34:56:78:9a',
                                       dl_vlan_enable = True,
                                       vlan_vid = access_port2_vid)
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

        add_overlay_bridge_flow(self.controller, [0x00, 0x12, 0x34, 0x56, 0x78, 0xbb], vnid, access_lport2, False, True)
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:12:34:56:78:bb',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)
        #verify packet on access port		
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst='00:12:34:56:78:bb',
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port2_vid)
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, access_phy_port2)
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
        access_lport1_mac=[0x00, 0x00, 0x00, 0x77, 0x77, 0x77]
        access_lport1_mac_str=(":".join(map(str, map(hex, access_lport1_mac)))).replace("0x", "")
        access_port2_vid=0
        access_phy_port2=config["port_map"].keys()[1]
        access_lport2=0x10002
        access_lport2_mac=[0x00,0x00, 0x00, 0x00, 0x00, 0x02]
        access_lport2_mac_str=(":".join(map(str, map(hex, access_lport2_mac)))).replace("0x", "")		
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
        network_lport_mac=[0x00,0x00, 0x00, 0x00, 0x00, 0x03]
        network_lport_mac_str=(":".join(map(str, map(hex, network_lport_mac)))).replace("0x", "")


        
        feature_reply=get_featureReplay(self)	
        #get switch CPU mac
        str_datapath_id_f= "{:016x}".format(feature_reply.datapath_id)        
        str_datapath_id=':'.join([str_datapath_id_f[i:i+2] for i in range(0, len(str_datapath_id_f), 2)])        
        switch_cpu_mac_str=str_datapath_id[6:]
        switch_cpu_mac = switch_cpu_mac_str.split(":")
        switch_cpu_mac=[int(switch_cpu_mac[i],16) for i in range(0, len(switch_cpu_mac))]

        #add config vtep/vtap/nexthop/vni        
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
        #vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=None, next_hop_id=None)
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
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport, 
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        #add port table to have vxlan ability
        add_port_table_flow(self.controller)
        add_port_table_flow(self.controller, is_overlay=False)
        
        #for network port need l2 interface group to decide vlan tag or not
        add_one_l2_interface_group(self.controller, network_port_phy_port, vlan_id=network_port_vlan)
        #add network mac
        add_overlay_bridge_flow(self.controller, network_lport_mac, vnid, network_lport, False, True)
        add_overlay_bridge_flow(self.controller, access_lport1_mac, vnid, access_lport1, False, True)

        #add termination table for network port
        add_termination_flow(self.controller, in_port=network_port_phy_port, eth_type=0x0800,
                             dst_mac=switch_cpu_mac, vlanid=network_port_vlan)
        #add vlan table for network port rx packet class vlan
        add_one_vlan_table_flow(self.controller, of_port=network_port_phy_port, 
                                vlan_id=network_port_vlan)

        #tx packet on access lport 1        
        parsed_pkt = simple_udp_packet(pktlen=96, eth_dst=network_lport_mac_str,
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        pkt = str(parsed_pkt)
        self.dataplane.send(access_phy_port1, pkt)
        #verify packet on network port	
        #need find a way to verify vxlan header        
        parsed_pkt = simple_udp_packet(pktlen=92, eth_dst=network_lport_mac_str)
        pkt = str(parsed_pkt) 
        verify_packet(self, pkt, network_port_phy_port)        
        verify_no_other_packets(self)
        
        #tx packet on network lport
        inner_pkt = simple_udp_packet(pktlen=96, eth_dst=access_lport1_mac_str)
        vxlan_pkt = simple_vxlan_packet(eth_dst=switch_cpu_mac_str,
                                        vnid=vnid, 
                                        ip_dst= network_port_sip, 
                                        ip_src=network_port_dip,
                                        inner_payload=inner_pkt)
        self.dataplane.send(network_port_phy_port, str(vxlan_pkt))
        #verify
        inner_pkt = simple_udp_packet(pktlen=100, eth_dst=access_lport1_mac_str,
                                       dl_vlan_enable= True,
                                       vlan_vid=access_port1_vid)
        
        verify_packet(self, inner_pkt, access_phy_port1)
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
        
class NetworkToNetwork(base_tests.SimpleDataPlane):
    def runTest(self):
        """
        This case can't work, can't identify it is chip limitation or not
        """
        return
        if 	config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")		
            return
			
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
  
        vnid=10
        mcast_ipv4="224.1.1.1"
        dst_mac_mcast="01:00:5e:01:01:01"       
        next_hop_id_mcast=3

        access_port1_vid=1
        access_phy_port1=config["port_map"].keys()[0]
        access_lport1=0x10001

        network_port1_phy_port=config["port_map"].keys()[1]
        network_lport1=0x10003
        network_port1_vlan=2
        network_port1_sip="192.168.1.1"
        network_port1_dip="192.168.2.1"
        network_port1_next_hop_id=1
        network_port1_dst_mac="00:00:11:22:22:11"
        network_lport1_mac=[0x00,0x00, 0x00, 0x00, 0x00, 0x33]
        network_lport1_mac_str=(":".join(map(str, map(hex, network_lport1_mac)))).replace("0x", "")
        
        network_port2_phy_port=config["port_map"].keys()[2]
        network_lport2=0x10004
        network_port2_vlan=3
        network_port2_sip="192.168.3.1"
        network_port2_dip="192.168.4.1"
        network_port2_next_hop_id=2
        network_port2_dst_mac="00:00:11:22:22:22"
        network_lport2_mac=[0x00,0x00, 0x00, 0x00, 0x00, 0x44]
        network_lport2_mac_str=(":".join(map(str, map(hex, network_lport2_mac)))).replace("0x", "")
        
        feature_reply=get_featureReplay(self)	
        #get switch CPU mac
        str_datapath_id_f= "{:016x}".format(feature_reply.datapath_id)        
        str_datapath_id=':'.join([str_datapath_id_f[i:i+2] for i in range(0, len(str_datapath_id_f), 2)])        
        switch_cpu_mac_str=str_datapath_id[6:]
        switch_cpu_mac = switch_cpu_mac_str.split(":")
        switch_cpu_mac=[int(switch_cpu_mac[i],16) for i in range(0, len(switch_cpu_mac))]
        #config vlxan
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=network_port1_next_hop_id, 
		                                          dst_mac=network_port1_dst_mac, 
												  phy_port=network_port1_phy_port, 
												  vlan=network_port1_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", network_port1_next_hop_id, network_port1_dst_mac, network_port1_phy_port, network_port1_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=network_port2_next_hop_id, 
		                                          dst_mac=network_port2_dst_mac, 
												  phy_port=network_port2_phy_port, 
												  vlan=network_port2_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", network_port2_next_hop_id, network_port2_dst_mac, network_port2_phy_port, network_port2_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port1_phy_port, 
												  vlan=network_port1_vlan)        
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id_mcast, dst_mac_mcast, network_port1_phy_port, network_port1_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml)==True)
        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=mcast_ipv4, next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
            
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                        lport=access_lport1, phy_port=access_phy_port1, 
                                        vlan=access_port1_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport1, access_phy_port1, access_port1_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport1, 
                                                src_ip=network_port1_sip, dst_ip=network_port1_dip,
                                                next_hop_id=network_port1_next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport1, network_port1_sip, network_port1_dip, network_port1_next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
                                                lport=network_lport2, 
                                                src_ip=network_port2_sip, dst_ip=network_port2_dip,
                                                next_hop_id=network_port2_next_hop_id, 
                                                vnid=vnid)												
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport2, network_port2_sip, network_port2_dip, network_port2_next_hop_id);                                                
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        #add port table to have vxlan ability
        add_port_table_flow(self.controller)

        #for network port need l2 interface group to decide vlan tag or not
        add_one_l2_interface_group(self.controller, network_port1_phy_port, vlan_id=network_port1_vlan)
        add_one_l2_interface_group(self.controller, network_port2_phy_port, vlan_id=network_port2_vlan)
        #add network mac
        add_overlay_bridge_flow(self.controller, network_lport1_mac, vnid, network_lport1, False, True)
        add_overlay_bridge_flow(self.controller, network_lport2_mac, vnid, network_lport2, False, True)

        #add termination table for network port
        add_termination_flow(self.controller, in_port=network_port1_phy_port, eth_type=0x0800,
                             dst_mac=switch_cpu_mac, vlanid=network_port1_vlan)
        add_termination_flow(self.controller, in_port=network_port2_phy_port, eth_type=0x0800,
                             dst_mac=switch_cpu_mac, vlanid=network_port2_vlan)                             
        #add vlan table for network port rx packet class vlan
        add_one_vlan_table_flow(self.controller, of_port=network_port1_phy_port, 
                                vlan_id=network_port1_vlan)        
        add_one_vlan_table_flow(self.controller, of_port=network_port2_phy_port, 
                                vlan_id=network_port2_vlan)        
        
        #packet tx on network port 1 rx on network port 2
        inner_pkt = simple_udp_packet(pktlen=96, eth_dst=network_lport2_mac_str)
        vxlan_pkt = simple_vxlan_packet(eth_dst=switch_cpu_mac_str,
                                        vnid=vnid, 
                                        ip_dst= network_port1_sip, 
                                        ip_src=network_port1_dip,
                                        inner_payload=inner_pkt)
        self.dataplane.send(network_port1_phy_port, str(vxlan_pkt))        
        #verify     
        verify_packet(self, str(inner_pkt), network_port2_phy_port)
        verify_no_other_packets(self)

        
        
		#exit verification so clear all configuration
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)   
        
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=access_lport1, phy_port=access_phy_port1, 
												vlan=access_port1_vid, vnid=vnid, operation="delete")
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)
          
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=network_lport1, 
												src_ip=network_port1_sip, dst_ip=network_port1_dip, 
												next_hop_id=network_port1_next_hop_id, 
												vnid=vnid, operation="delete")												
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id, 
		                                        lport=network_lport2, 
												src_ip=network_port2_sip, dst_ip=network_port2_dip, 
												next_hop_id=network_port2_next_hop_id, 
												vnid=vnid, operation="delete")												
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)        
        vni_config_xml=get_vni_config_xml(vni_id=vnid, mcast_ipv4=None, next_hop_id=None, operation="delete")
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)
        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=network_port1_next_hop_id, 
		                                          dst_mac=network_port1_dst_mac, 
												  phy_port=network_port1_phy_port, 
												  vlan=network_port1_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=network_port2_next_hop_id, 
		                                          dst_mac=network_port2_dst_mac, 
												  phy_port=network_port2_phy_port, 
												  vlan=network_port2_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)        
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast, 
		                                          dst_mac=dst_mac_mcast, 
												  phy_port=network_port1_phy_port, 
												  vlan=network_port1_vlan, operation="delete")
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)
        