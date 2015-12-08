"""
Group table test
Verify each group table can created correctly
"""
from oftest import config

import logging
import random

from oftest import config
import oftest
import oftest.base_tests as base_tests
import ofp

from oftest.testutils import *
from accton_util import *

def getkey(type):
    def byGroupId(stats_entry):
        return stats_entry.group_id
        
    def byGroupType(stats_entry):
        return stats_entry.group_type

        
    if type == "group_id":
        return byGroupId
    elif type == "group_type":
        return byGroupType
    else:
         assert(0)
    return byGroupId        
               
class L2InterfaceGroupOne(base_tests.SimpleDataPlane):
    def runTest(self):    
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    

        group_list1, msg1 = add_one_l2_interface_group(self.controller, config["port_map"].keys()[0], 1,  False, False)
        stats = get_stats(self, ofp.message.group_desc_stats_request())
 
        verify_group_stats=[ofp.group_desc_stats_entry(
                          group_type=msg1.group_type,
                          group_id=msg1.group_id,
                          buckets=msg1.buckets)]

        self.maxDiff=None

        self.assertEquals(stats, verify_group_stats)

class L2InterfaceGroup(base_tests.SimpleDataPlane):
    def runTest(self):    
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    

        group_list1, msg1 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)
        group_list2, msg2 =add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)       
        
        stats = get_stats(self, ofp.message.group_desc_stats_request())
 
        verify_group_stats=[]

        for msg in msg1:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets))        

        for msg in msg2:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets))

        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id")) 
        #self.maxDiff=None        
        self.assertEquals(stats, verify_group_stats)
        
class L2McastGroup(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    
        
        group_list1, msg1 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)       
        msg2=add_l2_mcast_group(self.controller, config["port_map"].keys(), 1, 1)
        
        group_list1, msg3 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)               
        msg4=add_l2_mcast_group(self.controller, config["port_map"].keys(), 2, 2)

        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        for msg in msg1:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg2.group_type,
                                  group_id=msg2.group_id,
                                  buckets=msg2.buckets)
                                  )
        
        for msg in msg3:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg4.group_type,
                                  group_id=msg4.group_id,
                                  buckets=msg4.buckets)
                                  )
                                  
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))                                   
        self.maxDiff=None
        self.assertEquals(stats, verify_group_stats)


class L2FloodGroup(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    
        
        group_list1, msg1 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)       
        msg2=add_l2_flood_group(self.controller, config["port_map"].keys(), 1, 1)
        
        group_list1, msg3 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)               
        msg4=add_l2_flood_group(self.controller, config["port_map"].keys(), 2, 2)

        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        for msg in msg1:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg2.group_type,
                                  group_id=msg2.group_id,
                                  buckets=msg2.buckets)
                                  )
        
        for msg in msg3:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg4.group_type,
                                  group_id=msg4.group_id,
                                  buckets=msg4.buckets)
                                  )
                                  
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))                                   
        self.maxDiff=None
        self.assertEquals(stats, verify_group_stats)


class L2RewriteGroup(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    
        
        group_list1, msg1 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)       
        msg2=add_l2_rewrite_group(self.controller, config["port_map"].keys()[0], 1, 1, [00,11,22,33,44,55], [00,22,22,22,22,22])
        
        group_list1, msg3 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)               
        msg4=add_l2_rewrite_group(self.controller, config["port_map"].keys()[0], 2, 2, [00,11,22,33,44,55], [00,33,33,33,33,33])

        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        for msg in msg1:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg2.group_type,
                                  group_id=msg2.group_id,
                                  buckets=msg2.buckets)
                                  )
        
        for msg in msg3:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg4.group_type,
                                  group_id=msg4.group_id,
                                  buckets=msg4.buckets)
                                  )

        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id")) 
                                  
        self.maxDiff=None
        self.assertEquals(stats, verify_group_stats)
        

class L3UnicastGroup(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    
        
        group_list1, msg1 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)       
        msg2=add_l3_unicast_group(self.controller, config["port_map"].keys()[0], 1, 1, [0x00,0x11,0x22,0x33,0x44,0x55], [00,0x22,0x22,0x22,0x22,0x22])
        
        group_list1, msg3 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)               
        msg4=add_l3_unicast_group(self.controller, config["port_map"].keys()[0], 2, 2, [0x00,0x11,0x22,0x33,0x44,0x55], [00,0x33,0x33,0x33,0x33,0x33])

        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        for msg in msg1:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg2.group_type,
                                  group_id=msg2.group_id,
                                  buckets=msg2.buckets)
                                  )
        
        for msg in msg3:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg4.group_type,
                                  group_id=msg4.group_id,
                                  buckets=msg4.buckets)
                                  )
                                  
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id")) 
                                  
        self.maxDiff=None
        self.assertEquals(stats, verify_group_stats)  


class L3ECMPGroup(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    
        
        group_list1, msg1 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)       
        msg2=add_l3_unicast_group(self.controller, config["port_map"].keys()[0], 1, 1, [0x00,0x11,0x22,0x33,0x44,0x55], [00,0x22,0x22,0x22,0x22,0x22])
        
        group_list1, msg3 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)               
        msg4=add_l3_unicast_group(self.controller, config["port_map"].keys()[0], 2, 2, [0x00,0x11,0x22,0x33,0x44,0x55], [00,0x33,0x33,0x33,0x33,0x33])

        group_ids=[msg2.group_id, msg4.group_id]
        
        msg5=add_l3_ecmp_group(self.controller, 1, group_ids)
        
        stats = get_stats(self, ofp.message.group_desc_stats_request())

        verify_group_stats=[]
        for msg in msg1:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg2.group_type,
                                  group_id=msg2.group_id,
                                  buckets=msg2.buckets)
                                  )
        
        for msg in msg3:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg4.group_type,
                                  group_id=msg4.group_id,
                                  buckets=msg4.buckets)
                                  )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg5.group_type,
                                  group_id=msg5.group_id,
                                  buckets=msg5.buckets)
                                  )

        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id")) 
                                  
        self.maxDiff=None
        self.assertEquals(stats, verify_group_stats)     


class L3InterfaceGroup(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    
        
        group_list1, msg1 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)               
        msg2=add_l3_interface_group(self.controller, config["port_map"].keys()[0], 1, 1, [0x00,0x11,0x22,0x33,0x44,0x55])
        group_list1, msg3 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)                       
        msg4=add_l3_interface_group(self.controller, config["port_map"].keys()[0], 2, 2, [0x00,0x11,0x22,0x33,0x44,0x66])

        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        for msg in msg1:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg2.group_type,
                                  group_id=msg2.group_id,
                                  buckets=msg2.buckets)
                                  )
        
        for msg in msg3:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg4.group_type,
                                  group_id=msg4.group_id,
                                  buckets=msg4.buckets)
                                  )

        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id")) 
                                  
        self.maxDiff=None
        self.assertEquals(stats, verify_group_stats)     


class L3McastGroup(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    

        # Vlan 3 forward to vlan 3 port 1 and 2
        # Vlan 3 foward to vlan 1 port 1
        # Vlan 3 foward to vlan 2 port 1     
        # Vlan 3 foward to vlan 2 port 2             
        group_list1_1, msg1 = add_l2_interface_grouop(self.controller, [config["port_map"].keys()[0]], 1,  False, False)               
        msg2=add_l3_interface_group(self.controller, config["port_map"].keys()[0], 1, 1, [0x00,0x11,0x22,0x33,0x44,0x11])
        group_list1_2, msg3 = add_l2_interface_grouop(self.controller, [config["port_map"].keys()[0]], 2,  False, False)
        msg4=add_l3_interface_group(self.controller, config["port_map"].keys()[0], 2, 2, [0x00,0x11,0x22,0x33,0x44,0x22])
        group_list2_1, msg5 = add_l2_interface_grouop(self.controller, [config["port_map"].keys()[1]], 2,  False, False)
        msg6=add_l3_interface_group(self.controller, config["port_map"].keys()[1], 2, 3, [0x00,0x11,0x22,0x33,0x44,0x33])
        group_list3, msg7 = add_l2_interface_grouop(self.controller, config["port_map"].keys(), 3,  False, False)
        
        group_actions=[msg2.group_id, msg4.group_id, msg6.group_id]
        group_actions.extend(group_list3)

        msg8=add_l3_mcast_group(self.controller, 3, 1, group_actions)
        
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        for msg in msg1:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg2.group_type,
                                  group_id=msg2.group_id,
                                  buckets=msg2.buckets)
                                  )
        
        for msg in msg3:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg4.group_type,
                                  group_id=msg4.group_id,
                                  buckets=msg4.buckets)
                                  )
        for msg in msg5:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg6.group_type,
                                  group_id=msg6.group_id,
                                  buckets=msg6.buckets)
                                  )                                      
        for msg in msg7:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )                                      
                                      
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=msg8.group_type,
                                  group_id=msg8.group_id,
                                  buckets=msg8.buckets)
                                  )  

        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id")) 
                                  
        self.maxDiff=None
        self.assertEquals(stats, verify_group_stats)     
        
        
class mpls_intf_group(base_tests.SimpleDataPlane):
    """
	create mpls intf group 
	1. ref l2_intf_group
	2. ref l2_flood_group
	"""
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    

        test_vid=1
        
        #ref l2_intf_group
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(self.controller, config["port_map"].keys()[0], test_vid,  False, False)
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, l2_intf_gid, [0x00,0x11,0x11,0x11,0x11,0x11], [0x00,0x22,0x22,0x22,0x22,0x22], vid=test_vid, index=1)
            
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=l2_intf_msg.group_type,
                                  group_id=l2_intf_msg.group_id,
                                  buckets=l2_intf_msg.buckets)
                                  )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_intf_msg.group_type,
                                  group_id=mpls_intf_msg.group_id,
                                  buckets=mpls_intf_msg.buckets)
                                  )
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))  
        self.assertEquals(stats, verify_group_stats)       
              

class mpls_l2_vpn_group(base_tests.SimpleDataPlane):
    """
	create mpls intf group 
	1. ref l2_intf_group
	
	"""
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    

        test_vid=1
        test_port=config["port_map"].keys()[0]        
        #ref l2_intf_group
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(self.controller, test_port, test_vid,  False, False)
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, l2_intf_gid, [0x00,0x11,0x11,0x11,0x11,0x11], [0x00,0x22,0x22,0x22,0x22,0x22], vid=test_vid, index=1)        
        mpls_label_gid, mpls_label_msg=add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 
		                                                  index=1, 
														  ref_gid=mpls_intf_gid, 
                                                          push_l2_header=True,
                                                          push_vlan=True,
                                                          push_mpls_header=True,
                                                          push_cw=False,
                                                          set_mpls_label=10,
                                                          set_bos=0,
                                                          set_tc=7,
                                                          set_tc_from_table=False,
														  cpy_tc_outward=False,														  
                                                          set_ttl=250,
                                                          cpy_ttl_outward=False,
                                                          oam_lm_tx_count=False,
                                                          set_pri_from_table=False
                                                          )
                   
        verify_group_stats=[]
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=l2_intf_msg.group_type,
                                  group_id=l2_intf_msg.group_id,
                                  buckets=l2_intf_msg.buckets)
                                  )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_intf_msg.group_type,
                                  group_id=mpls_intf_msg.group_id,
                                  buckets=mpls_intf_msg.buckets)
                                  )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_label_msg.group_type,
                                  group_id=mpls_label_msg.group_id,
                                  buckets=mpls_label_msg.buckets)
                                  )                                  
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats= get_stats(self, ofp.message.group_desc_stats_request())        
        stats=sorted(stats, key=getkey("group_id"))  
        #DumpGroup(stats, verify_group_stats)
        #AssertGroup(self, stats, verify_group_stats)
        self.assertEquals(stats, verify_group_stats)       
		

class mpls_tunnel_lable1_group(base_tests.SimpleDataPlane):
    """
	create mpls intf group 
	1. ref l2_intf_group
	
	"""
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    

        test_vid=1
        test_port=config["port_map"].keys()[0]        
        #ref l2_intf_group
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(self.controller, test_port, test_vid,  False, False)
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, l2_intf_gid, [0x00,0x11,0x11,0x11,0x11,0x11], [0x00,0x22,0x22,0x22,0x22,0x22], vid=test_vid, index=1)                
        mpls_label_gid, mpls_label_msg=add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 
		                                                  index=1, 
														  ref_gid=mpls_intf_gid, 
                                                          push_l2_header=True,
                                                          push_vlan=True,
                                                          push_mpls_header=True,
                                                          push_cw=True,
                                                          set_mpls_label=10,
                                                          set_bos=0,
                                                          set_tc=7,
                                                          set_tc_from_table=False,
														  cpy_tc_outward=False,														  
                                                          set_ttl=250,
                                                          cpy_ttl_outward=False,
                                                          oam_lm_tx_count=False,
                                                          set_pri_from_table=False
                                                          )
            
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=l2_intf_msg.group_type,
                                  group_id=l2_intf_msg.group_id,
                                  buckets=l2_intf_msg.buckets)
                                  )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_intf_msg.group_type,
                                  group_id=mpls_intf_msg.group_id,
                                  buckets=mpls_intf_msg.buckets)
                                  )        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_label_msg.group_type,
                                  group_id=mpls_label_msg.group_id,
                                  buckets=mpls_label_msg.buckets)
                                  )
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))  
        self.assertEquals(stats, verify_group_stats)       
		

class mpls_tunnel_lable2_group(base_tests.SimpleDataPlane):
    """
	create mpls intf group 
	1. ref l2_intf_group
	
	"""
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    

        test_vid=1
        test_port=config["port_map"].keys()[0]        
        #ref l2_intf_group
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(self.controller, test_port, test_vid,  False, False)
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, l2_intf_gid, [0x00,0x11,0x11,0x11,0x11,0x11], [0x00,0x22,0x22,0x22,0x22,0x22], vid=test_vid, index=1)                        
        mpls_label_gid, mpls_label_msg=add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL2, 
		                                                  index=1, 
														  ref_gid=mpls_intf_gid, 
                                                          push_l2_header=True,
                                                          push_vlan=True,
                                                          push_mpls_header=True,
                                                          push_cw=True,
                                                          set_mpls_label=10,
                                                          set_bos=0,
                                                          set_tc=7,
                                                          set_tc_from_table=False,
														  cpy_tc_outward=False,														  
                                                          set_ttl=250,
                                                          cpy_ttl_outward=False,
                                                          oam_lm_tx_count=False,
                                                          set_pri_from_table=False
                                                          )
            
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=l2_intf_msg.group_type,
                                  group_id=l2_intf_msg.group_id,
                                  buckets=l2_intf_msg.buckets)
                                  )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_intf_msg.group_type,
                                  group_id=mpls_intf_msg.group_id,
                                  buckets=mpls_intf_msg.buckets)
                                  )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_label_msg.group_type,
                                  group_id=mpls_label_msg.group_id,
                                  buckets=mpls_label_msg.buckets)
                                  )                                  
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))  
        self.assertEquals(stats, verify_group_stats)       
		
class mpls_swap_label_group(base_tests.SimpleDataPlane):
    """
	create mpls intf group 
	1. ref l2_intf_group
	"""
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    

        test_vid=1
        test_port=config["port_map"].keys()[0]
        #ref l2_intf_group
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(self.controller, test_port, test_vid,  False, False)
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, l2_intf_gid, [0x00,0x11,0x11,0x11,0x11,0x11], [0x00,0x22,0x22,0x22,0x22,0x22], vid=test_vid, index=1)                                
        mpls_label_gid, mpls_label_msg=add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_SWAP_LABEL, 
		                                                  index=1, 
														  ref_gid=mpls_intf_gid, 
                                                          push_l2_header=True,
                                                          push_vlan=True,
                                                          push_mpls_header=True,
                                                          push_cw=True,
                                                          set_mpls_label=10,
                                                          set_bos=0,
                                                          set_tc=7,
                                                          set_tc_from_table=False,
														  cpy_tc_outward=False,														  
                                                          set_ttl=250,
                                                          cpy_ttl_outward=False,
                                                          oam_lm_tx_count=False,
                                                          set_pri_from_table=False
                                                          )
            
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=l2_intf_msg.group_type,
                                  group_id=l2_intf_msg.group_id,
                                  buckets=l2_intf_msg.buckets)
                                  )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_intf_msg.group_type,
                                  group_id=mpls_intf_msg.group_id,
                                  buckets=mpls_intf_msg.buckets)
                                  )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_label_msg.group_type,
                                  group_id=mpls_label_msg.group_id,
                                  buckets=mpls_label_msg.buckets)
                                  )                                    
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))  
        self.assertEquals(stats, verify_group_stats)       


class mpls_forwarding_group_fastfailover(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller) 

        test_vid=1
        test_port=config["port_map"].keys()[0]
        #ref l2_intf_group
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(self.controller, test_port, test_vid,  False, False)
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, l2_intf_gid, [0x00,0x11,0x11,0x11,0x11,0x11], [0x00,0x22,0x22,0x22,0x22,0x22], vid=test_vid, index=1)                                
        mpls_label_gid, mpls_label_msg=add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_SWAP_LABEL, 
		                                                  index=1, 
														  ref_gid=mpls_intf_gid, 
                                                          push_l2_header=True,
                                                          push_vlan=True,
                                                          push_mpls_header=True,
                                                          push_cw=True,
                                                          set_mpls_label=10,
                                                          set_bos=0,
                                                          set_tc=7,
                                                          set_tc_from_table=False,
														  cpy_tc_outward=False,														  
                                                          set_ttl=250,
                                                          cpy_ttl_outward=False,
                                                          oam_lm_tx_count=False,
                                                          set_pri_from_table=False
                                                          )        
        mpls_fwd_gid, mpls_fwd_msg=add_mpls_forwarding_group(self.controller, 
                                                             subtype=OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 
                                                             index=1, 
                                                             ref_gids=[mpls_label_gid], 
                                                             watch_port=test_port, 
                                                             watch_group=ofp.OFPP_ANY, 
                                                             push_vlan=None,
                                                             pop_vlan=None,
                                                             set_vid=None)
            
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=l2_intf_msg.group_type,
                                  group_id=l2_intf_msg.group_id,
                                  buckets=l2_intf_msg.buckets)
                                  )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_intf_msg.group_type,
                                  group_id=mpls_intf_msg.group_id,
                                  buckets=mpls_intf_msg.buckets)
                                  )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_label_msg.group_type,
                                  group_id=mpls_label_msg.group_id,
                                  buckets=mpls_label_msg.buckets)
                                  )
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_fwd_msg.group_type,
                                  group_id=mpls_fwd_msg.group_id,
                                  buckets=mpls_fwd_msg.buckets)
                                  )                                    
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))  
        self.assertEquals(stats, verify_group_stats)       


class mpls_forwarding_group_ecmp(base_tests.SimpleDataPlane):
    """chip not support to bind flow on trident2 
    """
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller) 

        test_vid=1
        mpls_intf_msgs=[]
        mpls_intf_gids=[]
        l2_intf_msgs=[]
        index=1
        #ref l2_intf_group
        for port in config["port_map"].keys():
            l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(self.controller, port, test_vid,  False, False)
            l2_intf_msgs.append(l2_intf_msg)            
            mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, l2_intf_gid, [0x00,0x11,0x11,0x11,0x11,0x11], [0x00,0x22,0x22,0x22,0x22,0x22], vid=test_vid, index=index)
            index=index+1
            mpls_intf_msgs.append(mpls_intf_msg)
            mpls_intf_gids.append(mpls_intf_gid)
            
        mpls_fwd_gid, mpls_fwd_msg=add_mpls_forwarding_group(self.controller, 
                                                             subtype=OFDPA_MPLS_GROUP_SUBTYPE_ECMP, 
                                                             index=1, 
                                                             ref_gids=mpls_intf_gids, 
                                                             watch_port=None, 
                                                             watch_group=None,
                                                             push_vlan=None,
                                                             pop_vlan=None,
                                                             set_vid=None)
            
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        for msg in l2_intf_msgs:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )
        
        for msg in mpls_intf_msgs:
            verify_group_stats.append(ofp.group_desc_stats_entry(
                                      group_type=msg.group_type,
                                      group_id=msg.group_id,
                                      buckets=msg.buckets)
                                      )

        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_fwd_msg.group_type,
                                  group_id=mpls_fwd_msg.group_id,
                                  buckets=mpls_fwd_msg.buckets)
                                  )                                    
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))  
        self.assertEquals(stats, verify_group_stats)       


class mpls_forwarding_group_l2tag(base_tests.SimpleDataPlane):
    """chip not support
    """
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller) 

        test_vid=1
        test_port=config["port_map"].keys()[0]
        index=1
        #ref l2_intf_group        
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(self.controller, test_port, test_vid,  False, False)

        mpls_fwd_gid, mpls_fwd_msg=add_mpls_forwarding_group(self.controller, 
                                                             subtype=OFDPA_MPLS_GROUP_SUBTYPE_L2_TAG, 
                                                             index=1, 
                                                             ref_gids=l2_intf_gid, 
                                                             watch_port=None, 
                                                             watch_group=None,
                                                             push_vlan=None,
                                                             pop_vlan=None,
                                                             set_vid=1)
            
        stats = get_stats(self, ofp.message.group_desc_stats_request())
        
        verify_group_stats=[]
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=l2_intf_msg.group_type,
                                  group_id=l2_intf_msg.group_id,
                                  buckets=l2_intf_msg.buckets)
                                  )
        
        verify_group_stats.append(ofp.group_desc_stats_entry(
                                  group_type=mpls_fwd_msg.group_type,
                                  group_id=mpls_fwd_msg.group_id,
                                  buckets=mpls_fwd_msg.buckets)
                                  )                                    
        verify_group_stats=sorted(verify_group_stats, key=getkey("group_id")) 
        stats=sorted(stats, key=getkey("group_id"))  

        self.assertEquals(stats, verify_group_stats)  