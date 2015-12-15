import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time
from oftest.testutils import *

from ncclient import manager
import ncclient

OFDPA_GROUP_TYPE_SHIFT=28
OFDPA_VLAN_ID_SHIFT   =16
OFDPA_TUNNEL_ID_SHIFT =12
OFDPA_TUNNEL_SUBTYPE_SHIFT=10

#VLAN_TABLE_FLAGS
VLAN_TABLE_FLAG_ONLY_UNTAG=1
VLAN_TABLE_FLAG_ONLY_TAG  =2
VLAN_TABLE_FLAG_ONLY_BOTH =3

PORT_FLOW_TABLE=0
VLAN_FLOW_TABLE=10
TERMINATION_FLOW_TABLE=20
UCAST_ROUTING_FLOW_TABLE=30
MCAST_ROUTING_FLOW_TABLE=40
BRIDGE_FLOW_TABLE=50
ACL_FLOW_TABLE=60

def convertIP4toStr(ip_addr):
    a=(ip_addr&0xff000000)>>24
    b=(ip_addr&0x00ff0000)>>16
    c=(ip_addr&0x0000ff00)>>8
    d=(ip_addr&0x000000ff)
    return str(a)+"."+str(b)+"."+str(c)+"."+str(d)

def convertMACtoStr(mac):
    if not isinstance(mac, list):
        assert(0)

    return ':'.join(['%02X' % x for x in mac])

def getSwitchCpuMACFromDPID(dpid):
    str_datapath_id_f= "{:016x}".format(dpid)
    str_datapath_id=':'.join([str_datapath_id_f[i:i+2] for i in range(0, len(str_datapath_id_f), 2)])
    switch_cpu_mac_str=str_datapath_id[6:]
    switch_cpu_mac = switch_cpu_mac_str.split(":")
    switch_cpu_mac=[int(switch_cpu_mac[i],16) for i in range(0, len(switch_cpu_mac))]

    return switch_cpu_mac_str, switch_cpu_mac
        
def DumpGroup(stats, verify_group_stats, always_show=True):
    if(len(stats) > len(verify_group_stats)):
        min_len = len(verify_group_stats)
        print "Stats Len is not the same, stats>verify_group_stats"
    if(len(stats)< len(verify_group_stats)):
        min_len = len(stats)    
        print "Stats Len is not the same, stats<verify_group_stats"
    else:   
        min_len = len(stats)

    print "\r\n"
    for i in range(min_len):
        gs = stats[i]
        gv = verify_group_stats[i]        
        print "FromSwtich:(GID=%lx, TYPE=%lx)\r\nVerify    :(GID=%lx, TYPE=%lx)"%(gs.group_id, gs.group_type, gv.group_id, gv.group_type)
        if(len(gs.buckets) != len(gv.buckets)):
            print "buckets len is not the same gs %lx, gv %lx",(len(gs.buckets), len(gv.buckets))

        for j in range(len(gs.buckets)):
           b1=gs.buckets[j]
           b2=gv.buckets[j]           
           if(len(b1.actions) != len(b2.actions)):
               print "action len is not the same"

           for k in range(len(b1.actions)):
               a1=b1.actions[k]
               a2=b2.actions[k]
               if(always_show == True):
                   print "a1:"+a1.show()
                   print "a2:"+a2.show()               

def AssertGroup(self, stats, verify_group_stats):
    self.assertTrue(len(stats) ==len(verify_group_stats), "stats len is not the same")

    for i in range(len(stats)):
        gs = stats[i]
        gv = verify_group_stats[i]        
        self.assertTrue(len(gs.buckets) == len(gv.buckets), "buckets len is not the same")

        for j in range(len(gs.buckets)):
           b1=gs.buckets[j]
           b2=gv.buckets[j]           
           self.assertTrue(len(b1.actions) == len(b2.actions), "action len is not the same")

           for k in range(len(b1.actions)):
               a1=b1.actions[k]
               a2=b2.actions[k]
               self.assertEquals(a1, a2, "action is not the same")
    
def encode_l2_interface_group_id(vlan, id):
    return id + (vlan << OFDPA_VLAN_ID_SHIFT)

def encode_l2_rewrite_group_id(id):
    return id + (1 << OFDPA_GROUP_TYPE_SHIFT)

def encode_l3_unicast_group_id(id):
    return id + (2 << OFDPA_GROUP_TYPE_SHIFT)

def encode_l2_mcast_group_id(vlan, id):
    return id + (vlan << OFDPA_VLAN_ID_SHIFT) + (3 << OFDPA_GROUP_TYPE_SHIFT)

def encode_l2_flood_group_id(vlan, id):
    return id + (vlan << OFDPA_VLAN_ID_SHIFT) + (4 << OFDPA_GROUP_TYPE_SHIFT)
    
def encode_l3_interface_group_id(id):
    return id + (5 << OFDPA_GROUP_TYPE_SHIFT)

def encode_l3_mcast_group_id(vlan, id):
    return id + (vlan << OFDPA_VLAN_ID_SHIFT)+(6 << OFDPA_GROUP_TYPE_SHIFT)

def encode_l3_ecmp_group_id(id):
    return id + (7 << OFDPA_GROUP_TYPE_SHIFT)

def encode_l2_overlay_group_id(tunnel_id, subtype, index):
    tunnel_id=tunnel_id&0xffff #16 bits
    subtype = subtype&3        #2 bits
    index = index & 0x3f       #10 bits
    return index + (tunnel_id << OFDPA_TUNNEL_ID_SHIFT)+ (subtype<<OFDPA_TUNNEL_SUBTYPE_SHIFT)+(8 << OFDPA_GROUP_TYPE_SHIFT)

def add_l2_interface_group(ctrl, ports, vlan_id=1, is_tagged=False, send_barrier=False):
    # group table
    # set up untag groups for each port
    group_id_list=[]
    msgs=[]
    for of_port in ports:
        # do stuff
        group_id = encode_l2_interface_group_id(vlan_id, of_port)
        group_id_list.append(group_id)
        if is_tagged:
            actions = [
                ofp.action.output(of_port),
            ]        
        else:
            actions = [
                ofp.action.pop_vlan(),
                ofp.action.output(of_port),
            ]

        buckets = [
            ofp.bucket(actions=actions),
        ]

        request = ofp.message.group_add(group_type=ofp.OFPGT_INDIRECT,
                                        group_id=group_id,
                                        buckets=buckets
                                       )
        ctrl.message_send(request)
        msgs.append(request)

        if send_barrier:
            do_barrier(ctrl)
 
    return group_id_list, msgs

def add_one_l2_interface_group(ctrl, port, vlan_id=1, is_tagged=False, send_barrier=False):
    # group table
    # set up untag groups for each port
    group_id = encode_l2_interface_group_id(vlan_id, port)

    if is_tagged:
        actions = [
            ofp.action.output(port),
        ]        
    else:
        actions = [
            ofp.action.pop_vlan(),
            ofp.action.output(port),
        ]

    buckets = [
        ofp.bucket(actions=actions),
    ]

    request = ofp.message.group_add(group_type=ofp.OFPGT_INDIRECT,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)
 
    return group_id, request
    
def add_l2_mcast_group(ctrl, ports, vlanid, mcast_grp_index):
    buckets=[]
    for of_port in ports:
        group_id = encode_l2_interface_group_id(vlanid, of_port)
        action=[ofp.action.group(group_id)]
        buckets.append(ofp.bucket(actions=action))

    group_id =encode_l2_mcast_group_id(vlanid, mcast_grp_index)
    request = ofp.message.group_add(group_type=ofp.OFPGT_ALL,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request

def add_l2_flood_group(ctrl, ports, vlanid, id):
    buckets=[]
    for of_port in ports:
        group_id = encode_l2_interface_group_id(vlanid, of_port)
        action=[ofp.action.group(group_id)]
        buckets.append(ofp.bucket(actions=action))

    group_id =encode_l2_flood_group_id(vlanid, id)
    request = ofp.message.group_add(group_type=ofp.OFPGT_ALL,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request

def add_l2_rewrite_group(ctrl, port, vlanid, id, src_mac, dst_mac):
    group_id = encode_l2_interface_group_id(vlanid, port)

    action=[]
    if src_mac is not None:
        action.append(ofp.action.set_field(ofp.oxm.eth_src(src_mac)))

    if dst_mac is not None:
        action.append(ofp.action.set_field(ofp.oxm.eth_dst(dst_mac)))

    action.append(ofp.action.set_field(ofp.oxm.vlan_vid(vlanid)))
        
    action.append(ofp.action.group(group_id))
    
    buckets = [ofp.bucket(actions=action)]

    group_id =encode_l2_rewrite_group_id(id)
    request = ofp.message.group_add(group_type=ofp.OFPGT_INDIRECT,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request
    
def add_l3_unicast_group(ctrl, port, vlanid, id, src_mac, dst_mac):
    group_id = encode_l2_interface_group_id(vlanid, port)

    action=[]
    if src_mac is not None:
        action.append(ofp.action.set_field(ofp.oxm.eth_src(src_mac)))

    if dst_mac is not None:
        action.append(ofp.action.set_field(ofp.oxm.eth_dst(dst_mac)))

    action.append(ofp.action.set_field(ofp.oxm.vlan_vid(vlanid)))
        
    action.append(ofp.action.group(group_id))
    
    buckets = [ofp.bucket(actions=action)]

    group_id =encode_l3_unicast_group_id(id)
    request = ofp.message.group_add(group_type=ofp.OFPGT_INDIRECT,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request
    
def add_l3_interface_group(ctrl, port, vlanid, id, src_mac):
    group_id = encode_l2_interface_group_id(vlanid, port)

    action=[]
    action.append(ofp.action.set_field(ofp.oxm.eth_src(src_mac)))
    action.append(ofp.action.set_field(ofp.oxm.vlan_vid(vlanid)))       
    action.append(ofp.action.group(group_id))
    
    buckets = [ofp.bucket(actions=action)]

    group_id =encode_l3_interface_group_id(id)
    request = ofp.message.group_add(group_type=ofp.OFPGT_INDIRECT,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request

def add_l3_ecmp_group(ctrl, id, l3_ucast_groups):
    buckets=[]
    for group in l3_ucast_groups:
        buckets.append(ofp.bucket(actions=[ofp.action.group(group)]))

    group_id =encode_l3_ecmp_group_id(id)
    request = ofp.message.group_add(group_type=ofp.OFPGT_SELECT,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request
        
def add_l3_mcast_group(ctrl, vid,  mcast_group_id, groups_on_buckets):
    buckets=[]
    for group in groups_on_buckets:
        buckets.append(ofp.bucket(actions=[ofp.action.group(group)]))
    
    group_id =encode_l3_mcast_group_id(vid, mcast_group_id)
    request = ofp.message.group_add(group_type=ofp.OFPGT_ALL,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request

def add_l2_overlay_flood_over_unicast_tunnel_group(ctrl, tunnel_id, ports, index):
    buckets=[]
    for port in ports:
        buckets.append(ofp.bucket(actions=[ofp.action.output(port)]))

    group_id=encode_l2_overlay_group_id(tunnel_id, 0, index)
    request = ofp.message.group_add(group_type=ofp.OFPGT_ALL,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request

def add_l2_overlay_flood_over_mcast_tunnel_group(ctrl, tunnel_id, ports, index):
    buckets=[]
    for port in ports:
        buckets.append(ofp.bucket(actions=[ofp.action.output(port)]))

    group_id=encode_l2_overlay_group_id(tunnel_id, 1, index)
    request = ofp.message.group_add(group_type=ofp.OFPGT_ALL,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request

def add_l2_overlay_mcast_over_unicast_tunnel_group(ctrl, tunnel_id, ports, index):
    buckets=[]
    for port in ports:
        buckets.append(ofp.bucket(actions=[ofp.action.output(port)]))

    group_id=encode_l2_overlay_group_id(tunnel_id, 2, index)
    request = ofp.message.group_add(group_type=ofp.OFPGT_ALL,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request

def add_l2_overlay_mcast_over_mcast_tunnel_group(ctrl, tunnel_id, ports, index):
    buckets=[]
    for port in ports:
        buckets.append(ofp.bucket(actions=[ofp.action.output(port)]))

    group_id=encode_l2_overlay_group_id(tunnel_id, 3, index)
    request = ofp.message.group_add(group_type=ofp.OFPGT_ALL,
                                    group_id=group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return request
	
def add_port_table_flow(ctrl, is_overlay=True):
    match = ofp.match()

    if is_overlay == True:
       match.oxm_list.append(ofp.oxm.in_port(0x10000))
       NEXT_TABLE=50
    else:
       match.oxm_list.append(ofp.oxm.in_port(0))
       NEXT_TABLE=10       

    request = ofp.message.flow_add(
		table_id=0,
		cookie=42,
		match=match,
		instructions=[
		  ofp.instruction.goto_table(NEXT_TABLE)
		],
		priority=0)
    logging.info("Add port table, match port %lx" % 0x10000)
    ctrl.message_send(request)
    

def pop_vlan_flow(ctrl, ports, vlan_id=1):
    # table 10: vlan
    # goto to table 20
    msgs=[]
    for of_port in ports:
            match = ofp.match()
            match.oxm_list.append(ofp.oxm.in_port(of_port))
            match.oxm_list.append(ofp.oxm.vlan_vid(0x1000+vlan_id))
            request = ofp.message.flow_add(
                table_id=10,
                cookie=42,
                match=match,
                instructions=[
                  ofp.instruction.apply_actions(
                    actions=[
                      ofp.action.pop_vlan()
                    ]
                  ),
                  ofp.instruction.goto_table(20)
                ],
                priority=0)
            logging.info("Add vlan %d tagged packets on port %d and go to table 20" %( vlan_id, of_port))
            ctrl.message_send(request)


    return msgs

def add_vlan_table_flow(ctrl, ports, vlan_id=1, flag=VLAN_TABLE_FLAG_ONLY_BOTH, send_barrier=False):
    # table 10: vlan
    # goto to table 20
    msgs=[]
    for of_port in ports:
        if (flag == VLAN_TABLE_FLAG_ONLY_TAG) or (flag == VLAN_TABLE_FLAG_ONLY_BOTH):
            match = ofp.match()
            match.oxm_list.append(ofp.oxm.in_port(of_port))
            match.oxm_list.append(ofp.oxm.vlan_vid(0x1000+vlan_id))
            request = ofp.message.flow_add(
                table_id=10,
                cookie=42,
                match=match,
                instructions=[
                  ofp.instruction.apply_actions(
                    actions=[
                      ofp.action.pop_vlan()
                    ]
                  ),
                  ofp.instruction.goto_table(20)
                ],
                priority=0)
            logging.info("Add vlan %d tagged packets on port %d and go to table 20" %( vlan_id, of_port))
            ctrl.message_send(request)
            
        if (flag == VLAN_TABLE_FLAG_ONLY_UNTAG) or (flag == VLAN_TABLE_FLAG_ONLY_BOTH):
            match = ofp.match()
            match.oxm_list.append(ofp.oxm.in_port(of_port))
            match.oxm_list.append(ofp.oxm.vlan_vid_masked(0, 0x1fff))
            request = ofp.message.flow_add(
                table_id=10,
                cookie=42,
                match=match,
                instructions=[
                  ofp.instruction.apply_actions(
                    actions=[
                      ofp.action.set_field(ofp.oxm.vlan_vid(vlan_id))
                    ]
                  ),
                  ofp.instruction.goto_table(20)
                ],
                priority=0)
            logging.info("Add vlan %d untagged packets on port %d and go to table 20" % (vlan_id, of_port))
            ctrl.message_send(request)
            msgs.append(request)

    if send_barrier:
        do_barrier(ctrl)

    return msgs
    
def del_vlan_table_flow(ctrl, ports, vlan_id=1, flag=VLAN_TABLE_FLAG_ONLY_BOTH, send_barrier=False):
    # table 10: vlan
    # goto to table 20
    msgs=[]
    for of_port in ports:
        if (flag == VLAN_TABLE_FLAG_ONLY_TAG) or (flag == VLAN_TABLE_FLAG_ONLY_BOTH):
            match = ofp.match()
            match.oxm_list.append(ofp.oxm.in_port(of_port))
            match.oxm_list.append(ofp.oxm.vlan_vid(0x1000+vlan_id))
            request = ofp.message.flow_delete(
                table_id=10,
                cookie=42,
                match=match,
                priority=0)
            logging.info("Del vlan %d tagged packets on port %d and go to table 20" %( vlan_id, of_port))
            ctrl.message_send(request)

        if (flag == VLAN_TABLE_FLAG_ONLY_UNTAG) or (flag == VLAN_TABLE_FLAG_ONLY_BOTH):
            match = ofp.match()
            match.oxm_list.append(ofp.oxm.in_port(of_port))
            match.oxm_list.append(ofp.oxm.vlan_vid_masked(0, 0xfff))
            request = ofp.message.flow_delete(
                table_id=10,
                cookie=42,
                match=match,
                priority=0)
            logging.info("Del vlan %d untagged packets on port %d and go to table 20" % (vlan_id, of_port))
            ctrl.message_send(request)
            msgs.append(request)

    if send_barrier:
        do_barrier(ctrl)

    return msgs
    
def add_vlan_table_flow_pvid(ctrl, in_port, match_vid=None, pvid=1, send_barrier=False):
    """it will tag pack as untagged packet wether it has tagg or not"""
    match = ofp.match()
    match.oxm_list.append(ofp.oxm.in_port(in_port))
    actions=[]
    if match_vid == None:
        match.oxm_list.append(ofp.oxm.vlan_vid(0))    
        actions.append(ofp.action.set_field(ofp.oxm.vlan_vid(0x1000+pvid)))
        goto_table=20
    else:
        match.oxm_list.append(ofp.oxm.vlan_vid_masked(0x1000+match_vid, 0x1fff))
        actions.append(ofp.action.push_vlan(0x8100))
        actions.append(ofp.action.set_field(ofp.oxm.vlan_vid(0x1000+pvid)))        
        goto_table=20
        
    request = ofp.message.flow_add(
        table_id=10,
        cookie=42,
        match=match,
        instructions=[
             ofp.instruction.apply_actions(actions=actions)
            ,ofp.instruction.goto_table(goto_table)
        ],
        priority=0)
    logging.info("Add PVID %d on port %d and go to table %ld" %( pvid, in_port, goto_table))
    ctrl.message_send(request)   
    
    if send_barrier:
        do_barrier(ctrl)

def add_vlan_table_flow_allow_all_vlan(ctrl, in_port, send_barrier=False):
    """it st flow allow all vlan tag on this port"""
    match = ofp.match()
    match.oxm_list.append(ofp.oxm.in_port(in_port))
    match.oxm_list.append(ofp.oxm.vlan_vid_masked(0x1000, 0x1000))
    request = ofp.message.flow_add(
        table_id=10,
        cookie=42,
        match=match,
        instructions=[
            ofp.instruction.goto_table(20) 
        ],
        priority=0)
    logging.info("Add allow all vlan on port %d " %(in_port))
    ctrl.message_send(request)    

def add_one_vlan_table_flow(ctrl, of_port, vlan_id=1, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_BOTH, send_barrier=False):
    # table 10: vlan
    # goto to table 20
    if (flag == VLAN_TABLE_FLAG_ONLY_TAG) or (flag == VLAN_TABLE_FLAG_ONLY_BOTH):
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(of_port))
        match.oxm_list.append(ofp.oxm.vlan_vid_masked(0x1000+vlan_id,0x1fff))

        actions=[]
        if vrf!=0:
            actions.append(ofp.action.set_field(ofp.oxm.exp2ByteValue(exp_type=1, value=vrf)))
            
        #actions.append(ofp.action.set_field(ofp.oxm.vlan_vid(value=vlan_id)))

        request = ofp.message.flow_add(
            table_id=10,
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.apply_actions(
                     actions=actions
                ),
                ofp.instruction.goto_table(20)
            ],
            priority=0)
        logging.info("Add vlan %d tagged packets on port %d and go to table 20" %( vlan_id, of_port))
        ctrl.message_send(request)
        
    if (flag == VLAN_TABLE_FLAG_ONLY_UNTAG) or (flag == VLAN_TABLE_FLAG_ONLY_BOTH):
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(of_port))
        match.oxm_list.append(ofp.oxm.vlan_vid_masked(0, 0x1fff))
        
        actions=[]
        if vrf!=0:
            actions.append(ofp.action.set_field(ofp.oxm.exp2ByteValue(exp_type=1, value=vrf)))
            
        actions.append(ofp.action.set_field(ofp.oxm.vlan_vid(vlan_id)))
        
        request = ofp.message.flow_add(
            table_id=10,
            cookie=42,
            match=match,
            instructions=[
              ofp.instruction.apply_actions(
                actions=actions
              ),
              ofp.instruction.goto_table(20)
            ],
            priority=0)
        logging.info("Add vlan %d untagged packets on port %d and go to table 20" % (vlan_id, of_port))
        ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)

    return request
    
def add_bridge_flow(ctrl, dst_mac, vlanid, group_id, send_barrier=False):
    match = ofp.match()
    priority=500
    if dst_mac!=None:
        priority=1000
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac))

    match.oxm_list.append(ofp.oxm.vlan_vid(0x1000+vlanid))

    request = ofp.message.flow_add(
            table_id=50,
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(group_id)]),
                    ofp.instruction.goto_table(60)
                ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=priority)

    logging.info("Inserting Brdige flow vlan %d, mac %s", vlanid, dst_mac)
    ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)   

    return request        

def add_overlay_bridge_flow(ctrl, dst_mac, vnid, group_id, is_group=True, send_barrier=False):
    match = ofp.match()
    if dst_mac!=None:
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac))

    match.oxm_list.append(ofp.oxm.tunnel_id(vnid))
    if is_group == True:
        actions=[ofp.action.group(group_id)]
    else:
        actions=[ofp.action.output(group_id)]

    request = ofp.message.flow_add(
            table_id=50,
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=actions),
                    ofp.instruction.goto_table(60)
                ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1000) 

    logging.info("Inserting Brdige flow vnid %d, mac %s", vnid, dst_mac)
    ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)   

    return request        
    
def add_termination_flow(ctrl, in_port, eth_type, dst_mac, vlanid, goto_table=None, send_barrier=False):
    match = ofp.match()
    match.oxm_list.append(ofp.oxm.eth_type(eth_type))
    if dst_mac[0]&0x01 == 0x01:
       match.oxm_list.append(ofp.oxm.eth_dst_masked(dst_mac, [0xff, 0xff, 0xff, 0x80, 0x00, 0x00]))
       goto_table=40
    else:
       if in_port!=0:
           match.oxm_list.append(ofp.oxm.in_port(in_port))
       match.oxm_list.append(ofp.oxm.eth_dst(dst_mac))
       match.oxm_list.append(ofp.oxm.vlan_vid(0x1000+vlanid))
       if goto_table == None:
           goto_table=30

    request = ofp.message.flow_add(
            table_id=20,
            cookie=42,
            match=match,
            instructions=[
                    ofp.instruction.goto_table(goto_table)
                ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1) 

    logging.info("Inserting termination flow inport %d, eth_type %lx, vlan %d, mac %s", in_port, eth_type, vlanid, dst_mac)
    ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)   

    return request    
    
def add_unicast_routing_flow(ctrl, eth_type, dst_ip, mask, action_group_id, vrf=0, send_barrier=False):
    match = ofp.match()
    match.oxm_list.append(ofp.oxm.eth_type(eth_type))
    if vrf != 0:
        match.oxm_list.append(ofp.oxm.exp2ByteValue(ofp.oxm.OFDPA_EXP_TYPE_VRF, vrf))
    
    if mask!=0:
        match.oxm_list.append(ofp.oxm.ipv4_dst_masked(dst_ip, mask))
    else:
        match.oxm_list.append(ofp.oxm.ipv4_dst(dst_ip))


    request = ofp.message.flow_add(
            table_id=30,
            cookie=42,
            match=match,
            instructions=[
                    ofp.instruction.write_actions(
                        actions=[ofp.action.group(action_group_id)]),
                    ofp.instruction.goto_table(60)
                ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1) 

    logging.info("Inserting unicast routing flow eth_type %lx, dip %ld",eth_type, dst_ip)
    ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)   

    return request        

def add_mpls_flow(ctrl, action_group_id, label=100 ,ethertype=0x0800, bos=1, send_barrier=False):
    match = ofp.match()
    match.oxm_list.append(ofp.oxm.eth_type(0x8847))
    match.oxm_list.append(ofp.oxm.mpls_label(label))
    match.oxm_list.append(ofp.oxm.mpls_bos(bos))
    actions = [ofp.action.dec_mpls_ttl(),
               ofp.action.copy_ttl_in(),
               ofp.action.pop_mpls(ethertype)]
    request = ofp.message.flow_add(
            table_id=24,
            cookie=43,
            match=match,
            instructions=[
                    ofp.instruction.apply_actions(
                        actions=actions
                    ),
                    ofp.instruction.write_actions(
                        actions=[ofp.action.group(action_group_id)]),
                    ofp.instruction.goto_table(60)
                ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1)

    logging.info("Inserting MPLS flow , label %ld", label)
    ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)

    return request


def add_mcast4_routing_flow(ctrl, vlan_id, src_ip, src_ip_mask, dst_ip, action_group_id, send_barrier=False):
    match = ofp.match()
    match.oxm_list.append(ofp.oxm.eth_type(0x0800))
    match.oxm_list.append(ofp.oxm.vlan_vid(vlan_id))    
    if src_ip_mask!=0:
        match.oxm_list.append(ofp.oxm.ipv4_src_masked(src_ip, src_ip_mask))
    else:
        match.oxm_list.append(ofp.oxm.ipv4_src(src_ip))
        
    match.oxm_list.append(ofp.oxm.ipv4_dst(dst_ip))
    
    request = ofp.message.flow_add(
            table_id=40,
            cookie=42,
            match=match,
            instructions=[
                    ofp.instruction.write_actions(
                        actions=[ofp.action.group(action_group_id)]),
                    ofp.instruction.goto_table(60)
                ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1) 

    logging.info("Inserting mcast routing flow eth_type %lx, dip %lx, sip %lx, sip_mask %lx",0x0800, dst_ip, src_ip, src_ip_mask)
    ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)   

    return request            

#dpctl tcp:192.168.1.1:6633 flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x71000001 goto:60
def add_dnat_flow(ctrl, eth_type, ip_dst, ip_proto, tcp_dst, set_ip_dst, set_tcp_dst, action_group_id):
    match = ofp.match()
    match.oxm_list.append(ofp.oxm.eth_type(eth_type))
    match.oxm_list.append(ofp.oxm.ipv4_dst(ip_dst))
    match.oxm_list.append(ofp.oxm.ip_proto(ip_proto))
    match.oxm_list.append(ofp.oxm.tcp_dst(tcp_dst))
    
    request = ofp.message.flow_add(
            table_id=28,
            cookie=42,
            match=match,
            instructions=[
                    ofp.instruction.write_actions(
                        actions=[ofp.action.set_field(ofp.oxm.ipv4_dst(set_ip_dst)),
                                 ofp.action.set_field(ofp.oxm.tcp_dst(set_tcp_dst)),
                                 ofp.action.group(action_group_id)]),
                    ofp.instruction.goto_table(60)
                ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1) 
    logging.info("Inserting DNAT flow eth_type %lx, dip %lx, ip_proto %ld, tcp_dst %ld, SetFeild: Dip %lx, tcp_dst %ld, action_gorup=%lx",eth_type, ip_dst, ip_proto, tcp_dst, set_ip_dst, set_tcp_dst, action_group_id)
    ctrl.message_send(request)
    return request

#dpctl tcp:192.168.1.1:6633 flow-mod table=29,cmd=add,prio=291 eth_type=0x800,ip_src=10.0.0.1,ip_proto=6,tcp_src=2000 write:set_field=ip_src:100.0.0.1,set_field=tcp_src:5000 goto:30
def add_snat_flow(ctrl, eth_type, ip_src, ip_proto, tcp_src, set_ip_src, set_tcp_src):
    match = ofp.match()
    match.oxm_list.append(ofp.oxm.eth_type(eth_type))
    match.oxm_list.append(ofp.oxm.ipv4_src(ip_src))
    match.oxm_list.append(ofp.oxm.ip_proto(ip_proto))
    match.oxm_list.append(ofp.oxm.tcp_src(tcp_src))
    
    request = ofp.message.flow_add(
            table_id=29,
            cookie=42,
            match=match,
            instructions=[
                    ofp.instruction.write_actions(
                        actions=[ofp.action.set_field(ofp.oxm.ipv4_src(set_ip_src)),
                                 ofp.action.set_field(ofp.oxm.tcp_src(set_tcp_src))]),
                    ofp.instruction.goto_table(30)
                ],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1) 
    logging.info("Inserting DNAT flow eth_type %lx, sip %lx, ip_proto %ld, tcp_src %ld, SetFeild: sip %lx, tcp_src %ld",eth_type, ip_src, ip_proto, tcp_src, set_ip_src, set_tcp_src)
    ctrl.message_send(request)
    return request
    
def get_vtap_lport_config_xml(dp_id, lport, phy_port, vlan, vnid, operation='merge'):  
    """
    Command Example:
    of-agent vtap 10001 ethernet 1/1 vid 1
    of-agent vtp 10001 vni 10
    """
    if vlan != 0:
        config_vtap_xml="""
        <config>
            <capable-switch xmlns="urn:onf:of111:config:yang" xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <id>capable-switch-1</id>
                <resources>
                    <port xc:operation="OPERATION">
                        <resource-id >LPORT</resource-id>     
                        <features>
                            <current>
                              <rate>10Gb</rate>
                              <medium>fiber</medium>
                              <pause>symmetric</pause>      
                            </current>
                            <advertised>
                              <rate>10Gb</rate>
                              <rate>100Gb</rate>
                              <medium>fiber</medium>
                              <pause>symmetric</pause>
                            </advertised>    
                            <supported>
                              <rate>10Gb</rate>
                              <rate>100Gb</rate>
                              <medium>fiber</medium>
                              <pause>symmetric</pause>
                            </supported> 
                            <advertised-peer>
                              <rate>10Gb</rate>
                              <rate>100Gb</rate>
                              <medium>fiber</medium>
                              <pause>symmetric</pause>
                            </advertised-peer>        
                        </features>
                        <ofdpa10:vtap xmlns:ofdpa10="urn:bcm:ofdpa10:accton01" xc:operation="OPERATION">
                            <ofdpa10:phy-port>PHY_PORT</ofdpa10:phy-port>
                            <ofdpa10:vid>VLAN_ID</ofdpa10:vid>
                            <ofdpa10:vni>VNID</ofdpa10:vni>
                        </ofdpa10:vtap>
                    </port> 
              </resources>
              <logical-switches>
                  <switch>
                    <id>DATAPATH_ID</id>
                    <datapath-id>DATAPATH_ID</datapath-id>
                    <resources>
                      <port xc:operation="OPERATION">LPORT</port>
                    </resources>
                  </switch>
              </logical-switches>
            </capable-switch>
          </config>
        """    
    else:
        config_vtap_xml="""
        <config>
            <capable-switch xmlns="urn:onf:of111:config:yang" xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <id>capable-switch-1</id>
                <resources>
                    <port xc:operation="OPERATION">
                        <resource-id >LPORT</resource-id>     
                        <features>
                            <current>
                              <rate>10Gb</rate>
                              <medium>fiber</medium>
                              <pause>symmetric</pause>      
                            </current>
                            <advertised>
                              <rate>10Gb</rate>
                              <rate>100Gb</rate>
                              <medium>fiber</medium>
                              <pause>symmetric</pause>
                            </advertised>    
                            <supported>
                              <rate>10Gb</rate>
                              <rate>100Gb</rate>
                              <medium>fiber</medium>
                              <pause>symmetric</pause>
                            </supported> 
                            <advertised-peer>
                              <rate>10Gb</rate>
                              <rate>100Gb</rate>
                              <medium>fiber</medium>
                              <pause>symmetric</pause>
                            </advertised-peer>        
                        </features>
                        <ofdpa10:vtap xmlns:ofdpa10="urn:bcm:ofdpa10:accton01" xc:operation="OPERATION">
                            <ofdpa10:phy-port>PHY_PORT</ofdpa10:phy-port>
                            <ofdpa10:vni>VNID</ofdpa10:vni>
                        </ofdpa10:vtap>
                    </port> 
              </resources>
              <logical-switches>
                  <switch>
                    <id>DATAPATH_ID</id>
                    <datapath-id>DATAPATH_ID</datapath-id>
                    <resources>
                      <port xc:operation="OPERATION">LPORT</port>
                    </resources>
                  </switch>
              </logical-switches>
            </capable-switch>
          </config>
        """        
    str_datapath_id_f= "{:016x}".format(dp_id)        
    str_datapath_id=':'.join([str_datapath_id_f[i:i+2] for i in range(0, len(str_datapath_id_f), 2)])	
    config_vtap_xml=config_vtap_xml.replace("DATAPATH_ID", str_datapath_id)      
    config_vtap_xml=config_vtap_xml.replace("LPORT", str(int(lport)))         
    config_vtap_xml=config_vtap_xml.replace("PHY_PORT", str(phy_port))       
    config_vtap_xml=config_vtap_xml.replace("VLAN_ID", str(vlan))     
    config_vtap_xml=config_vtap_xml.replace("VNID", str(vnid))
    config_vtap_xml=config_vtap_xml.replace("OPERATION", str(operation))
    return config_vtap_xml
      
def get_vtep_lport_config_xml(dp_id, lport, src_ip, dst_ip, next_hop_id, vnid, udp_src_port=6633, ttl=25, operation='merge'): 
    """
    Command Example:
    of-agent vtep 10002 source user-input-src-ip destination user-input-dst-ip udp-source-port 6633 nexthop 2 ttl 25
    of-agent vtp 10001 vni 10    
    """

    config_vtep_xml="""
        <config>
          <capable-switch xmlns="urn:onf:of111:config:yang" xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
            <id>capable-switch-1</id>
            <resources>
             <port xc:operation="OPERATION">
               <resource-id>LPORT</resource-id>     
                 <features>
                   <current>
                     <rate>10Gb</rate>
                     <medium>fiber</medium>
                     <pause>symmetric</pause>      
                   </current>
                   <advertised>
                     <rate>10Gb</rate>
                     <rate>100Gb</rate>
                     <medium>fiber</medium>
                     <pause>symmetric</pause>
                   </advertised>    
                   <supported>
                     <rate>10Gb</rate>
                     <rate>100Gb</rate>
                     <medium>fiber</medium>
                     <pause>symmetric</pause>
                   </supported> 
                   <advertised-peer>
                     <rate>10Gb</rate>
                     <rate>100Gb</rate>
                     <medium>fiber</medium>
                     <pause>symmetric</pause>
                   </advertised-peer>        
                </features>
			  <ofdpa10:vtep xmlns:ofdpa10="urn:bcm:ofdpa10:accton01">
				<ofdpa10:src-ip>SRC_IP</ofdpa10:src-ip>
				<ofdpa10:dest-ip>DST_IP</ofdpa10:dest-ip>
				<ofdpa10:udp-src-port>UDP_SRC_PORT</ofdpa10:udp-src-port>
				<ofdpa10:vni xc:operation="OPERATION">
                    <ofdpa10:id>VNID</ofdpa10:id>
                </ofdpa10:vni>
				<ofdpa10:nexthop-id>NEXT_HOP_ID</ofdpa10:nexthop-id>
				<ofdpa10:ttl>TTL</ofdpa10:ttl>
			  </ofdpa10:vtep>
             </port> 
            </resources>
            <logical-switches>
                <switch>
                  <id>DATAPATH_ID</id>
                  <datapath-id>DATAPATH_ID</datapath-id>
                  <resources>
                    <port xc:operation="OPERATION">LPORT</port>
                  </resources>
                </switch>
            </logical-switches>
          </capable-switch>
        </config>  
    """
    str_datapath_id_f= "{:016x}".format(dp_id)        
    str_datapath_id=':'.join([str_datapath_id_f[i:i+2] for i in range(0, len(str_datapath_id_f), 2)])	
    config_vtep_xml=config_vtep_xml.replace("DATAPATH_ID", str_datapath_id)      
    config_vtep_xml=config_vtep_xml.replace("LPORT", str(int(lport)))
    config_vtep_xml=config_vtep_xml.replace("SRC_IP", str(src_ip))            
    config_vtep_xml=config_vtep_xml.replace("DST_IP", str(dst_ip))                 
    config_vtep_xml=config_vtep_xml.replace("UDP_SRC_PORT", str(udp_src_port))                      
    config_vtep_xml=config_vtep_xml.replace("NEXT_HOP_ID", str(next_hop_id))                           
    config_vtep_xml=config_vtep_xml.replace("TTL", str(ttl))                           
    config_vtep_xml=config_vtep_xml.replace("VNID", str(vnid))
    config_vtep_xml=config_vtep_xml.replace("OPERATION", str(operation))		

    return config_vtep_xml   
      
def get_next_hop_config_xml(next_hop_id, dst_mac, phy_port, vlan, operation='merge'): 
    #of-agent nexthop 2 destination user-input-dst-mac ethernet 1/2 vid 2
    config_nexthop_xml="""
      <config>
          <of11-config:capable-switch xmlns:of11-config="urn:onf:of111:config:yang" xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ofdpa10:next-hop xmlns:ofdpa10="urn:bcm:ofdpa10:accton01"  xc:operation="OPERATION">
              <ofdpa10:id>NEXT_HOP_ID</ofdpa10:id>
              <ofdpa10:dest-mac>DST_MAC</ofdpa10:dest-mac>
              <ofdpa10:phy-port>PHY_PORT</ofdpa10:phy-port>
              <ofdpa10:vid>VLAN_ID</ofdpa10:vid>
            </ofdpa10:next-hop>
          </of11-config:capable-switch>
      </config>
      """
    config_nexthop_xml=config_nexthop_xml.replace("VLAN_ID", str(vlan))
    config_nexthop_xml=config_nexthop_xml.replace("PHY_PORT", str(phy_port))   
    config_nexthop_xml=config_nexthop_xml.replace("NEXT_HOP_ID", str(next_hop_id))   
    config_nexthop_xml=config_nexthop_xml.replace("DST_MAC", str(dst_mac))   
    config_nexthop_xml=config_nexthop_xml.replace("OPERATION", str(operation))	
    return config_nexthop_xml   

def get_vni_config_xml(vni_id, mcast_ipv4, next_hop_id, operation='merge'):  
    #of-agent vni 10 multicast 224.1.1.1 nexthop 20
    if mcast_ipv4!=None:    
        config_vni_xml="""
          <config>
              <of11-config:capable-switch xmlns:of11-config="urn:onf:of111:config:yang" xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <ofdpa10:vni xmlns:ofdpa10="urn:bcm:ofdpa10:accton01" xc:operation="OPERATION">
                  <ofdpa10:id>VNID</ofdpa10:id>
                  <ofdpa10:vni-multicast-group>MCAST_IP</ofdpa10:vni-multicast-group>
                  <ofdpa10:multicast-group-nexthop-id>NEXT_HOP_ID</ofdpa10:multicast-group-nexthop-id>
                </ofdpa10:vni>
              </of11-config:capable-switch>
          </config>
          """   
        config_vni_xml=config_vni_xml.replace("NEXT_HOP_ID", str(next_hop_id))   
        config_vni_xml=config_vni_xml.replace("MCAST_IP", str(mcast_ipv4))             
    else:
        config_vni_xml="""
          <config>
              <of11-config:capable-switch xmlns:of11-config="urn:onf:of111:config:yang" xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <ofdpa10:vni xmlns:ofdpa10="urn:bcm:ofdpa10:accton01" xc:operation="OPERATION">
                  <ofdpa10:id>VNID</ofdpa10:id>
                </ofdpa10:vni>
              </of11-config:capable-switch>
          </config>
          """   
          
    config_vni_xml=config_vni_xml.replace("VNID", str(vni_id))            
    config_vni_xml=config_vni_xml.replace("OPERATION", str(operation))	
    return config_vni_xml
	
def get_featureReplay(self):    
    req = ofp.message.features_request()
    res, raw = self.controller.transact(req)
    self.assertIsNotNone(res, "Did not receive a response from the DUT.")        
    self.assertEqual(res.type, ofp.OFPT_FEATURES_REPLY,
                 ("Unexpected packet type %d received in response to "
                  "OFPT_FEATURES_REQUEST") % res.type)
    return res		
	
def send_edit_config(switch_ip, xml, target='runing'):
    NETCONF_ACCOUNT="netconfuser"
    NETCONF_PASSWD="netconfuser"
    with manager.connect_ssh(host=switch_ip, port=830, username=NETCONF_ACCOUNT, password=NETCONF_PASSWD, hostkey_verify=False ) as m:
        try:
            m.edit_config(target='running', 
                      config=xml, 
                      default_operation='merge', 
                      error_option='stop-on-error')

        except Exception as e:
            logging.info("Fail to set xml %s", xml)
            return False

	#return m.get_config(source='running').data_xml
    return True

def send_delete_config(switch_ip, xml, target='runing'):
    NETCONF_ACCOUNT="netconfuser"
    NETCONF_PASSWD="netconfuser"
    with manager.connect_ssh(host=switch_ip, port=830, username=NETCONF_ACCOUNT, password=NETCONF_PASSWD, hostkey_verify=False ) as m:
        try:
            m.edit_config(target='running', 
                      config=xml, 
                      default_operation='delete', 
                      error_option='stop-on-error')

        except Exception as e:
            logging.info("Fail to set xml %s", xml)
            return False

	#return m.get_config(source='running').data_xml
    return True
    
def get_edit_config(switch_ip, target='runing'):
    NETCONF_ACCOUNT="netconfuser"
    NETCONF_PASSWD="netconfuser"
    with manager.connect_ssh(host=switch_ip, port=830, username=NETCONF_ACCOUNT, password=NETCONF_PASSWD, hostkey_verify=False ) as m:
	    return m.get_config(source='running').data_xml


"""
MPLS
"""

OFDPA_MPLS_SUBTYPE_SHIFT=24
OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL=1 
OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL=2
OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1=3
OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL2=4
OFDPA_MPLS_GROUP_SUBTYPE_SWAP_LABEL=5
OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP=6
OFDPA_MPLS_GROUP_SUBTYPE_ECMP=8
OFDPA_MPLS_GROUP_SUBTYPE_L2_TAG=10

def encode_mpls_interface_group_id(subtype, index):
    index=index&0x00ffffff
    assert(subtype==0)
    return index + (9 << OFDPA_GROUP_TYPE_SHIFT)+(subtype<<OFDPA_MPLS_SUBTYPE_SHIFT)

def encode_mpls_label_group_id(subtype, index):
    index=index&0x00ffffff
    assert(subtype <=5 or subtype==0)
    #1: l2 vpn label
    #2: l3 vpn label
    #3: mpls tunnel label 1
    #4: mpls tunnel lable 2
    #5: mpls swap label
    return index + (9 << OFDPA_GROUP_TYPE_SHIFT)+(subtype<<OFDPA_MPLS_SUBTYPE_SHIFT)         

def encode_mpls_forwarding_group_id(subtype, index):
    index=index&0x00ffffff
    assert(subtype==6 or subtype==8 or subtype==10)
    return index + (10 << OFDPA_GROUP_TYPE_SHIFT)+(subtype<<OFDPA_MPLS_SUBTYPE_SHIFT)         


def add_mpls_intf_group(ctrl, ref_gid, dst_mac, src_mac, vid, index, subtype=0):
    action=[]
    action.append(ofp.action.set_field(ofp.oxm.eth_src(src_mac)))
    action.append(ofp.action.set_field(ofp.oxm.eth_dst(dst_mac)))
    action.append(ofp.action.set_field(ofp.oxm.vlan_vid(vid)))    
    action.append(ofp.action.group(ref_gid))
    
    buckets = [ofp.bucket(actions=action)]

    mpls_group_id =encode_mpls_interface_group_id(subtype, index)
    request = ofp.message.group_add(group_type=ofp.OFPGT_INDIRECT,
                                    group_id=mpls_group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return mpls_group_id, request

def add_mpls_label_group(ctrl, subtype, index, ref_gid, 
                         lmep_id=-1,
                         qos_index=-1,
                         push_l2_header=False,
                         push_vlan=False,
                         push_mpls_header=False,
                         push_cw=False,
                         set_mpls_label=None,
                         set_bos=None,
                         set_tc=None,
                         set_tc_from_table=False,
                         cpy_tc_outward=False,
                         set_ttl=None,
                         cpy_ttl_outward=False,
                         oam_lm_tx_count=False,
                         set_pri_from_table=False
                         ):
    """
    @ref_gid: only can be mpls intf group or mpls tunnel label 1/2 group
    """      
    action=[]

    if push_vlan== True:
        action.append(ofp.action.push_vlan(0x8100))
    if push_mpls_header== True:
        action.append(ofp.action.push_mpls(0x8847))
    if set_mpls_label != None:
        action.append(ofp.action.set_field(ofp.oxm.mpls_label(set_mpls_label)))
    if set_bos != None:
        action.append(ofp.action.set_field(ofp.oxm.mpls_bos(set_bos)))
    if set_tc != None:
        assert(set_tc_from_table==False)
        action.append(ofp.action.set_field(ofp.oxm.mpls_tc(set_tc)))
    if set_ttl != None:
        action.append(ofp.action.set_mpls_ttl(set_ttl))  
    if cpy_ttl_outward == True:
        action.append(ofp.action.copy_ttl_out())  
    """
    ofdpa experimenter
    """    
    if push_l2_header== True:
        action.append(ofp.action.ofdpa_push_l2_header())          
    if set_tc_from_table== True:
        assert(qos_index>=0)
        assert(set_tc == None)
        action.append(ofp.action.ofdpa_set_tc_from_table(qos_index))        
    if cpy_tc_outward == True:
        action.append(ofp.action.ofdpa_copy_tc_out())	
    if oam_lm_tx_count == True:
        assert(qos_index>=0 and lmep_id>=0)	
        action.append(ofp.action.ofdpa_oam_lm_tx_count(lmep_id, qos_index))  
    if set_pri_from_table == True:
        assert(qos_index>=0)	
        action.append(ofp.action.ofdpa_set_qos_from_table(qos_index))  
    if push_cw == True:
        action.append(ofp.action.ofdpa_push_cw())
       
    action.append(ofp.action.group(ref_gid))    
    buckets = [ofp.bucket(actions=action)]
    
    mpls_group_id = encode_mpls_label_group_id(subtype, index)
    request = ofp.message.group_add(group_type=ofp.OFPGT_INDIRECT,
                                    group_id=mpls_group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    
    return mpls_group_id, request    
    
def add_mpls_forwarding_group(ctrl, subtype, index, ref_gids, 
                              watch_port=None, 
							  watch_group=ofp.OFPP_ANY, 
							  push_vlan=None,
                              pop_vlan=None,
                              set_vid=None):
    assert(subtype == OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP
	       or subtype == OFDPA_MPLS_GROUP_SUBTYPE_ECMP
		   or subtype == OFDPA_MPLS_GROUP_SUBTYPE_L2_TAG)

    buckets=[]
    if subtype == OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP:
        group_type = ofp.OFPGT_FF
        for gid in ref_gids:
            action=[]
            action.append(ofp.action.group(gid)) 
            buckets.append(ofp.bucket(watch_port=watch_port, watch_group=watch_group,actions=action))

    elif subtype == OFDPA_MPLS_GROUP_SUBTYPE_ECMP:
        group_type = ofp.OFPGT_SELECT
        for gid in ref_gids:
            action=[]
            action.append(ofp.action.group(gid))    
            buckets.append(ofp.bucket(actions=action))

    elif subtype == OFDPA_MPLS_GROUP_SUBTYPE_L2_TAG:
        group_type = ofp.OFPGT_INDIRECT
        action=[]
        if set_vid!=None:
            action.append(ofp.action.set_field(ofp.oxm.vlan_vid(set_vid)))
        if push_vlan!=None:
            action.append(ofp.action.push_vlan(push_vlan))		
        if pop_vlan!=None:
            action.append(ofp.action.pop_vlan())		
            action.append(ofp.action.group(ref_gids[0]))    
            buckets.append(ofp.bucket(actions=action))

    mpls_group_id = encode_mpls_forwarding_group_id(subtype, index)
    request = ofp.message.group_add(group_type=group_type,
                                    group_id=mpls_group_id,
                                    buckets=buckets
                                   )
    ctrl.message_send(request)
    return mpls_group_id, request    


"""
dislay
"""   
def print_current_table_flow_stat(ctrl, table_id=0xff):
    stat_req=ofp.message.flow_stats_request()
    response, pkt = ctrl.transact(stat_req)
    if response == None:
        print "no response"
        return None
    print len(response.entries)
    for obj in response.entries:
        print "match ", obj.match
        print "cookie", obj.cookie
        print "priority", obj.priority
        print "idle_timeout", obj.idle_timeout
        print "hard_timeout", obj.hard_timeout
        #obj.actions
        print "packet count: %lx"%obj.packet_count
