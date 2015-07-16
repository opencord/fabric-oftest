import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time
from oftest.testutils import *

OFDPA_GROUP_TYPE_SHIFT=28
OFDPA_VLAN_ID_SHIFT   =16
OFDPA_TUNNEL_ID_SHIFT =16

#VLAN_TABLE_FLAGS
VLAN_TABLE_FLAG_ONLY_UNTAG=1
VLAN_TABLE_FLAG_ONLY_TAG  =2
VLAN_TABLE_FLAG_ONLY_BOTH =3

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

def encode_l2_overlay_flood_group_id(tunnel_id, index):
    return id + (tunnel_id << OFDPA_TUNNEL_ID_SHIFT)+(8 << OFDPA_GROUP_TYPE_SHIFT)

def encode_l2_overlay_mcast_group_id(tunnel_id, index):
    return id + (tunnel_id << OFDPA_TUNNEL_ID_SHIFT)+(9 << OFDPA_GROUP_TYPE_SHIFT)

    
def add_l2_interface_grouop(ctrl, ports, vlan_id=1, is_tagged=False, send_barrier=False):
    # group table
    # set up untag groups for each port
    for of_port in ports:
        # do stuff
        group_id = encode_l2_interface_group_id(vlan_id, of_port)
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

        if send_barrier:
            do_barrier(ctrl)


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


def add_vlan_table_flow(ctrl, ports, vlan_id=1, flag=VLAN_TABLE_FLAG_ONLY_BOTH, send_barrier=False):
    # table 10: vlan
    # goto to table 20
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
                  ofp.instruction.goto_table(20)
                ],
                priority=0)
            logging.info("Add vlan %d tagged packets on port %d and go to table 20" %( vlan_id, of_port))
            ctrl.message_send(request)
            
        if (flag == VLAN_TABLE_FLAG_ONLY_UNTAG) or (flag == VLAN_TABLE_FLAG_ONLY_BOTH):
            match = ofp.match()
            match.oxm_list.append(ofp.oxm.in_port(of_port))
            match.oxm_list.append(ofp.oxm.vlan_vid(0))
            request = ofp.message.flow_add(
                table_id=10,
                cookie=42,
                match=match,
                instructions=[
                  ofp.instruction.apply_actions(
                    actions=[
                      ofp.action.set_field(ofp.oxm.vlan_vid(0x1000+vlan_id))
                    ]
                  ),
                  ofp.instruction.goto_table(20)
                ],
                priority=0)
            logging.info("Add vlan %d untagged packets on port %d and go to table 20" % (vlan_id, of_port))
            ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)

def add_bridge_flow(ctrl, dst_mac, vlanid, group_id, send_barrier=False):
    match = ofp.match()
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
            priority=1000) 

    logging.info("Inserting Brdige flow vlan %d, mac %s", vlanid, dst_mac)
    ctrl.message_send(request)

    if send_barrier:
        do_barrier(ctrl)            