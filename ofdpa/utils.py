
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import Queue
import itertools

from oftest.testutils import *
from accton_util import *

"""
MISC
"""

def print_port_stats(test, port):
    entries = get_port_stats(test, port)
    for item in entries:
        packet_rcv          = item.rx_packets
        packet_rcv_dropped  = item.rx_dropped
        packet_rcv_errors   = item.rx_errors

        packet_sent         = item.tx_packets
        packet_sent_dropped = item.tx_dropped
        packet_sent_errors  = item.tx_errors

    print "\nPort %d stats count: tx %d rx %d - tx_dropped %d rx_dropped %d - tx_errors %d rx_errors %d" % (
        port, packet_sent, packet_rcv, packet_sent_dropped, packet_rcv_dropped, packet_sent_errors, packet_rcv_errors
        )

def filter_dhcp(controller):
    match = ofp.match( )
    match.oxm_list.append( ofp.oxm.eth_type( 0x0800 ) )
    match.oxm_list.append( ofp.oxm.ip_proto( 17 ) )
    match.oxm_list.append( ofp.oxm.udp_src( 68 ) )
    match.oxm_list.append( ofp.oxm.udp_dst( 67 ))
    request = ofp.message.flow_add(
        table_id=60,
        cookie=42,
        match=match,
        instructions=[ofp.instruction.clear_actions( )],
        buffer_id=ofp.OFP_NO_BUFFER,
        priority=1
        )
    controller.message_send( request )
    do_barrier( controller )

def filter_ipv6(controller):
    match = ofp.match( )
    match.oxm_list.append( ofp.oxm.eth_type( 0x86dd ) )
    request = ofp.message.flow_add(
        table_id=60,
        cookie=42,
        match=match,
        instructions=[ofp.instruction.clear_actions( )],
        buffer_id=ofp.OFP_NO_BUFFER,
        priority=1
        )
    controller.message_send( request )
    do_barrier( controller )

def filter_igmp(controller):
    match = ofp.match( )
    match.oxm_list.append( ofp.oxm.eth_type( 0x0800 ) )
    match.oxm_list.append( ofp.oxm.ip_proto( 2 ) )
    request = ofp.message.flow_add(
        table_id=60,
        cookie=42,
        match=match,
        instructions=[ofp.instruction.clear_actions( )],
        buffer_id=ofp.OFP_NO_BUFFER,
        priority=1
        )
    controller.message_send( request )
    do_barrier( controller )

"""
MULTICAST Pipelines
"""

def fill_mcast_pipeline_L3toL2(
    controller,
    logging,
    ports,
    is_ingress_tagged,
    is_egress_tagged,
    is_vlan_translated,
    is_max_vlan
    ):
    """
    This method, according to the scenario, fills properly
    the pipeline. The method generates using ports data the
    necessary information to fill the multicast pipeline and
    fills properly the pipeline which consists in this scenario:

    i) to create l2 interface groups;
    ii) to create l3 multicast groups;
    iii) to add multicast flows;
    iv) to add termination; flows;
    v) to add vlan flows

    Scenarios:
    1) ingress untagged, egress untagged
    2) ingress untagged, egress tagged
    3) ingress tagged, egress untagged
    4) ingress tagged, egress tagged, no translation
    5) ingress tagged, egress tagged, translation
    """

    MAX_INTERNAL_VLAN           = 4094
    # Used for no translation
    FIXED_VLAN                  = 300
    Groups                      = Queue.LifoQueue( )
    L2_Groups                   = []
    port_to_in_vlan             = {}
    port_to_out_vlan            = {}
    port_to_src_mac             = {}
    port_to_src_mac_str         = {}
    port_to_dst_mac             = {}
    port_to_dst_mac_str         = {}
    port_to_src_ip              = {}
    port_to_src_ip_str          = {}
    src_ip_0                    = 0xc0a80100
    src_ip_0_str                = "192.168.1.%s"
    dst_ip                      = 0xe0000001
    switch_mac                  = [ 0x01, 0x00, 0x5e, 0x00, 0x00, 0x00 ]

    for port in ports:
        in_vlan_id  = port + 1
        out_vlan_id = MAX_INTERNAL_VLAN - port
        if is_max_vlan and not is_vlan_translated:
            in_vlan_id  = MAX_INTERNAL_VLAN
            out_vlan_id = MAX_INTERNAL_VLAN
        elif not is_max_vlan and not is_vlan_translated:
            in_vlan_id  = FIXED_VLAN
            out_vlan_id = FIXED_VLAN
        src_mac                     = [ 0x00, 0x11, 0x11, 0x11, 0x11, port ]
        src_mac_str                 = ':'.join( [ '%02X' % x for x in src_mac ] )
        dst_mac                     = [ 0x01, 0x00, 0x5e, 0x01, 0x01, port ]
        dst_mac_str                 = ':'.join( [ '%02X' % x for x in dst_mac ] )
        src_ip                      = src_ip_0 + port
        src_ip_str                  = src_ip_0_str % port
        port_to_in_vlan[port]       = in_vlan_id
        port_to_out_vlan[port]      = out_vlan_id
        port_to_src_mac[port]       = src_mac
        port_to_src_mac_str[port]   = src_mac_str
        port_to_dst_mac[port]       = dst_mac
        port_to_dst_mac_str[port]   = dst_mac_str
        port_to_src_ip[port]        = src_ip
        port_to_src_ip_str[port]    = src_ip_str

    for in_port in ports:

        L2_Groups = []
        # add vlan flows table
        add_one_vlan_table_flow( controller, in_port, 1, port_to_in_vlan[in_port], flag=VLAN_TABLE_FLAG_ONLY_TAG )
        if not is_ingress_tagged:
            add_one_vlan_table_flow( controller, in_port, 1, port_to_in_vlan[in_port], flag=VLAN_TABLE_FLAG_ONLY_UNTAG )
        elif is_vlan_translated:
            add_one_vlan_table_flow_translation( controller, in_port, port_to_in_vlan[in_port], port_to_out_vlan[in_port], flag=VLAN_TABLE_FLAG_ONLY_TAG)
        # add termination flow
        if not is_vlan_translated:
            add_termination_flow( controller, in_port, 0x0800, switch_mac, port_to_in_vlan[in_port] )
        else:
            add_termination_flow( controller, in_port, 0x0800, switch_mac, port_to_out_vlan[in_port] )

        for out_port in ports:
            if out_port == in_port:
                continue
            # add l2 interface group, vlan_id equals for each port and must coincide with mcast_group vlan_id
            if not is_vlan_translated:
                l2gid, msg = add_one_l2_interface_group( controller, out_port, vlan_id=port_to_in_vlan[in_port],
                is_tagged=is_egress_tagged, send_barrier=True )
            else:
                l2gid, msg = add_one_l2_interface_group( controller, out_port, vlan_id=port_to_out_vlan[in_port],
                is_tagged=is_egress_tagged, send_barrier=True )
            Groups._put( l2gid )
            L2_Groups.append( l2gid )

        # add l3 mcast group
        if not is_vlan_translated:
            mcat_group_msg = add_l3_mcast_group( controller, port_to_in_vlan[in_port], in_port, L2_Groups )
        else:
            mcat_group_msg = add_l3_mcast_group( controller, port_to_out_vlan[in_port], in_port, L2_Groups )
        Groups._put( mcat_group_msg.group_id )
        # add mcast routing flow
        if not is_vlan_translated:
            add_mcast4_routing_flow( controller, port_to_in_vlan[in_port], port_to_src_ip[in_port], 0, dst_ip, mcat_group_msg.group_id )
        else:
            add_mcast4_routing_flow( controller, port_to_out_vlan[in_port], port_to_src_ip[in_port], 0, dst_ip, mcat_group_msg.group_id )

    return (
        port_to_in_vlan,
        port_to_out_vlan,
        port_to_src_mac_str,
        port_to_dst_mac_str,
        port_to_src_ip_str,
        Groups
        )

def fill_mcast_pipeline_L3toL3(
    controller,
    logging,
    ports,
    is_ingress_tagged,
    is_egress_tagged,
    is_vlan_translated,
    is_max_vlan
    ):
    """
    This method, according to the scenario, fills properly
    the pipeline. The method generates using ports data the
    necessary information to fill the multicast pipeline and
    fills properly the pipeline which consists in this scenario:

    i) to create l2 interface groups;
    ii)to create l3 interface groups;
    iii) to create l3 multicast groups;
    iv) to add multicast flows;
    v) to add termination; flows;
    vi) to add vlan flows

    Scenarios:
    1) ingress tagged, egress tagged, translation
    """

    Groups                      = Queue.LifoQueue( )
    MAX_INTERNAL_VLAN           = 4094
    port_to_in_vlan             = {}
    port_to_out_vlan            = {}
    port_to_src_mac             = {}
    port_to_src_mac_str         = {}
    port_to_dst_mac             = {}
    port_to_dst_mac_str         = {}
    port_to_src_ip              = {}
    port_to_src_ip_str          = {}
    port_to_intf_src_mac        = {}
    port_to_intf_src_mac_str    = {}
    src_ip_0                    = 0xc0a80100
    src_ip_0_str                = "192.168.1.%s"
    dst_ip                      = 0xe0000001
    switch_mac                  = [ 0x01, 0x00, 0x5e, 0x00, 0x00, 0x00 ]

    for port in ports:
        in_vlan_id                     = port + 1
        out_vlan_id                    = MAX_INTERNAL_VLAN - port
        src_mac                        = [ 0x00, 0x11, 0x11, 0x11, 0x11, port ]
        src_mac_str                    = ':'.join( [ '%02X' % x for x in src_mac ] )
        dst_mac                        = [ 0x01, 0x00, 0x5e, 0x01, 0x01, port ]
        dst_mac_str                    = ':'.join( [ '%02X' % x for x in dst_mac ] )
        src_ip                         = src_ip_0 + port
        src_ip_str                     = src_ip_0_str % port
        intf_src_mac                   = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, port ]
        intf_src_mac_str               = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
        port_to_in_vlan[port]          = in_vlan_id
        port_to_out_vlan[port]         = out_vlan_id
        port_to_src_mac[port]          = src_mac
        port_to_src_mac_str[port]      = src_mac_str
        port_to_dst_mac[port]          = dst_mac
        port_to_dst_mac_str[port]      = dst_mac_str
        port_to_src_ip[port]           = src_ip
        port_to_src_ip_str[port]       = src_ip_str
        port_to_intf_src_mac[port]     = intf_src_mac
        port_to_intf_src_mac_str[port] = intf_src_mac_str

    for port in ports:
        L3_Groups = []
        for other_port in ports:
            # add l2 interface group
            l2gid, msg = add_one_l2_interface_group( controller, other_port, vlan_id=port_to_out_vlan[other_port],
            is_tagged=True, send_barrier=False )
            Groups._put( l2gid )
            # add l3 interface group
            l3group_ucast_msg = add_l3_interface_group( controller, other_port, port_to_out_vlan[other_port], port_to_in_vlan[other_port],
            port_to_intf_src_mac[other_port] )
            L3_Groups.append(l3group_ucast_msg.group_id)
            Groups._put( l3group_ucast_msg.group_id )

        # add mcast group
        mcat_group_msg = add_l3_mcast_group( controller, port_to_in_vlan[port], port_to_in_vlan[port], L3_Groups )
        Groups._put( mcat_group_msg.group_id )
        # add mcast flow
        add_mcast4_routing_flow( controller, port_to_in_vlan[port], port_to_src_ip[port], 0, dst_ip, mcat_group_msg.group_id )
        # add termination flow
        add_termination_flow( controller, port, 0x0800, switch_mac, port_to_in_vlan[port] )
        # add vlan flow table
        add_one_vlan_table_flow( controller, port, 1, port_to_in_vlan[port], flag=VLAN_TABLE_FLAG_ONLY_TAG )

    return (
        port_to_in_vlan,
        port_to_out_vlan,
        port_to_src_mac_str,
        port_to_dst_mac_str,
        port_to_src_ip_str,
        port_to_intf_src_mac_str,
        Groups
        )

"""
VPWS Pipeline
"""

OF_DPA_MPLS_L2_VPN_Label     = 1
OF_DPA_MPLS_Tunnel_Label_1   = 3
OF_DPA_MPLS_Tunnel_Label_2   = 4

EGRESS_UNTAGGED     = 1
EGRESS_TAGGED       = 2
EGRESS_TAGGED_TRANS = 3


def fill_pw_initiation_pipeline(
    controller,
    logging,
    in_port,
    out_port,
    ingress_tags,
    egress_tag,
    mpls_labels
    ):
    """
    This method, according to the scenario, fills properly
    the pw pipeline. The method generates using ports data the
    necessary information to fill the pw pipeline and
    fills properly the pipeline which consists into:

    """

    Groups                  = Queue.LifoQueue( )
    out_vlan                = 4094
    port_to_in_vlan_1       = {}
    port_to_in_vlan_2       = {}
    port_to_in_vlan_3       = {}
    port_to_src_mac         = {}
    port_to_src_mac_str     = {}
    port_to_dst_mac         = {}
    port_to_dst_mac_str     = {}
    port_to_mpls_label_1    = {}
    port_to_mpls_label_2    = {}
    port_to_mpls_label_pw   = {}
    ports                   = [in_port, out_port]

    for port in ports:
        in_vlan_id_1                = port + 1
        in_vlan_id_2                = port + 100
        in_vlan_id_3                = port + 300
        mpls_label_1                = port + 100
        mpls_label_2                = port + 200
        mpls_label_pw               = port + 300
        port_to_in_vlan_1[port]     = in_vlan_id_1
        port_to_in_vlan_2[port]     = in_vlan_id_2
        port_to_in_vlan_3[port]     = in_vlan_id_3
        src_mac                     = [ 0x00, 0x00, 0x00, 0x00, 0x11, port ]
        src_mac_str                 = ':'.join( [ '%02X' % x for x in src_mac ] )
        dst_mac                     = [ 0x00, 0x00, 0x00, 0x11, 0x11, port ]
        dst_mac_str                 = ':'.join( [ '%02X' % x for x in dst_mac ] )
        port_to_src_mac[port]       = src_mac
        port_to_src_mac_str[port]   = src_mac_str
        port_to_dst_mac[port]       = dst_mac
        port_to_dst_mac_str[port]   = dst_mac_str
        port_to_mpls_label_1[port]  = mpls_label_1
        port_to_mpls_label_2[port]  = mpls_label_2
        port_to_mpls_label_pw[port] = mpls_label_pw

    # add l2 interface group, we have to pop the VLAN;
    l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(
        ctrl=controller,
        port=out_port,
        vlan_id=out_vlan,
        is_tagged=False,
        send_barrier=False
        )
    Groups._put( l2_intf_gid )
    # add MPLS interface group
    mpls_intf_gid, mpls_intf_msg = add_mpls_intf_group(
        ctrl=controller,
        ref_gid=l2_intf_gid,
        dst_mac=port_to_dst_mac[in_port],
        src_mac=port_to_src_mac[out_port],
        vid=out_vlan,
        index=in_port
        )
    Groups._put( mpls_intf_gid )
    mpls_gid = mpls_intf_gid
    # add MPLS tunnel label groups, the number depends on the labels
    if mpls_labels == 2:
        mpls_tunnel_gid, mpls_tunnel_msg = add_mpls_tunnel_label_group(
        ctrl=controller,
        ref_gid=mpls_intf_gid,
        subtype=OF_DPA_MPLS_Tunnel_Label_2,
        index=in_port,
        label=port_to_mpls_label_2[in_port]
        )
        Groups._put( mpls_tunnel_gid )
        mpls_tunnel_gid, mpls_tunnel_msg = add_mpls_tunnel_label_group(
            ctrl=controller,
            ref_gid=mpls_tunnel_gid,
            subtype=OF_DPA_MPLS_Tunnel_Label_1,
            index=in_port,
            label=port_to_mpls_label_1[in_port]
            )
        Groups._put( mpls_tunnel_gid )
        mpls_gid = mpls_tunnel_gid
    elif mpls_labels == 1:
        mpls_tunnel_gid, mpls_tunnel_msg = add_mpls_tunnel_label_group(
            ctrl=controller,
            ref_gid=mpls_intf_gid,
            subtype=OF_DPA_MPLS_Tunnel_Label_1,
            index=in_port,
            label=port_to_mpls_label_1[in_port]
            )
        Groups._put( mpls_tunnel_gid )
        mpls_gid = mpls_tunnel_gid
    # add MPLS L2 VPN group
    mpls_l2_vpn_gid, mpls_l2_vpn_msg = add_mpls_label_group(
        ctrl=controller,
        subtype=OF_DPA_MPLS_L2_VPN_Label,
        index=in_port,
        ref_gid=mpls_gid,
        push_l2_header=True,
        push_vlan=True,
        push_mpls_header=True,
        push_cw=True,
        set_mpls_label=port_to_mpls_label_pw[in_port],
        set_bos=1,
        cpy_ttl_outward=True
    )
    Groups._put( mpls_l2_vpn_gid )
    # add MPLS L2 port flow
    add_mpls_l2_port_flow(
        ctrl=controller,
        of_port=in_port,
        mpls_l2_port=in_port,
        tunnel_index=1,
        ref_gid=mpls_l2_vpn_gid
        )
    # add VLAN flows table
    if ingress_tags == 2:
        if egress_tag == EGRESS_TAGGED:
            add_one_vlan_1_table_flow_pw(
                ctrl=controller,
                of_port=in_port,
                tunnel_index=1,
                new_outer_vlan_id=-1,
                outer_vlan_id=port_to_in_vlan_2[in_port],
                inner_vlan_id=port_to_in_vlan_1[in_port],
                )
        elif egress_tag == EGRESS_TAGGED_TRANS:
            add_one_vlan_1_table_flow_pw(
                ctrl=controller,
                of_port=in_port,
                tunnel_index=1,
                new_outer_vlan_id=port_to_in_vlan_3[in_port],
                outer_vlan_id=port_to_in_vlan_2[in_port],
                inner_vlan_id=port_to_in_vlan_1[in_port],
                )
        add_one_vlan_table_flow(
            ctrl=controller,
            of_port=in_port,
            vlan_id=port_to_in_vlan_2[in_port],
            flag=VLAN_TABLE_FLAG_ONLY_STACKED,
            )
    elif ingress_tags == 1:
        if egress_tag == EGRESS_TAGGED:
            add_one_vlan_table_flow_pw(
                ctrl=controller,
                of_port=in_port,
                tunnel_index=1,
                vlan_id=port_to_in_vlan_1[in_port],
                flag=VLAN_TABLE_FLAG_ONLY_TAG,
                )
        elif egress_tag == EGRESS_TAGGED_TRANS:
            add_one_vlan_table_flow_pw(
                ctrl=controller,
                of_port=in_port,
                tunnel_index=1,
                vlan_id=port_to_in_vlan_1[in_port],
                new_vlan_id=port_to_in_vlan_3[in_port],
                flag=VLAN_TABLE_FLAG_ONLY_TAG,
                )
    elif ingress_tags == 0:
        filter_dhcp(controller)
        filter_ipv6(controller)
        filter_igmp(controller)
        if egress_tag == EGRESS_UNTAGGED:
            add_one_vlan_table_flow_pw(
                ctrl=controller,
                of_port=in_port,
                tunnel_index=1,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG,
                )
        elif egress_tag == EGRESS_TAGGED:
            add_one_vlan_table_flow_pw(
                ctrl=controller,
                of_port=in_port,
                tunnel_index=1,
                vlan_id=port_to_in_vlan_1[in_port],
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG,
                )

    return (
        port_to_mpls_label_2,
        port_to_mpls_label_1,
        port_to_mpls_label_pw,
        port_to_in_vlan_3,
        port_to_in_vlan_2,
        port_to_in_vlan_1,
        port_to_src_mac_str,
        port_to_dst_mac_str,
        Groups
        )

MPLS_FLOW_TABLE_0           = 23
OF_DPA_MPLS_SWAP_Label      = 5

def fill_pw_intermediate_transport_pipeline(
    controller,
    logging,
    ports,
    mpls_labels
    ):
    """
    This method, according to the scenario, fills properly
    the pw pipeline. The method generates using ports data the
    necessary information to fill the pw pipeline and
    fills properly the pipeline which consists into:

    """

    Groups                  = Queue.LifoQueue( )
    out_vlan                = 4094
    port_to_src_mac         = {}
    port_to_src_mac_str     = {}
    port_to_dst_mac         = {}
    port_to_dst_mac_str     = {}
    port_to_mpls_label_2    = {}
    port_to_mpls_label_1    = {}
    port_to_mpls_label_pw   = {}
    port_to_switch_mac      = {}
    port_to_switch_mac_str  = {}

    for port in ports:
        mpls_label_1                    = port + 10
        mpls_label_2                    = port + 100
        mpls_label_pw                   = port + 300
        src_mac                         = [ 0x00, 0x00, 0x00, 0x00, 0x11, port ]
        src_mac_str                     = ':'.join( [ '%02X' % x for x in src_mac ] )
        dst_mac                         = [ 0x00, 0x00, 0x00, 0x11, 0x11, port ]
        dst_mac_str                     = ':'.join( [ '%02X' % x for x in dst_mac ] )
        switch_mac                      = [ 0x00, 0x00, 0x00, 0x00, 0x00, port ]
        switch_mac_str                  = ':'.join( [ '%02X' % x for x in switch_mac ] )
        port_to_src_mac[port]           = src_mac
        port_to_src_mac_str[port]       = src_mac_str
        port_to_dst_mac[port]           = dst_mac
        port_to_dst_mac_str[port]       = dst_mac_str
        port_to_mpls_label_1[port]      = mpls_label_1
        port_to_mpls_label_2[port]      = mpls_label_2
        port_to_mpls_label_pw[port]     = mpls_label_pw
        port_to_switch_mac[port]        = switch_mac
        port_to_switch_mac_str[port]    = switch_mac_str

    for pair in itertools.product(ports, ports):
        in_port     = pair[0]
        out_port    = pair[1]
        if out_port == in_port:
            continue
        # add l2 interface group, we have to pop the VLAN;
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(
            ctrl=controller,
            port=out_port,
            vlan_id=out_vlan,
            is_tagged=False,
            send_barrier=False
            )
        Groups._put( l2_intf_gid )
        # add MPLS interface group
        mpls_intf_gid, mpls_intf_msg = add_mpls_intf_group(
            ctrl=controller,
            ref_gid=l2_intf_gid,
            dst_mac=port_to_dst_mac[in_port],
            src_mac=port_to_src_mac[out_port],
            vid=out_vlan,
            index=in_port
            )
        Groups._put( mpls_intf_gid )
        # add MPLS flows
        if mpls_labels >=2:
            add_mpls_flow_pw(
                ctrl=controller,
                action_group_id=mpls_intf_gid,
                label=port_to_mpls_label_2[in_port],
                ethertype=0x8847,
                tunnel_index=1,
                bos=0
                )
        else:
            mpls_tunnel_gid, mpls_tunnel_msg = add_mpls_tunnel_label_group(
                ctrl=controller,
                ref_gid=mpls_intf_gid,
                subtype=OF_DPA_MPLS_Tunnel_Label_2,
                index=in_port,
                label=port_to_mpls_label_2[in_port]
                )
            Groups._put( mpls_tunnel_gid )
            mpls_tunnel_gid, mpls_tunnel_msg = add_mpls_tunnel_label_group(
                ctrl=controller,
                ref_gid=mpls_tunnel_gid,
                subtype=OF_DPA_MPLS_Tunnel_Label_1,
                index=in_port,
                label=port_to_mpls_label_1[in_port]
                )
            Groups._put( mpls_tunnel_gid )
            mpls_swap_gid, mpls_tunnel_msg = add_mpls_swap_label_group(
                ctrl=controller,
                ref_gid=mpls_tunnel_gid,
                subtype=OF_DPA_MPLS_SWAP_Label,
                index=in_port,
                label=port_to_mpls_label_pw[in_port]
                )
            Groups._put( mpls_swap_gid )
            add_mpls_flow_pw(
                ctrl=controller,
                action_group_id=mpls_swap_gid,
                label=port_to_mpls_label_pw[in_port],
                ethertype=0x8847,
                tunnel_index=1,
                bos=1,
                popMPLS=False,
                popL2=False
                )
        # add Termination flow
        add_termination_flow(
            ctrl=controller,
            in_port=in_port,
            eth_type=0x8847,
            dst_mac=port_to_switch_mac[in_port],
            vlanid=out_vlan,
            goto_table=MPLS_FLOW_TABLE_0)
        # add VLAN flows
        add_one_vlan_table_flow(
            ctrl=controller,
            of_port=in_port,
            vlan_id=out_vlan,
            flag=VLAN_TABLE_FLAG_ONLY_TAG,
            )
        add_one_vlan_table_flow(
            ctrl=controller,
            of_port=in_port,
            vlan_id=out_vlan,
            flag=VLAN_TABLE_FLAG_ONLY_UNTAG
            )

    return (
        port_to_mpls_label_2,
        port_to_mpls_label_1,
        port_to_mpls_label_pw,
        port_to_switch_mac_str,
        port_to_src_mac_str,
        port_to_dst_mac_str,
        Groups
        )

def fill_pw_termination_pipeline(
    controller,
    logging,
    in_port,
    out_port,
    egress_tags
    ):
    """
    This method, according to the scenario, fills properly
    the pw pipeline. The method generates using ports data the
    necessary information to fill the pw pipeline and
    fills properly the pipeline which consists into:

    """

    Groups                  = Queue.LifoQueue( )
    out_vlan                = 4094
    port_to_mpls_label_pw   = {}
    port_to_vlan_2          = {}
    port_to_vlan_1          = {}
    port_to_switch_mac      = {}
    port_to_switch_mac_str  = {}
    ports                   = [in_port, out_port]

    for port in ports:
        mpls_label_pw                   = port + 300
        in_vlan_id_1                    = port + 1
        in_vlan_id_2                    = port + 100
        switch_mac                      = [ 0x00, 0x00, 0x00, 0x00, 0x11, port ]
        switch_mac_str                  = ':'.join( [ '%02X' % x for x in switch_mac ] )
        port_to_mpls_label_pw[port]     = mpls_label_pw
        port_to_vlan_2[port]            = in_vlan_id_2
        port_to_vlan_1[port]            = in_vlan_id_1
        port_to_switch_mac[port]        = switch_mac
        port_to_switch_mac_str[port]    = switch_mac_str

    # add l2 interface group;
    if egress_tags == 2:
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(
            ctrl=controller,
            port=out_port,
            vlan_id=port_to_vlan_2[out_port],
            is_tagged=True,
            send_barrier=False
            )
    elif egress_tags == 1:
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(
            ctrl=controller,
            port=out_port,
            vlan_id=port_to_vlan_1[out_port],
            is_tagged=True,
            send_barrier=False
            )
    elif egress_tags == 0:
        l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(
            ctrl=controller,
            port=out_port,
            vlan_id=port_to_vlan_1[out_port],
            is_tagged=False,
            send_barrier=False
            )
    Groups._put( l2_intf_gid )
    add_mpls_flow_pw(
        ctrl=controller,
        action_group_id=l2_intf_gid,
        label=port_to_mpls_label_pw[out_port],
        ethertype=0x6558,
        bos=1,
        tunnel_index=1,
        popMPLS=True,
        popL2=True,
        of_port=in_port
        )
    # add Termination flow
    add_termination_flow(
        ctrl=controller,
        in_port=in_port,
        eth_type=0x8847,
        dst_mac=port_to_switch_mac[in_port],
        vlanid=out_vlan,
        goto_table=MPLS_FLOW_TABLE_0)
    # add VLAN flows
    add_one_vlan_table_flow(
        ctrl=controller,
        of_port=in_port,
        vlan_id=out_vlan,
        flag=VLAN_TABLE_FLAG_ONLY_TAG,
        )
    add_one_vlan_table_flow(
        ctrl=controller,
        of_port=in_port,
        vlan_id=out_vlan,
        flag=VLAN_TABLE_FLAG_ONLY_UNTAG
        )

    return (
        port_to_mpls_label_pw,
        port_to_vlan_2,
        port_to_vlan_1,
        port_to_switch_mac_str,
        Groups
        )
