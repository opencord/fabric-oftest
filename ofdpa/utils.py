import Queue

from oftest.testutils import *
from accton_util import *

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
        add_one_vlan_table_flow( controller, in_port, port_to_in_vlan[in_port], flag=VLAN_TABLE_FLAG_ONLY_TAG )
        if not is_ingress_tagged:
            add_one_vlan_table_flow( controller, in_port, port_to_in_vlan[in_port], flag=VLAN_TABLE_FLAG_ONLY_UNTAG )
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
        add_one_vlan_table_flow( controller, port, port_to_in_vlan[port], flag=VLAN_TABLE_FLAG_ONLY_TAG )

    return (
        port_to_in_vlan,
        port_to_out_vlan,
        port_to_src_mac_str,
        port_to_dst_mac_str,
        port_to_src_ip_str,
        port_to_intf_src_mac_str,
        Groups
        )