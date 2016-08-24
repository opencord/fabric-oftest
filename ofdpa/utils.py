import Queue

from oftest.testutils import *
from accton_util import *

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