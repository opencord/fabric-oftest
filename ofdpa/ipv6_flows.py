
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


"""
Check README file
"""
import Queue

import itertools
from oftest import config
import inspect
import logging
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *
from utils import *
import time

class PacketInICMPv6( base_tests.SimpleDataPlane ):
    """
    Verify ACL rule for ICMPv6 packet. The expected behavior is
    Packet-In message in the control plane.
    """

    def runTest( self ):
        try:
            # We insert an ACL rule for ICMPv6
            add_acl_rule(
                self.controller,
                eth_type=0x86dd,
                ip_proto=0x3A,
                send_barrier=False
                )

            ports = config[ "port_map" ].keys( )
            for in_port in ports:
                # Neighbor solicitation
                parsed_icmpv6_pkt = simple_icmpv6_packet(icmp_type=135)
                icmpv6_pkt = str( parsed_icmpv6_pkt )
                self.dataplane.send(in_port, icmpv6_pkt)
                verify_packet_in(self, icmpv6_pkt, in_port, ofp.OFPR_ACTION)
                verify_no_other_packets( self )
                # Neighbor advertisement
                parsed_icmpv6_pkt = simple_icmpv6_packet(icmp_type=136)
                icmpv6_pkt = str( parsed_icmpv6_pkt )
                self.dataplane.send(in_port, icmpv6_pkt)
                verify_packet_in(self, icmpv6_pkt, in_port, ofp.OFPR_ACTION)
                verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

class PacketInIPv6Table( base_tests.SimpleDataPlane ):
    """
    Verify Packet-in message from IP table when controller action is used
    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    #todo verify you stop receiving after adding rule
    """

    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port         = pair[0]
                out_port        = pair[1]
                vlan_id         = in_port
                dst_mac[ 5 ]    = vlan_id
                dst_ip          = dip % in_port
                # We fill the unicast_table
                add_unicast_v6_routing_flow(
                    ctrl=self.controller,
                    eth_type=0x86dd,
                    dst_ip=dst_ip,
                    mask="ffff:ffff:ffff:ffff::",
                    action_group_id=None,
                    vrf=0,
                    send_ctrl=True,
                    send_barrier=False
                    )
                # add termination flow
                add_termination_flow(
                    ctrl=self.controller,
                    in_port=in_port,
                    eth_type=0x86dd,
                    dst_mac=dst_mac,
                    vlanid=vlan_id
                    )
                # add vlan table flow
                add_one_vlan_table_flow(
                    ctrl=self.controller,
                    of_port=in_port,
                    out_vlan_id=1,
                    vlan_id=vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_TAG
                    )

            for port in ports:
                vlan_id             = port
                dst_mac[ 5 ]        = vlan_id
                dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
                dip_str             = dip % port
                parsed_tcpv6_pkt    = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=dst_mac_str,
                    dl_vlan_enable=True,
                    vlan_vid=vlan_id,
                    ipv6_dst=dip_str,
                    ipv6_src=sip
                    )
                tcpv6_pkt = str( parsed_tcpv6_pkt )
                self.dataplane.send(port, tcpv6_pkt)
                verify_packet_in(self, tcpv6_pkt, port, ofp.OFPR_ACTION)
                verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

class _128UcastUnTagged( base_tests.SimpleDataPlane ):
    """ Verify /128 IP forwarding to L3 Interface"""

    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            Groups = Queue.LifoQueue( )
            r_dst_mac       = [ 0x00, 0x00, 0x00, 0xa2, 0x22, 0x00 ]
            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0xa2, 0x00 ]
            intf_src_mac    = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )
            vlan_id         = 4094

            in_port             = ports[0]
            out_port            = ports[1]
            r_dst_mac[5]        = in_port
            intf_src_mac[5]     = out_port
            dst_mac[5]          = out_port
            dst_ip              = dip % in_port
            dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
            r_dst_mac_str       = ':'.join( [ '%02X' % x for x in r_dst_mac ] )
            intf_src_mac_str    = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            # We create the L2 group
            l2gid, msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=vlan_id,
                is_tagged=False,
                send_barrier=True
                )
            Groups._put(l2gid)
            # We create the L3 group
            l3_msg = add_l3_unicast_group(
                ctrl=self.controller,
                port=out_port,
                vlanid=vlan_id,
                id=vlan_id,
                src_mac=intf_src_mac,
                dst_mac=dst_mac,
                send_barrier=True
                )
            Groups._put( l3_msg.group_id )
            # We fill the unicast_table
            add_unicast_v6_routing_flow(
                ctrl=self.controller,
                eth_type=0x86dd,
                dst_ip=dst_ip,
                mask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                action_group_id=l3_msg.group_id,
                vrf=0,
                send_ctrl=False,
                send_barrier=True
                )
            # add termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x86dd,
                dst_mac=r_dst_mac,
                vlanid=vlan_id,
                )
            # add filtering flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_TAG
                )
            # add assignment flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )

            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=r_dst_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            self.dataplane.send(in_port, tcpv6_pkt)
            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=dst_mac_str,
                    eth_src=intf_src_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    ipv6_hlim=63
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            verify_packet(self, tcpv6_pkt, out_port )
            verify_no_packet(self, tcpv6_pkt, in_port )
            verify_no_other_packets(self)


        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class _128ECMPVpn( base_tests.SimpleDataPlane ):
    """  Verify MPLS IP VPN Initiation from /128 rule using ECMP  """

    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            Groups = Queue.LifoQueue( )
            r_dst_mac       = [ 0x00, 0x00, 0x00, 0xa2, 0x22, 0x00 ]
            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0xa2, 0x00 ]
            intf_src_mac    = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )
            vlan_id         = 4094
            mpls_label      = 255
            label = (mpls_label, 0, 1, 63)

            in_port             = ports[0]
            out_port            = ports[1]
            r_dst_mac[5]        = in_port
            intf_src_mac[5]     = out_port
            dst_mac[5]          = out_port
            dst_ip              = dip % in_port
            dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
            r_dst_mac_str       = ':'.join( [ '%02X' % x for x in r_dst_mac ] )
            intf_src_mac_str    = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            # We create the L2 group
            l2gid, msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=vlan_id,
                is_tagged=False,
                send_barrier=True
                )
            Groups.put(l2gid)
            mpls_gid, mpls_msg = add_mpls_intf_group(
                ctrl=self.controller,
                ref_gid=l2gid,
                dst_mac=dst_mac,
                src_mac=intf_src_mac,
                vid=vlan_id,
                index=out_port,
                send_barrier=True
                )
            Groups.put( mpls_gid )
            # add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group(
                ctrl=self.controller,
                subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                index=out_port,
                ref_gid=mpls_gid,
                push_mpls_header=True,
                set_mpls_label=mpls_label,
                set_bos=1,
                cpy_ttl_outward=True,
                send_barrier=True
                )
            Groups.put( mpls_label_gid )
            # Add ECMP group
            ecmp_msg = add_l3_ecmp_group(
                ctrl=self.controller,
                id=vlan_id,
                l3_ucast_groups=[ mpls_label_gid ],
                send_barrier=True
            )
            Groups.put( ecmp_msg.group_id )
            # We fill the unicast_table
            add_unicast_v6_routing_flow(
                ctrl=self.controller,
                eth_type=0x86dd,
                dst_ip=dst_ip,
                mask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                action_group_id=ecmp_msg.group_id,
                vrf=0,
                send_ctrl=False,
                send_barrier=True
                )
            # add termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x86dd,
                dst_mac=r_dst_mac,
                vlanid=vlan_id
                )
            # add filtering flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_TAG
                )
            # add assignment flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )

            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=r_dst_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            self.dataplane.send(in_port, tcpv6_pkt)
            parsed_mplsv6_pkt = mplsv6_packet(
                    pktlen=104,
                    eth_dst=dst_mac_str,
                    eth_src=intf_src_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    ipv6_hlim=63,
                    label=[ label ]
                    )
            mplsv6_pkt = str( parsed_mplsv6_pkt )
            verify_packet(self, mplsv6_pkt, out_port )
            verify_no_packet(self, mplsv6_pkt, in_port )
            verify_no_other_packets(self)

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class _128ECMPL3( base_tests.SimpleDataPlane ):
    """ Verifies /128 IP routing and ECMP """

    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            Groups = Queue.LifoQueue( )
            r_dst_mac       = [ 0x00, 0x00, 0x00, 0xa2, 0x22, 0x00 ]
            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0xa2, 0x00 ]
            intf_src_mac    = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )
            vlan_id         = 4094

            in_port             = ports[0]
            out_port            = ports[1]
            r_dst_mac[5]        = in_port
            intf_src_mac[5]     = out_port
            dst_mac[5]          = out_port
            dst_ip              = dip % in_port
            dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
            r_dst_mac_str       = ':'.join( [ '%02X' % x for x in r_dst_mac ] )
            intf_src_mac_str    = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            # We create the L2 group
            l2gid, msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=vlan_id,
                is_tagged=False,
                send_barrier=True
                )
            Groups.put(l2gid)
            # We create the L3 group
            l3_msg = add_l3_unicast_group(
                ctrl=self.controller,
                port=out_port,
                vlanid=vlan_id,
                id=vlan_id,
                src_mac=intf_src_mac,
                dst_mac=dst_mac,
                send_barrier=True
                )
            Groups.put( l3_msg.group_id )
            # Add ECMP group
            ecmp_msg = add_l3_ecmp_group(
                ctrl=self.controller,
                id=vlan_id,
                l3_ucast_groups=[ l3_msg.group_id ],
                send_barrier=True
            )
            Groups.put( ecmp_msg.group_id )
            # We fill the unicast_table
            add_unicast_v6_routing_flow(
                ctrl=self.controller,
                eth_type=0x86dd,
                dst_ip=dst_ip,
                mask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                action_group_id=ecmp_msg.group_id,
                vrf=0,
                send_ctrl=False,
                send_barrier=True
                )
            # add termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x86dd,
                dst_mac=r_dst_mac,
                vlanid=vlan_id
                )
            # add filtering flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_TAG
                )
            # add assignment flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )

            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=r_dst_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            self.dataplane.send(in_port, tcpv6_pkt)
            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=dst_mac_str,
                    eth_src=intf_src_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    ipv6_hlim=63
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            verify_packet(self, tcpv6_pkt, out_port )
            verify_no_packet(self, tcpv6_pkt, in_port )
            verify_no_other_packets(self)

        finally:
            print "END"
            #delete_all_flows( self.controller )
            #delete_groups( self.controller, Groups )
            #delete_all_groups( self.controller )

class _64UcastUntagged( base_tests.SimpleDataPlane ):
    """ Verify /64 IP forwarding to L3 Interface"""

    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            Groups = Queue.LifoQueue( )
            r_dst_mac       = [ 0x00, 0x00, 0x00, 0xa2, 0x22, 0x00 ]
            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0xa2, 0x00 ]
            intf_src_mac    = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )
            vlan_id         = 4094

            in_port             = ports[0]
            out_port            = ports[1]
            r_dst_mac[5]        = in_port
            intf_src_mac[5]     = out_port
            dst_mac[5]          = out_port
            dst_ip              = dip % in_port
            dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
            r_dst_mac_str       = ':'.join( [ '%02X' % x for x in r_dst_mac ] )
            intf_src_mac_str    = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            # We create the L2 group
            l2gid, msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=vlan_id,
                is_tagged=False,
                send_barrier=True
                )
            Groups._put(l2gid)
            # We create the L3 group
            l3_msg = add_l3_unicast_group(
                ctrl=self.controller,
                port=out_port,
                vlanid=vlan_id,
                id=vlan_id,
                src_mac=intf_src_mac,
                dst_mac=dst_mac,
                send_barrier=True
                )
            Groups._put( l3_msg.group_id )
            # We fill the unicast_table
            add_unicast_v6_routing_flow(
                ctrl=self.controller,
                eth_type=0x86dd,
                dst_ip=dst_ip,
                mask="ffff:ffff:ffff:ffff::",
                action_group_id=l3_msg.group_id,
                vrf=0,
                send_ctrl=False,
                send_barrier=True
                )
            # add termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x86dd,
                dst_mac=r_dst_mac,
                vlanid=vlan_id,
                )
            # add filtering flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_TAG
                )
            # add assignment flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )

            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=r_dst_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            self.dataplane.send(in_port, tcpv6_pkt)
            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=dst_mac_str,
                    eth_src=intf_src_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    ipv6_hlim=63
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            verify_packet(self, tcpv6_pkt, out_port )
            verify_no_packet(self, tcpv6_pkt, in_port )
            verify_no_other_packets(self)

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class _64ECMPVpn( base_tests.SimpleDataPlane ):
    """  Verify MPLS IP VPN Initiation from /64 rule using ECMP  """

    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            Groups = Queue.LifoQueue( )
            r_dst_mac       = [ 0x00, 0x00, 0x00, 0xa2, 0x22, 0x00 ]
            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0xa2, 0x00 ]
            intf_src_mac    = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )
            vlan_id         = 4094
            mpls_label      = 255
            label = (mpls_label, 0, 1, 63)

            in_port             = ports[0]
            out_port            = ports[1]
            r_dst_mac[5]        = in_port
            intf_src_mac[5]     = out_port
            dst_mac[5]          = out_port
            dst_ip              = dip % in_port
            dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
            r_dst_mac_str       = ':'.join( [ '%02X' % x for x in r_dst_mac ] )
            intf_src_mac_str    = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            # We create the L2 group
            l2gid, msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=vlan_id,
                is_tagged=False,
                send_barrier=True
                )
            Groups.put(l2gid)
            mpls_gid, mpls_msg = add_mpls_intf_group(
                ctrl=self.controller,
                ref_gid=l2gid,
                dst_mac=dst_mac,
                src_mac=intf_src_mac,
                vid=vlan_id,
                index=out_port,
                send_barrier=True
                )
            Groups.put( mpls_gid )
            # add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group(
                ctrl=self.controller,
                subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                index=out_port,
                ref_gid=mpls_gid,
                push_mpls_header=True,
                set_mpls_label=mpls_label,
                set_bos=1,
                cpy_ttl_outward=True,
                send_barrier=True
                )
            Groups.put( mpls_label_gid )
            # Add ECMP group
            ecmp_msg = add_l3_ecmp_group(
                ctrl=self.controller,
                id=vlan_id,
                l3_ucast_groups=[ mpls_label_gid ],
                send_barrier=True
            )
            Groups.put( ecmp_msg.group_id )
            # We fill the unicast_table
            add_unicast_v6_routing_flow(
                ctrl=self.controller,
                eth_type=0x86dd,
                dst_ip=dst_ip,
                mask="ffff:ffff:ffff:ffff::",
                action_group_id=ecmp_msg.group_id,
                vrf=0,
                send_ctrl=False,
                send_barrier=True
                )
            # add termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x86dd,
                dst_mac=r_dst_mac,
                vlanid=vlan_id
                )
            # add filtering flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_TAG
                )
            # add assignment flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )

            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=r_dst_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            self.dataplane.send(in_port, tcpv6_pkt)
            parsed_mplsv6_pkt = mplsv6_packet(
                    pktlen=104,
                    eth_dst=dst_mac_str,
                    eth_src=intf_src_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    ipv6_hlim=63,
                    label=[ label ]
                    )
            mplsv6_pkt = str( parsed_mplsv6_pkt )
            verify_packet(self, mplsv6_pkt, out_port )
            verify_no_packet(self, mplsv6_pkt, in_port )
            verify_no_other_packets(self)

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class _64ECMPL3( base_tests.SimpleDataPlane ):
    """ Verifies /64 IP routing and ECMP """


    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            Groups = Queue.LifoQueue( )
            r_dst_mac       = [ 0x00, 0x00, 0x00, 0xa2, 0x22, 0x00 ]
            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0xa2, 0x00 ]
            intf_src_mac    = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )
            vlan_id         = 4094

            in_port             = ports[0]
            out_port            = ports[1]
            r_dst_mac[5]        = in_port
            intf_src_mac[5]     = out_port
            dst_mac[5]          = out_port
            dst_ip              = dip % in_port
            dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
            r_dst_mac_str       = ':'.join( [ '%02X' % x for x in r_dst_mac ] )
            intf_src_mac_str    = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            # We create the L2 group
            l2gid, msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=vlan_id,
                is_tagged=False,
                send_barrier=True
                )
            Groups.put(l2gid)
            # We create the L3 group
            l3_msg = add_l3_unicast_group(
                ctrl=self.controller,
                port=out_port,
                vlanid=vlan_id,
                id=vlan_id,
                src_mac=intf_src_mac,
                dst_mac=dst_mac,
                send_barrier=True
                )
            Groups.put( l3_msg.group_id )
            # Add ECMP group
            ecmp_msg = add_l3_ecmp_group(
                ctrl=self.controller,
                id=vlan_id,
                l3_ucast_groups=[ l3_msg.group_id ],
                send_barrier=True
            )
            Groups.put( ecmp_msg.group_id )
            # We fill the unicast_table
            add_unicast_v6_routing_flow(
                ctrl=self.controller,
                eth_type=0x86dd,
                dst_ip=dst_ip,
                mask="ffff:ffff:ffff:ffff::",
                action_group_id=ecmp_msg.group_id,
                vrf=0,
                send_ctrl=False,
                send_barrier=True
                )
            # add termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x86dd,
                dst_mac=r_dst_mac,
                vlanid=vlan_id
                )
            # add filtering flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                out_vlan_id=1,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_TAG
                )
            # add assignment flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                out_vlan_id=1,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )

            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=r_dst_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            self.dataplane.send(in_port, tcpv6_pkt)
            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=dst_mac_str,
                    eth_src=intf_src_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    ipv6_hlim=63
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            verify_packet(self, tcpv6_pkt, out_port )
            verify_no_packet(self, tcpv6_pkt, in_port )
            verify_no_other_packets(self)

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class _0UcastV6( base_tests.SimpleDataPlane ):
    """  Verify default gateway IP forwarding to L3 Interface ( /0 rule ) """

    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            Groups = Queue.LifoQueue( )
            r_dst_mac       = [ 0x00, 0x00, 0x00, 0xa2, 0x22, 0x00 ]
            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0xa2, 0x00 ]
            intf_src_mac    = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )
            vlan_id         = 4094

            in_port             = ports[0]
            out_port            = ports[1]
            r_dst_mac[5]        = in_port
            intf_src_mac[5]     = out_port
            dst_mac[5]          = out_port
            dst_ip              = dip % in_port
            dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
            r_dst_mac_str       = ':'.join( [ '%02X' % x for x in r_dst_mac ] )
            intf_src_mac_str    = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            # We create the L2 group
            l2gid, msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=vlan_id,
                is_tagged=False,
                send_barrier=True
                )
            Groups._put(l2gid)
            # We create the L3 group
            l3_msg = add_l3_unicast_group(
                ctrl=self.controller,
                port=out_port,
                vlanid=vlan_id,
                id=vlan_id,
                src_mac=intf_src_mac,
                dst_mac=dst_mac,
                send_barrier=True
                )
            Groups._put( l3_msg.group_id )
            # We fill the unicast_table
            add_unicast_v6_routing_flow(
                ctrl=self.controller,
                eth_type=0x86dd,
                dst_ip="::",
                mask="::",
                action_group_id=l3_msg.group_id,
                vrf=0,
                send_ctrl=False,
                send_barrier=True
                )
            # add termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x86dd,
                dst_mac=r_dst_mac,
                vlanid=vlan_id,
                )
            # add filtering flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_TAG
                )
            # add assignment flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )

            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=r_dst_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            self.dataplane.send(in_port, tcpv6_pkt)
            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=dst_mac_str,
                    eth_src=intf_src_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    ipv6_hlim=63
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            verify_packet(self, tcpv6_pkt, out_port )
            verify_no_packet(self, tcpv6_pkt, in_port )
            verify_no_other_packets(self)

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class _MPLSTerminationV6( base_tests.SimpleDataPlane ):
    """ Verify MPLS termination with IPv6 traffic """

    def runTest( self ):
        try:

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            Groups = Queue.LifoQueue( )
            r_dst_mac       = [ 0x00, 0x00, 0x00, 0xa2, 0x22, 0x00 ]
            dst_mac         = [ 0x00, 0x00, 0x00, 0x22, 0xa2, 0x00 ]
            intf_src_mac    = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x00 ]
            # We are assuming that the port number are xx"
            dip             = "2000::%s"
            sip             = "2000::1"
            ports           = config[ "port_map" ].keys( )
            vlan_id         = 4094
            mpls_label      = 255
            label           = (mpls_label, 0, 1, 64)

            in_port             = ports[0]
            out_port            = ports[1]
            r_dst_mac[5]        = in_port
            intf_src_mac[5]     = out_port
            dst_mac[5]          = out_port
            dst_ip              = dip % in_port
            dst_mac_str         = ':'.join( [ '%02X' % x for x in dst_mac ] )
            r_dst_mac_str       = ':'.join( [ '%02X' % x for x in r_dst_mac ] )
            intf_src_mac_str    = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            # We create the L2 group
            l2gid, msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=vlan_id,
                is_tagged=False,
                send_barrier=True
                )
            Groups.put(l2gid)
            # We create the L3 group
            l3_msg = add_l3_unicast_group(
                ctrl=self.controller,
                port=out_port,
                vlanid=vlan_id,
                id=vlan_id,
                src_mac=intf_src_mac,
                dst_mac=dst_mac,
                send_barrier=True
                )
            Groups.put( l3_msg.group_id )
            # Add ECMP group
            ecmp_msg = add_l3_ecmp_group(
                ctrl=self.controller,
                id=vlan_id,
                l3_ucast_groups=[ l3_msg.group_id ],
                send_barrier=True
            )
            Groups.put( ecmp_msg.group_id )
            # add filtering flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_TAG
                )
            # add assignment flow
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=vlan_id,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )
            # add termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x8847,
                dst_mac=r_dst_mac,
                vlanid=vlan_id,
                goto_table=24
                )
            # We fill the mpls flow table 1
            add_mpls_flow(
                ctrl=self.controller,
                action_group_id=ecmp_msg.group_id,
                label=mpls_label,
                send_barrier=True
                )

            parsed_mplsv6_pkt = mplsv6_packet(
                    pktlen=104,
                    eth_dst=r_dst_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    label=[ label ]
                    )
            mplsv6_pkt = str( parsed_mplsv6_pkt )
            self.dataplane.send(in_port, mplsv6_pkt)
            parsed_tcpv6_pkt = simple_tcpv6_packet(
                    pktlen=100,
                    eth_dst=dst_mac_str,
                    eth_src=intf_src_mac_str,
                    ipv6_dst=dst_ip,
                    ipv6_src=sip,
                    ipv6_hlim=63
                    )
            tcpv6_pkt = str( parsed_tcpv6_pkt )
            verify_packet(self, tcpv6_pkt, out_port )
            verify_no_packet(self, tcpv6_pkt, in_port )
            verify_no_other_packets(self)

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )