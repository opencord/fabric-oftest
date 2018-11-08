
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

from oftest import config
import inspect
import logging
import oftest.base_tests as base_tests
import ofp
import time
from oftest.oft12.testutils import delete_all_flows_one_table
from oftest.testutils import *
from accton_util import *
from utils import *

class PacketInUDP( base_tests.SimpleDataPlane ):
    """
    Verify ACL rule for IP_PROTO=2 wont match a UDP packet and a rule for IP_PROTO=17 WILL match a UDP packet.
    """

    def runTest( self ):
        try:
            parsed_vlan_pkt = simple_udp_packet( pktlen=104, vlan_vid=0x1001, dl_vlan_enable=True )
            vlan_pkt = str( parsed_vlan_pkt )
            # create match
            match = ofp.match( )
            match.oxm_list.append( ofp.oxm.eth_type( 0x0800 ) )
            match.oxm_list.append( ofp.oxm.ip_proto( 2 ) )
            request = ofp.message.flow_add( table_id=60, cookie=42, match=match, instructions=[
                ofp.instruction.apply_actions( actions=[
                    ofp.action.output( port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER ) ] ), ],
                    buffer_id=ofp.OFP_NO_BUFFER, priority=1 )
            logging.info( "Inserting packet in flow to controller" )
            self.controller.message_send( request )

            for of_port in config[ "port_map" ].keys( ):
                logging.info( "PacketInMiss test, port %d", of_port )
                self.dataplane.send( of_port, vlan_pkt )

                verify_no_packet_in( self, vlan_pkt, of_port )
            delete_all_flows( self.controller )
            do_barrier( self.controller )

            match = ofp.match( )
            match.oxm_list.append( ofp.oxm.eth_type( 0x0800 ) )
            match.oxm_list.append( ofp.oxm.ip_proto( 17 ) )
            request = ofp.message.flow_add( table_id=60, cookie=42, match=match, instructions=[
                ofp.instruction.apply_actions( actions=[
                    ofp.action.output( port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER ) ] ), ],
                    buffer_id=ofp.OFP_NO_BUFFER, priority=1 )
            logging.info( "Inserting packet in flow to controller" )
            self.controller.message_send( request )
            do_barrier( self.controller )

            for of_port in config[ "port_map" ].keys( ):
                logging.info( "PacketInMiss test, port %d", of_port )
                self.dataplane.send( of_port, vlan_pkt )

                verify_packet_in( self, vlan_pkt, of_port, ofp.OFPR_ACTION )

                verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )


@disabled
class ArpNL2( base_tests.SimpleDataPlane ):
    """
    Needs a description, disabled for now. Also needs try/finally
    """
    def runTest( self ):
        delete_all_flows( self.controller )
        delete_all_groups( self.controller )

        ports = sorted( config[ "port_map" ].keys( ) )
        match = ofp.match( )
        match.oxm_list.append( ofp.oxm.eth_type( 0x0806 ) )
        request = ofp.message.flow_add( table_id=60, cookie=42, match=match, instructions=[
            ofp.instruction.apply_actions( actions=[
                ofp.action.output( port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER ) ] ), ],
                buffer_id=ofp.OFP_NO_BUFFER, priority=40000 )
        self.controller.message_send( request )
        for port in ports:
            add_one_l2_interface_group( self.controller, port, 1, False, False )
            add_one_vlan_table_flow( self.controller, port, 1, flag=VLAN_TABLE_FLAG_ONLY_BOTH )
            group_id = encode_l2_interface_group_id( 1, port )
            add_bridge_flow( self.controller, [ 0x00, 0x12, 0x34, 0x56, 0x78, port ], 1, group_id, True )
        do_barrier( self.controller )
        parsed_arp_pkt = simple_arp_packet( )
        arp_pkt = str( parsed_arp_pkt )

        for out_port in ports:
            self.dataplane.send( out_port, arp_pkt )
            verify_packet_in( self, arp_pkt, out_port, ofp.OFPR_ACTION )
            # change dest based on port number
            mac_dst = '00:12:34:56:78:%02X' % out_port
            for in_port in ports:
                if in_port == out_port:
                    continue
                # change source based on port number to avoid packet-ins from learning
                mac_src = '00:12:34:56:78:%02X' % in_port
                parsed_pkt = simple_tcp_packet( eth_dst=mac_dst, eth_src=mac_src )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for ofport in ports:
                    if ofport in [ out_port ]:
                        verify_packet( self, pkt, ofport )
                    else:
                        verify_no_packet( self, pkt, ofport )

                verify_no_other_packets( self )

class PacketInArp( base_tests.SimpleDataPlane ):
    """
    Verify Packet-in message from eth_type 0x806 on ACL table
    """

    def runTest( self ):
        try:
            parsed_arp_pkt = simple_arp_packet( )
            arp_pkt = str( parsed_arp_pkt )
            # create match
            match = ofp.match( )
            match.oxm_list.append( ofp.oxm.eth_type( 0x0806 ) )
            request = ofp.message.flow_add( table_id=60, cookie=42, match=match, instructions=[
                ofp.instruction.apply_actions( actions=[
                    ofp.action.output( port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER ) ] ), ],
                    buffer_id=ofp.OFP_NO_BUFFER, priority=1 )

            logging.info( "Inserting arp flow " )
            self.controller.message_send( request )
            do_barrier( self.controller )

            for of_port in config[ "port_map" ].keys( ):
                logging.info( "PacketInArp test, sending arp packet to port %d", of_port )
                self.dataplane.send( of_port, arp_pkt )

                verify_packet_in( self, arp_pkt, of_port, ofp.OFPR_ACTION )

                verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

@disabled
class PacketInIPTable( base_tests.SimpleDataPlane ):
    """
    Verify Packet-in message from IP table when controller action is used
    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    #todo verify you stop receiving after adding rule
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = sorted( config[ "port_map" ].keys( ) )

            for port in ports:
                # add l2 interface group
                vlan_id = port
                add_one_l2_interface_group( self.controller, port, vlan_id=vlan_id, is_tagged=True,
                        send_barrier=False )
                dst_mac[ 5 ] = vlan_id
                l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id, id=vlan_id,
                        src_mac=intf_src_mac, dst_mac=dst_mac )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, vlan_id=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add unicast routing flow
                dst_ip = dip + (vlan_id << 8)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffff00, l3_msg.group_id,
                        send_ctrl=True )
                Groups.put( l3_msg.group_id )

            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                mac_src = '00:00:00:22:22:%02X' % in_port
                ip_src = '192.168.%02d.1' % in_port
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % out_port
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=in_port,
                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    verify_packet_in( self, pkt, in_port, ofp.OFPR_ACTION )
                    # verify_no_other_packets(self)
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class L2FloodQinQ( base_tests.SimpleDataPlane ):
    """
    Verify Vlan based flooding of QinQ based on its outer vlan
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            ports = sorted( config[ "port_map" ].keys( ) )
            vlan_id = 100

            for port in ports:
                L2gid, l2msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, False )
                add_one_vlan_table_flow( self.controller, port, vlan_id=vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                Groups.put( L2gid )

            msg = add_l2_flood_group( self.controller, ports, vlan_id, vlan_id )
            Groups.put( msg.group_id )
            add_bridge_flow( self.controller, None, vlan_id, msg.group_id, True )
            do_barrier( self.controller )

            # verify flood
            for ofport in ports:
                # change dest based on port number
                mac_src = '00:12:34:56:78:%02X' % ofport
                parsed_pkt = simple_tcp_packet_two_vlan( pktlen=108, out_dl_vlan_enable=True,
                        out_vlan_vid=vlan_id, in_dl_vlan_enable=True, in_vlan_vid=10,
                        eth_dst='00:12:34:56:78:9a', eth_src=mac_src )
                pkt = str( parsed_pkt )
                self.dataplane.send( ofport, pkt )
                # self won't rx packet
                verify_no_packet( self, pkt, ofport )
                # others will rx packet
                tmp_ports = list( ports )
                tmp_ports.remove( ofport )
                verify_packets( self, pkt, tmp_ports )

            verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )



@disabled
class L2FloodTagged( base_tests.SimpleDataPlane ):
    """
    currently disabled; fix with try/finally
    Test L2 flood to a vlan
    Send a packet with unknown dst_mac and check if the packet is flooded to all ports except inport
    """

    def runTest( self ):
        # Hashes Test Name and uses it as id for installing unique groups
        vlan_id = abs( hash( inspect.stack( )[ 0 ][ 3 ] ) ) % (256)
        print vlan_id

        ports = sorted( config[ "port_map" ].keys( ) )

        delete_all_flows( self.controller )
        delete_all_groups( self.controller )

        # Installing flows to avoid packet-in
        for port in ports:
            add_one_l2_interface_group( self.controller, port, vlan_id, True, False )
            add_one_vlan_table_flow( self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
        msg = add_l2_flood_group( self.controller, ports, vlan_id, vlan_id )
        add_bridge_flow( self.controller, None, vlan_id, msg.group_id, True )
        do_barrier( self.controller )

        # verify flood
        for ofport in ports:
            # change dest based on port number
            pkt = str(
                    simple_tcp_packet( dl_vlan_enable=True, vlan_vid=vlan_id, eth_dst='00:12:34:56:78:9a' ) )
            self.dataplane.send( ofport, pkt )
            # self won't rx packet
            verify_no_packet( self, pkt, ofport )
            # others will rx packet
            tmp_ports = list( ports )
            tmp_ports.remove( ofport )
            verify_packets( self, pkt, tmp_ports )
        verify_no_other_packets( self )


class L2UnicastTagged( base_tests.SimpleDataPlane ):
    """ Verify Bridging works: match(VID, DST_MAC)> fwd(port) """

    def runTest( self ):

        Groups = Queue.LifoQueue( )
        try:
            ports = sorted( config[ "port_map" ].keys( ) )
            vlan_id = 1;
            for port in ports:
                L2gid, l2msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, False )
                add_one_vlan_table_flow( self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                Groups.put( L2gid )
                add_bridge_flow( self.controller, [ 0x00, 0x12, 0x34, 0x56, 0x78, port ], vlan_id, L2gid,
                        True )
            do_barrier( self.controller )

            for out_port in ports:
                # change dest based on port number
                mac_dst = '00:12:34:56:78:%02X' % out_port
                for in_port in ports:
                    if in_port == out_port:
                        continue
                    pkt = str( simple_tcp_packet( dl_vlan_enable=True, vlan_vid=vlan_id, eth_dst=mac_dst ) )
                    self.dataplane.send( in_port, pkt )
                    for ofport in ports:
                        if ofport in [ out_port ]:
                            verify_packet( self, pkt, ofport )
                        else:
                            verify_no_packet( self, pkt, ofport )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class Bridging( base_tests.SimpleDataPlane ):
    """
    Verify bridging works including flooding with different vlans
    ports[0] has vlan 31 untagged
    ports[1] has vlan 31 untagged (native) and vlan 41 tagged
    ARP request should be flooded
    ARP reply should be forwarded by bridging rule
    Both arp messages should also be copied to controller
    """

    def runTest( self ):
        Groupd = Queue.LifoQueue()
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return
            ports = sorted( config[ "port_map" ].keys() )
            vlan_p0_untagged = 31
            vlan_p1_tagged = 31
            vlan_p1_native = 41

            #l2 interface groups and table 10 flows
            L2p0gid, l2msg0 = add_one_l2_interface_group( self.controller, ports[0], vlan_p0_untagged,
                                                          is_tagged=False, send_barrier=False )
            add_one_vlan_table_flow( self.controller, ports[0], vlan_id=vlan_p0_untagged, flag=VLAN_TABLE_FLAG_ONLY_BOTH,
                                     send_barrier=True)
            L2p1gid, l2msg1 = add_one_l2_interface_group( self.controller, ports[1], vlan_p1_tagged,
                                                          is_tagged=True, send_barrier=False )
            add_one_vlan_table_flow( self.controller, ports[1], vlan_id=vlan_p1_tagged, flag=VLAN_TABLE_FLAG_ONLY_TAG,
                                     send_barrier=True)
            L2p1gid2, l2msg3 = add_one_l2_interface_group( self.controller, ports[1], vlan_p1_native,
                                                          is_tagged=False, send_barrier=False )
            add_one_vlan_table_flow( self.controller, ports[1], vlan_id=vlan_p1_native, flag=VLAN_TABLE_FLAG_ONLY_BOTH,
                                     send_barrier=True)
            #flooding groups
            Floodmsg31 = add_l2_flood_group( self.controller, ports, vlan_p0_untagged, id=0 )
            Floodmsg41 = add_l2_flood_group( self.controller, [ ports[1] ], vlan_p1_native, id=0 )

            #add bridging flows for flooding groups
            add_bridge_flow( self.controller, dst_mac=None, vlanid=vlan_p0_untagged, group_id=Floodmsg31.group_id )
            add_bridge_flow( self.controller, dst_mac=None, vlanid=vlan_p1_native, group_id=Floodmsg41.group_id )
            do_barrier( self.controller )

            # add bridging flows for dstMac+vlan
            add_bridge_flow( self.controller, [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 ], vlan_p0_untagged, L2p0gid, True )
            add_bridge_flow( self.controller, [ 0x00, 0x66, 0x77, 0x88, 0x99, 0xaa ], vlan_p1_tagged, L2p1gid, True )
            add_bridge_flow( self.controller, [ 0x00, 0x66, 0x77, 0x88, 0x99, 0xaa ], vlan_p1_native, L2p1gid2, True )

            # add terminationMac flow
            router_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x0800, router_mac, vlan_p0_untagged )
                add_termination_flow( self.controller, 0, 0x0800, router_mac, vlan_p1_native )
            else:
                add_termination_flow( self.controller, ports[0], 0x0800, router_mac, vlan_p0_untagged )
                add_termination_flow( self.controller, ports[1], 0x0800, router_mac, vlan_p1_tagged )
                add_termination_flow( self.controller, ports[1], 0x0800, router_mac, vlan_p1_native )

            # add acl rule for arp
            match = ofp.match( )
            match.oxm_list.append( ofp.oxm.eth_type( 0x0806 ) )
            request = ofp.message.flow_add( table_id=60, cookie=42, match=match, instructions=[
                ofp.instruction.apply_actions( actions=[
                    ofp.action.output( port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER ) ] ), ],
                    buffer_id=ofp.OFP_NO_BUFFER, priority=1 )
            self.controller.message_send( request )
            do_barrier( self.controller )

            #acl rule for gateway ip
            match = ofp.match( )
            match.oxm_list.append( ofp.oxm.eth_type( 0x0800 ) )
            match.oxm_list.append( ofp.oxm.ipv4_dst( 0xc0a80003 ) )
            request = ofp.message.flow_add( table_id=60, cookie=42, match=match, instructions=[
                ofp.instruction.apply_actions( actions=[
                    ofp.action.output( port=ofp.OFPP_CONTROLLER, max_len=ofp.OFPCML_NO_BUFFER ) ] ),
                ofp.instruction.clear_actions() ],
                    buffer_id=ofp.OFP_NO_BUFFER, priority=1 )
            self.controller.message_send( request )
            do_barrier( self.controller )

            # send ARP request
            parsed_arp_pkt = simple_arp_packet(pktlen=80,
                                               eth_dst='ff:ff:ff:ff:ff:ff',
                                               eth_src='00:66:77:88:99:aa',
                                               vlan_vid=vlan_p1_tagged,
                                               vlan_pcp=0,
                                               arp_op=1,
                                               ip_snd='192.168.0.2',
                                               ip_tgt='192.168.0.1',
                                               hw_snd='00:66:77:88:99:aa',
                                               hw_tgt='00:00:00:00:00:00')
            arp_pkt_to_send = str( parsed_arp_pkt )
            logging.info( "sending arp request to port %d", ports[1] )
            self.dataplane.send( ports[1], arp_pkt_to_send )
            verify_packet_in( self, arp_pkt_to_send, ports[1], ofp.OFPR_ACTION )
            parsed_arp_pkt_untagged = simple_arp_packet(pktlen=76,
                                               eth_dst='ff:ff:ff:ff:ff:ff',
                                               eth_src='00:66:77:88:99:aa',
                                               vlan_vid=0,
                                               vlan_pcp=0,
                                               arp_op=1,
                                               ip_snd='192.168.0.2',
                                               ip_tgt='192.168.0.1',
                                               hw_snd='00:66:77:88:99:aa',
                                               hw_tgt='00:00:00:00:00:00')
            arp_pkt_dest = str( parsed_arp_pkt_untagged )
            verify_packet( self, arp_pkt_dest, ports[0] )
            #verify_no_other_packets( self )

            # send ARP reply
            parsed_arp_pkt = simple_arp_packet(pktlen=76,
                                               eth_dst='00:66:77:88:99:aa',
                                               eth_src='00:11:22:33:44:55',
                                               vlan_vid=0,
                                               vlan_pcp=0,
                                               arp_op=2,
                                               ip_snd='192.168.0.1',
                                               ip_tgt='192.168.0.2',
                                               hw_snd='00:11:22:33:44:55',
                                               hw_tgt='00:66:77:88:99:aa')
            arp_pkt_to_send = str( parsed_arp_pkt )
            logging.info( "sending arp reply to port %d", ports[0] )
            self.dataplane.send( ports[0], arp_pkt_to_send )
            verify_packet_in( self, arp_pkt_to_send, ports[0], ofp.OFPR_ACTION )
            parsed_arp_pkt_tagged = simple_arp_packet(pktlen=80,
                                               eth_dst='00:66:77:88:99:aa',
                                               eth_src='00:11:22:33:44:55',
                                               vlan_vid=vlan_p1_tagged,
                                               vlan_pcp=0,
                                               arp_op=2,
                                               ip_snd='192.168.0.1',
                                               ip_tgt='192.168.0.2',
                                               hw_snd='00:11:22:33:44:55',
                                               hw_tgt='00:66:77:88:99:aa')
            arp_pkt_dest = str( parsed_arp_pkt_tagged )
            verify_packet( self, arp_pkt_dest, ports[1] )

        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )
            #print("done")



class Mtu1500( base_tests.SimpleDataPlane ):
    """
    Verifies basic mtu limits
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            ports = sorted( config[ "port_map" ].keys( ) )
            vlan_id = 18
            for port in ports:
                L2gid, msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, False )
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                Groups.put( L2gid )
                add_bridge_flow( self.controller, [ 0x00, 0x12, 0x34, 0x56, 0x78, port ], vlan_id, L2gid,
                        True )
            do_barrier( self.controller )

            for out_port in ports:
                # change dest based on port number
                mac_dst = '00:12:34:56:78:%02X' % out_port
                for in_port in ports:
                    if in_port == out_port:
                        continue
                    pkt = str( simple_tcp_packet( pktlen=1500, dl_vlan_enable=True, vlan_vid=vlan_id,
                            eth_dst=mac_dst ) )
                    self.dataplane.send( in_port, pkt )
                    for ofport in ports:
                        if ofport in [ out_port ]:
                            verify_packet( self, pkt, ofport )
                        else:
                            verify_no_packet( self, pkt, ofport )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class _32UcastTagged( base_tests.SimpleDataPlane ):
    """ Verify /32 IP forwarding to L3 Unicast-> L2Interface"""

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            test_id = 26
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            for port in ports:
                vlan_id = port + test_id
                # add l2 interface group and l3 unicast group
                l2gid, msg = add_one_l2_interface_group( self.controller, port, vlan_id=vlan_id,
                        is_tagged=True, send_barrier=False )
                dst_mac[ 5 ] = vlan_id
                l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id, id=vlan_id,
                        src_mac=intf_src_mac, dst_mac=dst_mac )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add unicast routing flow
                dst_ip = dip + (vlan_id << 8)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffffff, l3_msg.group_id )
                Groups.put( l2gid )
                Groups.put( l3_msg.group_id )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                mac_src = '00:00:00:22:32:%02X' % (test_id + in_port)
                ip_src = '192.168.%02d.1' % (test_id + in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % (test_id + out_port)
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True,
                            vlan_vid=(test_id + in_port), eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64,
                            ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expected packet
                    mac_dst = '00:00:00:22:22:%02X' % (test_id + out_port)
                    exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True,
                            vlan_vid=(test_id + out_port), eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63,
                            ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class _32VPN( base_tests.SimpleDataPlane ):
    """
    Verify /32 routing rule -> MPLS_VPN_Label -> MPLSInterface -> L2Interface
    No ECMP group used
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # add l2 interface group
                id = port
                vlan_id = port
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, True )
                dst_mac[ 5 ] = vlan_id
                # add MPLS interface group
                mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, dst_mac, intf_src_mac,
                        vlan_id, id )
                # add MPLS L3 VPN group
                mpls_label_gid, mpls_label_msg = add_mpls_label_group( self.controller,
                        subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=id, ref_gid=mpls_gid,
                        push_mpls_header=True, set_mpls_label=port, set_bos=1, set_ttl=32 )
                do_barrier( self.controller )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, vrf=2,
                        flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add routing flow
                dst_ip = dip + (vlan_id << 8)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffffff, mpls_label_gid, vrf=2 )
                Groups._put( l2_gid )
                Groups._put( mpls_gid )
                Groups._put( mpls_label_gid )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                ip_src = '192.168.%02d.1' % (in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % (out_port)
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(in_port),
                            eth_dst=switch_mac, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expect packet
                    mac_dst = '00:00:00:22:22:%02X' % (out_port)
                    label = (out_port, 0, 1, 32)
                    exp_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(out_port), ip_ttl=63,
                            ip_src=ip_src, ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac,
                            label=[ label ] )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class _32EcmpVpn( base_tests.SimpleDataPlane ):
    """
    Verify /32 routing rule -> L3 ECMP -> MPLS_VPN_Label -> MPLSInterface -> L2Interface
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # add l2 interface group
                id = port
                vlan_id = port
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, True )
                dst_mac[ 5 ] = vlan_id
                # add MPLS interface group
                mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, dst_mac, intf_src_mac,
                        vlan_id, id )
                # add MPLS L3 VPN group
                mpls_label_gid, mpls_label_msg = add_mpls_label_group( self.controller,
                        subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=id, ref_gid=mpls_gid,
                        push_mpls_header=True, set_mpls_label=port, set_bos=1, set_ttl=32 )
                ecmp_msg = add_l3_ecmp_group( self.controller, vlan_id, [ mpls_label_gid ] )
                do_barrier( self.controller )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, vrf=0,
                        flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add routing flow
                dst_ip = dip + (vlan_id << 8)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffffff, ecmp_msg.group_id )
                Groups._put( l2_gid )
                Groups._put( mpls_gid )
                Groups._put( mpls_label_gid )
                Groups._put( ecmp_msg.group_id )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                ip_src = '192.168.%02d.1' % (in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % (out_port)
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(in_port),
                            eth_dst=switch_mac, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expect packet
                    mac_dst = '00:00:00:22:22:%02X' % (out_port)
                    label = (out_port, 0, 1, 32)
                    exp_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(out_port), ip_ttl=63,
                            ip_src=ip_src, ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac,
                            label=[ label ] )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


@disabled
class One_32EcmpVpn( base_tests.SimpleDataPlane ):
    """
    Verify /32 routing rule -> L3 ECMP -> MPLS_VPN_Label -> MPLSInterface -> L2Interface
    in only one direction
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            # add l2 interface group
            id = ports[1]
            in_offset = 19
            out_offset = 20
            vlan_id = ports[1] + out_offset
            l2_gid, l2_msg = add_one_l2_interface_group( self.controller, ports[1], vlan_id, True, True )
            dst_mac[ 5 ] = ports[1]
            # add MPLS interface group
            mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, dst_mac, intf_src_mac,
                                                      vlan_id, id )
            # add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group( self.controller,
                        subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=id, ref_gid=mpls_gid,
                        push_mpls_header=True, set_mpls_label=ports[1] + out_offset, set_bos=1, set_ttl=32 )
            # add ECMP group
            ecmp_msg = add_l3_ecmp_group( self.controller, vlan_id, [ mpls_label_gid ] )
            do_barrier( self.controller )
            # add vlan flow table
            add_one_vlan_table_flow( self.controller, ports[0], 1, vlan_id=ports[0] + in_offset, vrf=0,
                                     flag=VLAN_TABLE_FLAG_ONLY_TAG )
            # add termination flow
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlanid=ports[0] + in_offset )
            else:
                add_termination_flow( self.controller, ports[0], 0x0800, intf_src_mac, vlanid=ports[0] + in_offset )
            # add routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffffff, ecmp_msg.group_id, send_barrier=True )
            Groups._put( l2_gid )
            Groups._put( mpls_gid )
            Groups._put( mpls_label_gid )
            Groups._put( ecmp_msg.group_id )


            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            in_port = ports[0]
            out_port = ports[1]
            ip_src = '192.168.%02d.1' % (in_port)
            ip_dst = '192.168.%02d.1' % (out_port+out_offset)
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(in_port + in_offset),
                                            eth_dst=switch_mac, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( parsed_pkt )
            self.dataplane.send( in_port, pkt )
            # build expect packet
            mac_dst = '00:00:00:22:22:%02X' % (out_port)
            label = (out_port+out_offset, 0, 1, 32)
            exp_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(out_port + out_offset), ip_ttl=63,
                                   ip_src=ip_src, ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac,
                                   label=[ label ] )
            pkt = str( exp_pkt )
            verify_packet( self, pkt, out_port )
            #verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_group(self.controller, ecmp_msg.group_id)
            delete_group(self.controller, mpls_label_gid)
            delete_group(self.controller, mpls_gid)
            delete_group(self.controller, l2_gid)


class _32ECMPL3( base_tests.SimpleDataPlane ):
    """
    Verifies /32 IP routing and ECMP with no label push
    IP -> L3ECMP -> L3Unicast -> L2Interface
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            # Hashes Test Name and uses it as id for installing unique groups
            ports = config[ "port_map" ].keys( )
            for port in ports:
                vlan_id = port
                id = port
                # add l2 interface group
                l2_gid, msg = add_one_l2_interface_group( self.controller, port, vlan_id=vlan_id,
                        is_tagged=True, send_barrier=False )
                dst_mac[ 5 ] = vlan_id
                l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id, id=id,
                        src_mac=intf_src_mac, dst_mac=dst_mac )
                ecmp_msg = add_l3_ecmp_group( self.controller, id, [ l3_msg.group_id ] )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add unicast routing flow
                dst_ip = dip + (vlan_id << 8)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffffff, ecmp_msg.group_id )
                Groups._put( l2_gid )
                Groups._put( l3_msg.group_id )
                Groups._put( ecmp_msg.group_id )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                mac_src = '00:00:00:22:22:%02X' % in_port
                ip_src = '192.168.%02d.1' % in_port
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % out_port
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=in_port,
                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expected packet
                    mac_dst = '00:00:00:22:22:%02X' % out_port
                    exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=out_port,
                            eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class One_32ECMPL3( base_tests.SimpleDataPlane ):
    """
    Verifies /32 IP routing and ECMP with no label push
    IP -> L3ECMP -> L3Unicast -> L2Interface
    in only one direction
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            # Hashes Test Name and uses it as id for installing unique groups
            ports = config[ "port_map" ].keys( )
            inport = ports[0]
            outport = ports[1]
            in_offset = 19
            out_offset = 20
            vlan_id = outport + out_offset
            id = outport
            # add l2 interface group, l3 unicast and ecmp group for outport
            l2_gid, msg = add_one_l2_interface_group( self.controller, outport, vlan_id=vlan_id,
                                                      is_tagged=True, send_barrier=False )
            dst_mac[ 5 ] = outport
            l3_msg = add_l3_unicast_group( self.controller, outport, vlanid=vlan_id, id=id,
                                           src_mac=intf_src_mac, dst_mac=dst_mac )
            ecmp_msg = add_l3_ecmp_group( self.controller, id, [ l3_msg.group_id ] )
            # add vlan flow table
            add_one_vlan_table_flow( self.controller, of_port=inport, vlan_id=inport+in_offset, flag=VLAN_TABLE_FLAG_ONLY_TAG )
            # add termination flow
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlanid=inport+in_offset )
            else:
                add_termination_flow( self.controller, in_port=inport, eth_type=0x0800, dst_mac=intf_src_mac, vlanid=inport+in_offset )
            # add unicast routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffffff, ecmp_msg.group_id, send_barrier=True )
            Groups._put( l2_gid )
            Groups._put( l3_msg.group_id )
            Groups._put( ecmp_msg.group_id )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            mac_src = '00:00:00:22:22:%02X' % inport
            ip_src = '192.168.%02d.1' % inport
            ip_dst = '192.168.%02d.1' % (outport+out_offset)
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=inport+in_offset,
                                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( parsed_pkt )
            self.dataplane.send( inport, pkt )
            # build expected packet
            mac_dst = '00:00:00:22:22:%02X' % outport
            exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=outport+out_offset,
                                         eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63, ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( exp_pkt )
            verify_packet( self, pkt, outport )
            verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )




@disabled
class _24VPN( base_tests.SimpleDataPlane ):
    """  Verify MPLS IP VPN Initiation from /32 rule without using ECMP  """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # add l2 interface group
                id = port
                vlan_id = port
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, True )
                dst_mac[ 5 ] = vlan_id
                # add MPLS interface group
                mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, dst_mac, intf_src_mac,
                        vlan_id, id )
                # add MPLS L3 VPN group
                mpls_label_gid, mpls_label_msg = add_mpls_label_group( self.controller,
                        subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=id, ref_gid=mpls_gid,
                        push_mpls_header=True, set_mpls_label=port, set_bos=1, set_ttl=32 )
                # ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [mpls_label_gid])
                do_barrier( self.controller )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, vrf=0,
                        flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add routing flow
                dst_ip = dip + (vlan_id << 8)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffff00, mpls_label_gid )
                Groups._put( l2_gid )
                Groups._put( mpls_gid )
                Groups._put( mpls_label_gid )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                ip_src = '192.168.%02d.1' % (in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % (out_port)
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(in_port),
                            eth_dst=switch_mac, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expect packet
                    mac_dst = '00:00:00:22:22:%02X' % (out_port)
                    label = (out_port, 0, 1, 32)
                    exp_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(out_port), ip_ttl=63,
                            ip_src=ip_src, ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac,
                            label=[ label ] )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class _24EcmpVpn( base_tests.SimpleDataPlane ):
    """  Verify MPLS IP VPN Initiation from /24 rule using ECMP  """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # add l2 interface group
                id = port
                vlan_id = id
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, True )
                dst_mac[ 5 ] = vlan_id
                # add MPLS interface group
                mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, dst_mac, intf_src_mac,
                        vlan_id, id )
                # add MPLS L3 VPN group
                mpls_label_gid, mpls_label_msg = add_mpls_label_group( self.controller,
                        subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=id, ref_gid=mpls_gid,
                        push_mpls_header=True, set_mpls_label=port, set_bos=1, set_ttl=32 )
                ecmp_msg = add_l3_ecmp_group( self.controller, id, [ mpls_label_gid ] )
                do_barrier( self.controller )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, vrf=0,
                        flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add routing flow
                dst_ip = dip + (vlan_id << 8)
                # add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0, mpls_label_gid, vrf=2)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffff00, ecmp_msg.group_id,
                        vrf=0 )
                Groups._put( l2_gid )
                Groups._put( mpls_gid )
                Groups._put( mpls_label_gid )
                Groups._put( ecmp_msg.group_id )

            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                mac_src = '00:00:00:22:22:%02X' % (in_port)
                ip_src = '192.168.%02d.1' % (in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % (out_port)
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(in_port),
                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expect packet
                    mac_dst = '00:00:00:22:22:%02X' % out_port
                    label = (out_port, 0, 1, 32)
                    exp_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(out_port), ip_ttl=63,
                            ip_src=ip_src, ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac,
                            label=[ label ] )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class FloodGroupMod( base_tests.SimpleDataPlane ):
    """ Modify a referenced flood group """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            ports = sorted( config[ "port_map" ].keys( ) )
            vlan_id = 1

            for port in ports:
                L2gid, l2msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, False )
                add_one_vlan_table_flow( self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                Groups.put( L2gid )

            msg = add_l2_flood_group( self.controller, ports, vlan_id, vlan_id )
            Groups.put( msg.group_id )
            add_bridge_flow( self.controller, None, vlan_id, msg.group_id, True )
            do_barrier( self.controller )
            # verify flood
            for ofport in ports:
                # change dest based on port number
                mac_src = '00:12:34:56:78:%02X' % ofport
                parsed_pkt = simple_tcp_packet_two_vlan( pktlen=108, out_dl_vlan_enable=True,
                        out_vlan_vid=vlan_id, in_dl_vlan_enable=True, in_vlan_vid=10,
                        eth_dst='00:12:34:56:78:9a', eth_src=mac_src )
                pkt = str( parsed_pkt )
                self.dataplane.send( ofport, pkt )
                # self won't rx packet
                verify_no_packet( self, pkt, ofport )
                # others will rx packet
                tmp_ports = list( ports )
                tmp_ports.remove( ofport )
                verify_packets( self, pkt, tmp_ports )
            verify_no_other_packets( self )
            msg = mod_l2_flood_group( self.controller, [ ports[ 0 ] ], vlan_id, vlan_id )
            mac_src = '00:12:34:56:78:%02X' % ports[ 1 ]
            parsed_pkt = simple_tcp_packet_two_vlan( pktlen=108, out_dl_vlan_enable=True,
                    out_vlan_vid=vlan_id, in_dl_vlan_enable=True, in_vlan_vid=10, eth_dst='00:12:34:56:78:9a',
                    eth_src=mac_src )
            pkt = str( parsed_pkt )
            self.dataplane.send( ports[ 1 ], pkt )
            verify_packets( self, pkt, [ ports[ 0 ] ] )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class _24ECMPL3( base_tests.SimpleDataPlane ):
    """ Verifies /24 IP routing using ECMP -> L3U -> L2I """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            # Hashes Test Name and uses it as id for installing unique groups
            ports = config[ "port_map" ].keys( )
            for port in ports:
                vlan_id = port
                id = port
                # add l2 interface group
                l2_gid, msg = add_one_l2_interface_group( self.controller, port, vlan_id=vlan_id,
                        is_tagged=True, send_barrier=False )
                dst_mac[ 5 ] = vlan_id
                l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id, id=id,
                        src_mac=intf_src_mac, dst_mac=dst_mac )
                ecmp_msg = add_l3_ecmp_group( self.controller, id, [ l3_msg.group_id ] )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add unicast routing flow
                dst_ip = dip + (vlan_id << 8)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffff00, ecmp_msg.group_id )
                Groups._put( l2_gid )
                Groups._put( l3_msg.group_id )
                Groups._put( ecmp_msg.group_id )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                mac_src = '00:00:00:22:22:%02X' % in_port
                ip_src = '192.168.%02d.1' % in_port
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % out_port
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=in_port,
                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expected packet
                    mac_dst = '00:00:00:22:22:%02X' % out_port
                    exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=out_port,
                            eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


@disabled
class MPLSBUG( base_tests.SimpleDataPlane ):
    """
    Needs a description or needs to be removed
    """
    def runTest( self ):
        if len( config[ "port_map" ] ) < 2:
            logging.info( "Port count less than 2, can't run this case" )
            return
        intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
        dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
        dip = 0xc0a80001
        Groups = Queue.LifoQueue( )
        ports = config[ "port_map" ].keys( )
        for port in ports:
            # add l2 interface group
            vlan_id = port
            l2_gid, l2_msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, False )
            dst_mac[ 5 ] = vlan_id
            # add L3 Unicast  group
            l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id, id=vlan_id,
                    src_mac=intf_src_mac, dst_mac=dst_mac )
            # add vlan flow table
            add_one_vlan_table_flow( self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_BOTH )
            # add termination flow
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x08847, intf_src_mac, vlan_id, goto_table=24 )
            else:
                add_termination_flow( self.controller, port, 0x8847, intf_src_mac, vlan_id, goto_table=24 )
            # add mpls flow
            add_mpls_flow( self.controller, l3_msg.group_id, port )
            # add termination flow
            add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
            # add unicast routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffffff, l3_msg.group_id )
            Groups._put( l2_gid )
            Groups._put( l3_msg.group_id )
        do_barrier( self.controller )

        switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
        for in_port in ports:
            mac_src = '00:00:00:22:22:%02X' % in_port
            ip_src = '192.168.%02d.1' % in_port
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % out_port
                switch_mac = "00:00:00:cc:cc:cc"
                label = (out_port, 0, 1, 32)
                parsed_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=in_port, ip_src=ip_src,
                        ip_dst=ip_dst, eth_dst=switch_mac, eth_src=mac_src, label=[ label ] )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                # build expect packet
                mac_dst = '00:00:00:22:22:%02X' % out_port
                exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=out_port,
                        eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=31, ip_src=ip_src, ip_dst=ip_dst )
                pkt = str( exp_pkt )
                verify_packet( self, pkt, out_port )
                verify_no_other_packets( self )

                parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=in_port,
                        eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # build expected packet
                mac_dst = '00:00:00:22:22:%02X' % out_port
                exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=out_port,
                        eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63, ip_src=ip_src, ip_dst=ip_dst )
                pkt = str( exp_pkt )
                verify_packet( self, pkt, out_port )
                verify_no_other_packets( self )
        delete_all_flows( self.controller )
        delete_groups( self.controller, Groups )

class L3McastToL3( base_tests.SimpleDataPlane ):
    """
    Mcast routing, in this test case the traffic comes in tagged.
    port+1 is used as ingress vlan_id. The packet goes out tagged on
    different ports. 4094-port is used as egress vlan_id.
    """
    def runTest( self ):
        """
        port1 (vlan 300)-> All Ports (vlan 300)
        """
        Groups = Queue.LifoQueue( )
        try:
        # We can forward on the in_port but egress_vlan has to be different from ingress_vlan
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports      = config[ "port_map" ].keys( )
            dst_ip_str = "224.0.0.1"
            (
                port_to_in_vlan,
                port_to_out_vlan,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                port_to_src_ip,
                port_to_src_ip_str,
                port_to_intf_src_mac_str,
                Groups) = fill_mcast_pipeline_L3toL3(
                self.controller,
                logging,
                ports,
                is_ingress_tagged   = True,
                is_egress_tagged    = True,
                is_vlan_translated  = True,
                is_max_vlan         = False
                )

            for in_port in ports:

                parsed_pkt = simple_udp_packet(
                    pktlen         = 100,
                    dl_vlan_enable = True,
                    vlan_vid       = port_to_in_vlan[in_port],
                    eth_dst        = port_to_dst_mac_str[in_port],
                    eth_src        = port_to_src_mac_str[in_port],
                    ip_ttl         = 64,
                    ip_src         = port_to_src_ip_str[in_port],
                    ip_dst         = dst_ip_str
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for out_port in ports:

                    parsed_pkt = simple_udp_packet(
                        pktlen         = 100,
                        dl_vlan_enable = True,
                        vlan_vid       = port_to_out_vlan[out_port],
                        eth_dst        = port_to_dst_mac_str[in_port],
                        eth_src        = port_to_intf_src_mac_str[out_port],
                        ip_ttl         = 63,
                        ip_src         = port_to_src_ip_str[in_port],
                        ip_dst         = dst_ip_str
                        )
                    pkt = str( parsed_pkt )
                    verify_packet( self, pkt, out_port )

                verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class L3McastToL2UntagToUntag( base_tests.SimpleDataPlane ):
    """
    Fails on alternate runs
    Mcast routing, in this test case the traffic is untagged.
    4094 is used as internal vlan_id. The packet goes out
    untagged.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                assert (False)
                return
            ports      = config[ "port_map" ].keys( )
            dst_ip_str = "224.0.0.1"
            (
                port_to_in_vlan,
                port_to_out_vlan,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                port_to_src_ip,
                port_to_src_ip_str,
                Groups) = fill_mcast_pipeline_L3toL2(
                self.controller,
                logging,
                ports,
                is_ingress_tagged   = False,
                is_egress_tagged    = False,
                is_vlan_translated  = False,
                is_max_vlan         = True
                )

            for in_port in ports:

                parsed_pkt = simple_udp_packet(
                    pktlen  = 96,
                    eth_dst = port_to_dst_mac_str[in_port],
                    eth_src = port_to_src_mac_str[in_port],
                    ip_ttl  = 64,
                    ip_src  = port_to_src_ip_str[in_port],
                    ip_dst  = dst_ip_str
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for out_port in ports:

                    parsed_pkt = simple_udp_packet(
                        pktlen  = 96,
                        eth_dst = port_to_dst_mac_str[in_port],
                        eth_src = port_to_src_mac_str[in_port],
                        ip_ttl  = 64,
                        ip_src  = port_to_src_ip_str[in_port],
                        ip_dst  = dst_ip_str
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class L3McastToL2UntagToTag( base_tests.SimpleDataPlane ):
    """
    Mcast routing, in this test case the traffic is untagged.
    300 is used as vlan_id. The packet goes out
    tagged.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                assert (False)
                return
            ports      = config[ "port_map" ].keys( )
            dst_ip_str = "224.0.0.1"
            (
                port_to_in_vlan,
                port_to_out_vlan,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                port_to_src_ip,
                port_to_src_ip_str,
                Groups) = fill_mcast_pipeline_L3toL2(
                self.controller,
                logging,
                ports,
                is_ingress_tagged   = False,
                is_egress_tagged    = True,
                is_vlan_translated  = False,
                is_max_vlan         = False
                )

            for in_port in ports:

                parsed_pkt = simple_udp_packet(
                    pktlen  = 96,
                    eth_dst = port_to_dst_mac_str[in_port],
                    eth_src = port_to_src_mac_str[in_port],
                    ip_ttl  = 64,
                    ip_src  = port_to_src_ip_str[in_port],
                    ip_dst  = dst_ip_str
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for out_port in ports:

                    parsed_pkt = simple_udp_packet(
                        pktlen          = 100,
                        dl_vlan_enable  = True,
                        vlan_vid        = port_to_out_vlan[in_port],
                        eth_dst         = port_to_dst_mac_str[in_port],
                        eth_src         = port_to_src_mac_str[in_port],
                        ip_ttl          = 64,
                        ip_src          = port_to_src_ip_str[in_port],
                        ip_dst          = dst_ip_str
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class L3McastToL2TagToUntag( base_tests.SimpleDataPlane ):
    """
    Mcast routing, in this test case the traffic is tagged.
    300 is used as vlan_id. The packet goes out
    untagged.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                assert (False)
                return
            ports      = config[ "port_map" ].keys( )
            dst_ip_str = "224.0.0.1"
            (
                port_to_in_vlan,
                port_to_out_vlan,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                port_to_src_ip,
                port_to_src_ip_str,
                Groups) = fill_mcast_pipeline_L3toL2(
                self.controller,
                logging,
                ports,
                is_ingress_tagged   = True,
                is_egress_tagged    = False,
                is_vlan_translated  = False,
                is_max_vlan         = False
                )

            for in_port in ports:

                parsed_pkt = simple_udp_packet(
                    pktlen         = 100,
                    dl_vlan_enable = True,
                    vlan_vid       = port_to_in_vlan[in_port],
                    eth_dst        = port_to_dst_mac_str[in_port],
                    eth_src        = port_to_src_mac_str[in_port],
                    ip_ttl         = 64,
                    ip_src         = port_to_src_ip_str[in_port],
                    ip_dst         = dst_ip_str
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for out_port in ports:

                    parsed_pkt = simple_udp_packet(
                        pktlen          = 96,
                        eth_dst         = port_to_dst_mac_str[in_port],
                        eth_src         = port_to_src_mac_str[in_port],
                        ip_ttl          = 64,
                        ip_src          = port_to_src_ip_str[in_port],
                        ip_dst          = dst_ip_str
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class L3McastToL2TagToTag( base_tests.SimpleDataPlane ):
    """
    Mcast routing, in this test case the traffic is tagged.
    300 is used as vlan_id. The packet goes out tagged.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                assert (False)
                return
            ports      = config[ "port_map" ].keys( )
            dst_ip_str = "224.0.0.1"
            (
                port_to_in_vlan,
                port_to_out_vlan,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                port_to_src_ip,
                port_to_src_ip_str,
                Groups) = fill_mcast_pipeline_L3toL2(
                self.controller,
                logging,
                ports,
                is_ingress_tagged   = True,
                is_egress_tagged    = True,
                is_vlan_translated  = False,
                is_max_vlan         = False
                )

            for in_port in ports:

                parsed_pkt = simple_udp_packet(
                    pktlen         = 100,
                    dl_vlan_enable = True,
                    vlan_vid       = port_to_in_vlan[in_port],
                    eth_dst        = port_to_dst_mac_str[in_port],
                    eth_src        = port_to_src_mac_str[in_port],
                    ip_ttl         = 64,
                    ip_src         = port_to_src_ip_str[in_port],
                    ip_dst         = dst_ip_str
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for out_port in ports:

                    parsed_pkt = simple_udp_packet(
                        pktlen         = 100,
                        dl_vlan_enable = True,
                        vlan_vid       = port_to_in_vlan[in_port],
                        eth_dst        = port_to_dst_mac_str[in_port],
                        eth_src        = port_to_src_mac_str[in_port],
                        ip_ttl         = 64,
                        ip_src         = port_to_src_ip_str[in_port],
                        ip_dst         = dst_ip_str
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class L3McastToL2TagToTagTranslated( base_tests.SimpleDataPlane ):
    """
    Mcast routing, in this test case the traffic is tagged.
    port+1 is used as ingress vlan_id. The packet goes out
    tagged. 4094-port is used as egress vlan_id
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                assert (False)
                return
            ports      = config[ "port_map" ].keys( )
            dst_ip_str = "224.0.0.1"
            (
                port_to_in_vlan,
                port_to_out_vlan,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                port_to_src_ip,
                port_to_src_ip_str,
                Groups) = fill_mcast_pipeline_L3toL2(
                self.controller,
                logging,
                ports,
                is_ingress_tagged   = True,
                is_egress_tagged    = True,
                is_vlan_translated  = True,
                is_max_vlan         = False
                )

            for in_port in ports:

                parsed_pkt = simple_udp_packet(
                    pktlen         = 100,
                    dl_vlan_enable = True,
                    vlan_vid       = port_to_in_vlan[in_port],
                    eth_dst        = port_to_dst_mac_str[in_port],
                    eth_src        = port_to_src_mac_str[in_port],
                    ip_ttl         = 64,
                    ip_src         = port_to_src_ip_str[in_port],
                    ip_dst         = dst_ip_str
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for out_port in ports:

                    parsed_pkt = simple_udp_packet(
                        pktlen         = 100,
                        dl_vlan_enable = True,
                        vlan_vid       = port_to_out_vlan[in_port],
                        eth_dst        = port_to_dst_mac_str[in_port],
                        eth_src        = port_to_src_mac_str[in_port],
                        ip_ttl         = 64,
                        ip_src         = port_to_src_ip_str[in_port],
                        ip_dst         = dst_ip_str
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class L3McastTrafficThenDrop( base_tests.SimpleDataPlane ):
    # fails on alternate repeated runs
    """
    Mcast routing, in this test case the traffic is untagged.
    4094 is used as internal vlan_id. We first install aa full pipeline,
    test that it forwards properly then remove all rules on table 40 and
    mcast groups and ensure traffic is dropped. Blackhole of mcast traffic
    if no tree is programmed on the switch.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                assert (False)
                return
            ports      = config[ "port_map" ].keys( )
            dst_ip_str = "224.0.0.1"
            (
                port_to_in_vlan,
                port_to_out_vlan,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                port_to_src_ip,
                port_to_src_ip_str,
                Groups) = fill_mcast_pipeline_L3toL2(
                self.controller,
                logging,
                ports,
                is_ingress_tagged   = False,
                is_egress_tagged    = False,
                is_vlan_translated  = False,
                is_max_vlan         = True
                )

            for in_port in ports:

                parsed_pkt = simple_udp_packet(
                    pktlen  = 96,
                    eth_dst = port_to_dst_mac_str[in_port],
                    eth_src = port_to_src_mac_str[in_port],
                    ip_ttl  = 64,
                    ip_src  = port_to_src_ip_str[in_port],
                    ip_dst  = dst_ip_str
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for out_port in ports:

                    parsed_pkt = simple_udp_packet(
                        pktlen  = 96,
                        eth_dst = port_to_dst_mac_str[in_port],
                        eth_src = port_to_src_mac_str[in_port],
                        ip_ttl  = 64,
                        ip_src  = port_to_src_ip_str[in_port],
                        ip_dst  = dst_ip_str
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )

            delete_all_flows_one_table(ctrl=self.controller, logger=logging, table_id=40);
            delete_all_groups(self.controller)

            for in_port in ports:

                parsed_pkt = simple_udp_packet(
                    pktlen  = 96,
                    eth_dst = port_to_dst_mac_str[in_port],
                    eth_src = port_to_src_mac_str[in_port],
                    ip_ttl  = 64,
                    ip_src  = port_to_src_ip_str[in_port],
                    ip_dst  = dst_ip_str
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                for out_port in ports:

                    parsed_pkt = simple_udp_packet(
                        pktlen  = 96,
                        eth_dst = port_to_dst_mac_str[in_port],
                        eth_src = port_to_src_mac_str[in_port],
                        ip_ttl  = 64,
                        ip_src  = port_to_src_ip_str[in_port],
                        ip_dst  = dst_ip_str
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_no_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class _MplsFwd( base_tests.SimpleDataPlane ):
    """ Verify basic MPLS forwarding: Label switch router  """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return
            dip = 0xc0a80001
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            # Assigns unique hardcoded test_id to make sure tests don't overlap when writing rules
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # Shift MPLS label and VLAN ID by 16 to avoid reserved values
                vlan_id = port + 16
                mpls_label = port + 16

                # add l2 interface group
                id = port
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, False )
                dst_mac[ 5 ] = port
                mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, dst_mac, intf_src_mac,
                        vlan_id, id )
                mpls_label_gid, mpls_label_msg = add_mpls_label_group( self.controller,
                        subtype=OFDPA_MPLS_GROUP_SUBTYPE_SWAP_LABEL, index=id, ref_gid=mpls_gid,
                        push_mpls_header=False, set_mpls_label=mpls_label, set_bos=1 )
                #ecmp_gid, ecmp_msg = add_mpls_forwarding_group( self.controller,
                #        subtype=OFDPA_MPLS_GROUP_SUBTYPE_ECMP, index=id, ref_gids=[mpls_label_gid] )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x8847, intf_src_mac, vlan_id, goto_table=24 )
                else:
                    add_termination_flow( self.controller, port, 0x8847, intf_src_mac, vlan_id, goto_table=24 )
                #add_mpls_flow( self.controller, ecmp_gid, port, goto_table=29 )
                if config["switch_type"] != 'xpliant':
                    add_mpls_flow( self.controller, mpls_label_gid, mpls_label, goto_table=29 )
                else:
                    xpliant_add_mpls_flow( self.controller, mpls_label_gid, mpls_label, goto_table=29 )
                dst_ip = dip + (vlan_id << 8)
                Groups._put( l2_gid )
                Groups._put( mpls_gid )
                Groups._put( mpls_label_gid )
                #Groups._put( ecmp_gid )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                ip_src = '192.168.%02d.1' % (in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue

                    # Shift MPLS label and VLAN ID by 16 to avoid reserved values
                    out_mpls_label = out_port + 16
                    in_vlan_vid = in_port + 16
                    out_vlan_vid = out_port + 16

                    ip_dst = '192.168.%02d.1' % (out_port)
                    label = (out_mpls_label, 0, 1, 32)
                    parsed_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(in_vlan_vid),
                            ip_src=ip_src, ip_dst=ip_dst, eth_dst=switch_mac, label=[ label ] )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )

                    # build expect packet
                    mac_dst = '00:00:00:22:22:%02X' % (out_port)
                    label = (out_mpls_label, 0, 1, 31)
                    exp_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(out_vlan_vid),
                            ip_src=ip_src, ip_dst=ip_dst, eth_src=switch_mac, eth_dst=mac_dst,
                            label=[ label ] )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class _MplsTermination( base_tests.SimpleDataPlane ):
    """ Verify MPLS VPN Termination at penultimate hop """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return
            dip = 0xc0a80001
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            # Assigns unique hardcoded test_id to make sure tests don't overlap when writing rules
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # Shift MPLS label and VLAN ID by 16 to avoid reserved values
                vlan_id = port + 16
                mpls_label = port + 16

                # add l2 interface group
                id, dst_mac[ 5 ] = port, port
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, port, vlan_id, True, False )
                # add L3 Unicast  group
                l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id, id=id,
                        src_mac=intf_src_mac, dst_mac=dst_mac )
                # add L3 ecmp group
                ecmp_msg = add_l3_ecmp_group( self.controller, id, [ l3_msg.group_id ] )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x8847, intf_src_mac, vlan_id, goto_table=24 )
                else:
                    add_termination_flow( self.controller, port, 0x8847, intf_src_mac, vlan_id, goto_table=24 )

                if config["switch_type"] != 'xpliant':
                    add_mpls_flow( self.controller, ecmp_msg.group_id, mpls_label )
                else:
                    xpliant_add_mpls_flow( self.controller, ecmp_msg.group_id, mpls_label )

                # add_mpls_flow(self.controller, label=port)
                dst_ip = dip + (vlan_id << 8)
                # add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0xffffff00,
                #                         ecmp_msg.group_id, 1)
                Groups._put( l2_gid )
                Groups._put( l3_msg.group_id )
                Groups._put( ecmp_msg.group_id )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                ip_src = '192.168.%02d.1' % (in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue

                    # Shift MPLS label and VLAN ID by 16 to avoid reserved values
                    out_mpls_label = out_port + 16
                    in_vlan_vid = in_port + 16
                    out_vlan_vid = out_port + 16

                    ip_dst = '192.168.%02d.1' % (out_port)
                    label = (out_mpls_label, 0, 1, 32)
                    parsed_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(in_vlan_vid),
                            ip_src=ip_src, ip_dst=ip_dst, eth_dst=switch_mac, label=[ label ] )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expect packet
                    mac_dst = '00:00:00:22:22:%02X' % (out_port)
                    if config["switch_type"] != 'xpliant':
                        ip_ttl=31
                    else:
                        ip_ttl=64
                    exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(out_vlan_vid),
                            eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=ip_ttl, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


@disabled
class One_MplsTermination( base_tests.SimpleDataPlane ):
    """
    Verify MPLS VPN Termination at penultimate hop in only one direction
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return
            dip = 0xc0a80001
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            # Assigns unique hardcoded test_id to make sure tests don't overlap when writing rules
            ports = config[ "port_map" ].keys( )
            inport = ports[0]
            outport = ports[1]

            # Shift MPLS label and VLAN ID by 16 to avoid reserved values
            invlan_id = inport + 16
            outvlan_id = outport + 16
            mpls_label = outport + 16

            # add l2 interface group
            id, dst_mac[ 5 ] = inport, outport
            l2_gid, l2_msg = add_one_l2_interface_group( self.controller, outport, outvlan_id, True, False )
            # add L3 Unicast  group
            l3_msg = add_l3_unicast_group( self.controller, outport, vlanid=outvlan_id, id=id,
                                           src_mac=intf_src_mac, dst_mac=dst_mac )
            # add L3 ecmp group
            ecmp_msg = add_l3_ecmp_group( self.controller, id, [ l3_msg.group_id ] )
            # add vlan flow table
            add_one_vlan_table_flow( self.controller, inport, 1, invlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
            # add tmac flow
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x8847, intf_src_mac, invlan_id, goto_table=24 )
            else:
                add_termination_flow( self.controller, inport, 0x8847, intf_src_mac, invlan_id, goto_table=24 )
            # add mpls termination flow
            add_mpls_flow( self.controller, ecmp_msg.group_id, mpls_label, send_barrier=True )
            Groups._put( l2_gid )
            Groups._put( l3_msg.group_id )
            Groups._put( ecmp_msg.group_id )

            time.sleep(0.1)
            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            ip_src = '192.168.%02d.1' % (inport)
            # Shift MPLS label and VLAN ID by 16 to avoid reserved values
            out_mpls_label = outport + 16
            in_vlan_vid = inport + 16
            out_vlan_vid = outport + 16

            ip_dst = '192.168.%02d.1' % (outport)
            label = (out_mpls_label, 0, 1, 32)
            parsed_pkt = mpls_packet( pktlen=104, dl_vlan_enable=True, vlan_vid=(in_vlan_vid),
                                      ip_src=ip_src, ip_dst=ip_dst, eth_dst=switch_mac, label=[ label ] )
            pkt = str( parsed_pkt )
            self.dataplane.send( inport, pkt )
            # build expect packet
            mac_dst = '00:00:00:22:22:%02X' % (outport)
            exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(out_vlan_vid),
                                         eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=31, ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( exp_pkt )
            verify_packet( self, pkt, outport )
            verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class _24UcastTagged( base_tests.SimpleDataPlane ):
    """ Verify /24 IP forwarding to L3 Interface """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            test_id = 26
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # add l2 interface group
                vlan_id = port + test_id
                l2gid, msg = add_one_l2_interface_group( self.controller, port, vlan_id=vlan_id,
                        is_tagged=True, send_barrier=False )
                dst_mac[ 5 ] = vlan_id
                l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id, id=vlan_id,
                        src_mac=intf_src_mac, dst_mac=dst_mac )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add unicast routing flow
                dst_ip = dip + (vlan_id << 8)
                # def add_unicast_routing_flow(ctrl, eth_type, dst_ip, mask, action_group_id, vrf=0, send_ctrl=False, send_barrier=False, priority = 1):
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffff00, l3_msg.group_id )
                Groups.put( l2gid )
                Groups.put( l3_msg.group_id )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                mac_src = '00:00:00:22:22:%02X' % (test_id + in_port)
                ip_src = '192.168.%02d.1' % (test_id + in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % (test_id + out_port)
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True,
                            vlan_vid=(test_id + in_port), eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64,
                            ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expected packet
                    mac_dst = '00:00:00:22:22:%02X' % (test_id + out_port)
                    exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True,
                            vlan_vid=(test_id + out_port), eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63,
                            ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class _24UcastRouteBlackHole( base_tests.SimpleDataPlane ):
    """ Verify black-holing of unicast routes, feature present only from OFDPA Premium 1.1.3.0"""

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            test_id = 27
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # add l2 interface group
                vlan_id = port + test_id
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add unicast routing flow
                #dst ip = 10.0.0.0/8
                dst_ip = 0x0a000000
                add_unicast_blackhole_flow(self.controller, 0x0800, dst_ip, 0xffffff00 )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                mac_src = '00:00:00:22:22:%02X' % (test_id + in_port)
                ip_src = '192.168.%02d.1' % (test_id + in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % (test_id + out_port)
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True,
                            vlan_vid=(test_id + in_port), eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64,
                            ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expected packet
                    mac_dst = '00:00:00:22:22:%02X' % (test_id + out_port)
                    exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True,
                            vlan_vid=(test_id + out_port), eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63,
                            ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( exp_pkt )
                    verify_no_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class _0Ucast( base_tests.SimpleDataPlane ):
    """  Verify default gateway IP forwarding to L3 Interface ( /0 rule ) """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )
            for port in ports:
                # add l2 interface group
                vlan_id = port
                l2gid, msg = add_one_l2_interface_group( self.controller, port, vlan_id=vlan_id + 1,
                        is_tagged=True, send_barrier=False )
                dst_mac[ 5 ] = vlan_id
                l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id + 1, id=vlan_id,
                        src_mac=intf_src_mac, dst_mac=dst_mac )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add unicast routing flow
                dst_ip = dip + (vlan_id << 8)
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffffff, l3_msg.group_id, priority=2 )
                Groups.put( l2gid )
                Groups.put( l3_msg.group_id )
            l3_gid = encode_l3_unicast_group_id( ports[ 0 ] )
            dst_ip = 0x0
            add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0x0, l3_gid )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            for in_port in ports:
                mac_src = '00:00:00:22:22:%02X' % (in_port)
                ip_src = '192.168.%02d.1' % (in_port)
                for out_port in ports:
                    if in_port == out_port:
                        continue
                    ip_dst = '192.168.%02d.1' % (out_port)
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(in_port),
                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expected packet
                    mac_dst = '00:00:00:22:22:%02X' % (out_port)
                    exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=(out_port + 1),
                            eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )
                    ip_dst = '1.168.%02d.1' % ports[ 0 ]
                    parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=in_port,
                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                    pkt = str( parsed_pkt )
                    self.dataplane.send( in_port, pkt )
                    # build expect packet
                    mac_dst = '00:00:00:22:22:%02X' % ports[ 0 ]
                    exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=ports[ 0 ] + 1,
                            ip_ttl=63, ip_src=ip_src, ip_dst=ip_dst, eth_dst=mac_dst, eth_src=switch_mac )
                    pkt = str( exp_pkt )
                    verify_packet( self, pkt, ports[ 0 ] )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class Unfiltered( base_tests.SimpleDataPlane ):
    """
    Attempt to add an unfiltered group: [ATTENTION] this doesn't verify addition
    """

    def runTest( self ):
        try:
            ports = sorted( config[ "port_map" ].keys( ) )
            vlan_id = 1;
            for port in ports:
                add_l2_unfiltered_group( self.controller, [ port ], False )
            do_barrier( self.controller )
        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

@disabled
class L3McastToVPN( base_tests.SimpleDataPlane ):
    """
    Mcast routing and VPN initiation
    """

    def runTest( self ):
        """
        port1 (vlan 1)-> port 2 (vlan 2)
        """
        try:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

            if len( config[ "port_map" ] ) < 3:
                logging.info( "Port count less than 3, can't run this case" )
                assert (False)
                return

            vlan_id = 1
            port2_out_vlan = 2
            port3_out_vlan = 3
            in_vlan = 1  # macast group vid shall use input vlan diffe from l3 interface use output vlan
            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            intf_src_mac_str = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            dst_mac = [ 0x01, 0x00, 0x5e, 0x01, 0x01, 0x01 ]
            dst_mac_str = ':'.join( [ '%02X' % x for x in dst_mac ] )
            port1_mac = [ 0x00, 0x11, 0x11, 0x11, 0x11, 0x11 ]
            port1_mac_str = ':'.join( [ '%02X' % x for x in port1_mac ] )
            src_ip = 0xc0a80101
            src_ip_str = "192.168.1.1"
            dst_ip = 0xe0010101
            dst_ip_str = "224.1.1.1"

            port1 = config[ "port_map" ].keys( )[ 0 ]
            port2 = config[ "port_map" ].keys( )[ 1 ]
            # port3=config["port_map"].keys()[2]

            # add l2 interface group
            for port in config[ "port_map" ].keys( ):
                add_one_l2_interface_group( self.controller, port, vlan_id=vlan_id, is_tagged=False,
                        send_barrier=False )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                vlan_id += 1

                # add termination flow
            add_termination_flow( self.controller, port1, 0x0800, [ 0x01, 0x00, 0x5e, 0x00, 0x00, 0x00 ],
                    vlan_id )

            # add MPLS interface group
            l2_gid = encode_l2_interface_group_id( port2_out_vlan, port2 )
            mpls_gid2, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, dst_mac, intf_src_mac,
                    port2_out_vlan, port2 )
            # l2_gid3 = encode_l2_interface_group_id(port3_out_vlan, port3)
            # mpls_gid3, mpls_msg = add_mpls_intf_group(self.controller, l2_gid3, dst_mac, intf_src_mac, port3_out_vlan, port3)
            # add L3VPN groups
            mpls_label_gid2, mpls_label_msg = add_mpls_label_group( self.controller,
                    subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=(0x20000 + port2), ref_gid=mpls_gid2,
                    push_mpls_header=True, set_mpls_label=port2, set_bos=1, cpy_ttl_outward=True )
            # mpls_label_gid3, mpls_label_msg = add_mpls_label_group(self.controller, subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
            #                                                       index=(0x10000+port3), ref_gid= mpls_gid3, push_mpls_header=True, set_mpls_label=port3, set_bos=1, cpy_ttl_outward=True)

            mcat_group_msg = add_l3_mcast_group( self.controller, in_vlan, 2, [ mpls_label_gid2 ] )
            add_mcast4_routing_flow( self.controller, in_vlan, src_ip, 0, dst_ip, mcat_group_msg.group_id )

            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=1, eth_dst=dst_mac_str,
                    eth_src=port1_mac_str, ip_ttl=64, ip_src=src_ip_str, ip_dst=dst_ip_str )
            pkt = str( parsed_pkt )
            self.dataplane.send( port1, pkt )
            label = (12, 0, 1, 63)
            exp_pkt = mpls_packet( pktlen=100, eth_dst=dst_mac_str, eth_src=intf_src_mac_str, ip_ttl=64,
                    ip_src=src_ip_str, label=[ label ], ip_dst=dst_ip_str )
            pkt = str( exp_pkt )
            verify_packet( self, pkt, port2 )
            # verify_packet(self, pkt, port3)
            verify_no_other_packets( self )
            delete_all_groups( self.controller )
        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

@disabled
class PacketInSrcMacMiss( base_tests.SimpleDataPlane ):
    """
    Test packet in function on a src-mac miss
    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    #todo verify you stop receiving after adding rule
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            ports = sorted( config[ "port_map" ].keys( ) )

            Groups = Queue.LifoQueue( )
            for port in ports:
                L2gid, l2msg = add_one_l2_interface_group( self.controller, port, 1, True, False )
                add_one_vlan_table_flow( self.controller, port, 1, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                Groups.put( L2gid )
            parsed_vlan_pkt = simple_tcp_packet( pktlen=104, vlan_vid=0x1001, dl_vlan_enable=True )
            vlan_pkt = str( parsed_vlan_pkt )
            for of_port in config[ "port_map" ].keys( ):
                logging.info( "PacketInMiss test, port %d", of_port )
                self.dataplane.send( of_port, vlan_pkt )
                verify_packet_in( self, vlan_pkt, of_port, ofp.OFPR_NO_MATCH )
                verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )


class EcmpGroupMod( base_tests.SimpleDataPlane ):
    """
        Verify referenced group can be modified by adding or removing buckets
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            # Hashes Test Name and uses it as id for installing unique groups
            ports = config[ "port_map" ].keys( )
            ecmp = [ ]
            dst_ips = []
            # add flows for all ports but include only the egress switchport (connected to ports[1])
            # in the ecmp group
            for port in ports:
                vlan_id = port
                id = port
                # add l2 interface group
                l2_gid, msg = add_one_l2_interface_group( self.controller, port, vlan_id=vlan_id,
                        is_tagged=True, send_barrier=False )
                dst_mac[ 5 ] = vlan_id
                l3_msg = add_l3_unicast_group( self.controller, port, vlanid=vlan_id, id=id,
                        src_mac=intf_src_mac, dst_mac=dst_mac )
                if port == ports[1]:
                    ecmp += [ l3_msg.group_id ]
                Groups._put( l2_gid )
                Groups._put( l3_msg.group_id )
                ecmp_msg = add_l3_ecmp_group( self.controller, ports[ 0 ], [ l3_msg.group_id ] )
                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
                else:
                    add_termination_flow( self.controller, port, 0x0800, intf_src_mac, vlan_id )
                # add unicast routing flow
                dst_ip = dip + (vlan_id << 8)
                dst_ips += [dst_ip]
                Groups._put( ecmp_msg.group_id )
            mod_l3_ecmp_group( self.controller, ports[ 0 ], ecmp )
            for dst_ip in dst_ips:
                add_unicast_routing_flow( self.controller, 0x0800, dst_ip, 0xffffff00, ecmp_msg.group_id )
            do_barrier(self.controller)
            time.sleep(0.1)
            # first part of the test: send packet from ingress switchport and expect it at egress switchport
            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            parsed_pkt = exp_pkt = 0
            in_port = ports[0]
            out_port = ports[1]
            logging.info("\nSending packet to port: " + str(in_port) + ", expected egress on port: " + str(out_port))
            mac_src = '00:00:00:22:22:%02X' % ports[ 0 ]
            ip_src = '192.168.%02d.%02d' % (ports[ 0 ], 1)
            ip_dst = '192.168.%02d.%02d' % (ports[ 1 ], 1)
            tcp = out_port if out_port == 24 else 25
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=ports[ 0 ],
                                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src,
                                            ip_dst=ip_dst, tcp_dport=tcp )
            pkt = str( parsed_pkt )
            self.dataplane.send( ports[ 0 ], pkt )
            # build expected packet at egress switchport
            mac_dst = '00:00:00:22:22:%02X' % out_port
            exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=out_port,
                                         eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63, ip_src=ip_src,
                                         ip_dst=ip_dst, tcp_dport=tcp )
            pkt = str( exp_pkt )
            verify_packet( self, pkt, out_port )
            verify_no_other_packets( self )

            # second part of the test - edit the ecmp group to remove the orginal egress switchport
            # and instead add the ingress switchport. Send packet from ingress switchport, and expect
            # it back on the ingress switchport
            l3_gid = encode_l3_unicast_group_id( ports[ 0 ] )
            mod_l3_ecmp_group( self.controller, ports[ 0 ], [ l3_gid ] )
            time.sleep(0.1)
            logging.info("Sending packet to port: " + str(ports[0]) + ", expected egress on port: " + str(ports[0]))
            mac_src = '00:00:00:22:22:%02X' % ports[ 0 ]
            ip_src = '192.168.%02d.%02d' % (ports[ 0 ], 1)
            ip_dst = '192.168.%02d.%02d' % (ports[ 1 ], 1)
            tcp = port if port == 24 else 25
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=ports[ 0 ],
                                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src,
                                            ip_dst=ip_dst,tcp_dport=tcp )
            pkt = str( parsed_pkt )
            self.dataplane.send( ports[ 0 ], pkt )
            # build expected packet
            mac_dst = '00:00:00:22:22:%02X' % ports[ 0 ]
            exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=ports[ 0 ],
                                         eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63, ip_src=ip_src,
                                         ip_dst=ip_dst,tcp_dport=tcp )
            # Expects packet on the input port
            if config["switch_type"] != 'xpliant':
                pkt = str( exp_pkt )
                verify_packet( self, pkt, ports[ 0 ] )
                verify_no_other_packets( self )

            # third part of the test - edit the group to completely remove bucket. Packet sent
            # should be dropped by the switch
            mod_l3_ecmp_group( self.controller, ports[ 0 ], [ ] )
            time.sleep(0.1)
            logging.info("Sending packet to port: " + str(ports[0]) + ", expected drop")
            mac_src = '00:00:00:22:22:%02X' % ports[ 0 ]
            ip_src = '192.168.%02d.%02d' % (ports[ 0 ], 1)
            ip_dst = '192.168.%02d.%02d' % (ports[ 1 ], 1)
            tcp = port if port == 24 else 25
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=ports[ 0 ],
                                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src,
                                            ip_dst=ip_dst,tcp_dport=tcp )
            pkt = str( parsed_pkt )
            self.dataplane.send( ports[ 0 ], pkt )
            verify_no_other_packets( self )

            # final part of the test - edit the empty group to add back the bucket for the
            # original egress port, and verify packet is received on egress switch port
            l3_gid = encode_l3_unicast_group_id( ports[ 1 ] )
            mod_l3_ecmp_group( self.controller, ports[ 0 ], [ l3_gid ] )
            do_barrier(self.controller)
            in_port = ports[0]
            out_port = ports[1]
            logging.info("Sending packet to port: " + str(in_port) + ", expected egress on port: " + str(out_port))
            mac_src = '00:00:00:22:22:%02X' % ports[ 0 ]
            ip_src = '192.168.%02d.%02d' % (ports[ 0 ], 1)
            ip_dst = '192.168.%02d.%02d' % (ports[ 1 ], 1)
            tcp = out_port if out_port == 24 else 25
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=ports[ 0 ],
                                            eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64, ip_src=ip_src,
                                            ip_dst=ip_dst, tcp_dport=tcp )
            pkt = str( parsed_pkt )
            self.dataplane.send( ports[ 0 ], pkt )
            # build expected packet at egress switchport
            mac_dst = '00:00:00:22:22:%02X' % out_port
            exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=out_port,
                                         eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63, ip_src=ip_src,
                                         ip_dst=ip_dst, tcp_dport=tcp )
            pkt = str( exp_pkt )
            verify_packet( self, pkt, out_port )
            verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


class Untagged( base_tests.SimpleDataPlane ):
    """
        Verify VLAN filtering table does not require OFPVID_PRESENT bit to be 0.
        This should be fixed in OFDPA 2.0 GA and above, the test fails with
        previous versions of the OFDPA.

        Two rules are necessary in VLAN table (10):
        1) Assignment: match 0x0000/(no mask), set_vlan_vid 0x100A, goto 20
        2) Filtering: match 0x100A/0x1FFF, goto 20

        In this test case vlan_id = (MAX_INTERNAL_VLAN - port_no).
        The remaining part of the test is based on the use of the bridging table
    """

    MAX_INTERNAL_VLAN = 4094

    def runTest( self ):
        groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted( config[ "port_map" ].keys( ) )
            for port in ports:
                vlan_id = Untagged.MAX_INTERNAL_VLAN - port
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
                add_one_vlan_table_flow( self.controller, port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_UNTAG )
                for other_port in ports:
                    if other_port == port:
                        continue
                    L2gid, l2msg = add_one_l2_interface_group( self.controller, other_port, vlan_id, False, False )
                    groups.put( L2gid )
                    add_bridge_flow( self.controller, [ 0x00, 0x12, 0x34, 0x56, 0x78, other_port ], vlan_id, L2gid, True )

            do_barrier( self.controller )

            for out_port in ports:
                # change dest based on port number
                mac_dst = '00:12:34:56:78:%02X' % out_port
                for in_port in ports:
                    if in_port == out_port:
                        continue
                    pkt = str( simple_tcp_packet( eth_dst=mac_dst ) )
                    self.dataplane.send( in_port, pkt )
                    for ofport in ports:
                        if ofport in [ out_port ]:
                            verify_packet( self, pkt, ofport )
                        else:
                            verify_no_packet( self, pkt, ofport )
                    verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, groups )
            delete_all_groups( self.controller )

class MPLSSwapTest( base_tests.SimpleDataPlane ):
    """
    MPLS switching with the same label used.
    Used for interconnecting spines between different fabrics where
    the label should not be popped, but swapepd with the same label.
    """

    def runTest( self ):
        try:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 3, can't run this case" )
                assert (False)
                return

            input_src_mac = [ 0x00, 0x00, 0x5e, 0x01, 0x01, 0x01 ]
            input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

            input_dst_mac = [ 0x00, 0x00, 0x5e, 0x01, 0x01, 0x02 ]
            input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

            output_dst_mac = [ 0x00, 0x00, 0x5e, 0x01, 0x01, 0x03 ]
            output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

            mpls_label = 1000

            src_ip = 0xc0a80101
            src_ip_str = "192.168.1.1"
            dst_ip = 0xe0010101
            dst_ip_str = "224.1.1.1"

            src_port = config[ "port_map" ].keys( )[ 0 ]
            dst_port = config[ "port_map" ].keys( )[ 1 ]

            out_vlan = 4094

            add_one_l2_interface_group( self.controller, dst_port, vlan_id=out_vlan, is_tagged=False,
                       		 	send_barrier=True )

            # add vlan flow table
            add_one_vlan_table_flow( self.controller, src_port, out_vlan_id=out_vlan, vlan_id=out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG )
            add_one_vlan_table_flow( self.controller, src_port, out_vlan_id=out_vlan, vlan_id=out_vlan, flag=VLAN_TABLE_FLAG_ONLY_UNTAG )

            # add termination flow

            if config["switch_type"] == "qmx":
                logging.debug("MPLSSwitching : Adding flow for qmx, without input port")
                add_termination_flow( self.controller, 0, eth_type=0x08847, dst_mac=input_dst_mac, vlanid=out_vlan, goto_table=23)
            else:
                add_termination_flow( self.controller, in_port=src_port,
				  eth_type=0x8847, dst_mac=input_dst_mac, vlanid=out_vlan, goto_table=23)

	    # add groups that will be used now
            l2_gid = encode_l2_interface_group_id( out_vlan, dst_port)
            mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid,
						      output_dst_mac, input_dst_mac,
                    	  			      out_vlan, dst_port, send_barrier=True)
            index = 60
            mpls_swap_gid, mpls_swap_msg = add_mpls_swap_label_group( self.controller, mpls_gid,
	 	            					      5, index, mpls_label)

            # add flow to mpls table
            add_mpls_flow_swap( self.controller, mpls_swap_gid, mpls_label, 0x8847, 1, send_barrier=True)

            # we generate the packet which carries a single label
            label = (mpls_label, 0, 1, 63)
            parsed_pkt = mpls_packet(
                pktlen=104,
                label=[label],
                eth_src=input_src_mac_str,
                eth_dst=input_dst_mac_str,
                )
            pkt = str( parsed_pkt )

            self.dataplane.send( src_port, pkt )

            label = (mpls_label, 0, 1, 62)
            parsed_pkt = mpls_packet(
                pktlen=104,
                label=[label],
                eth_src=input_dst_mac_str,
                eth_dst=output_dst_mac_str,
                )
            pkt = str( parsed_pkt )

            verify_packet( self, pkt, dst_port )
            verify_no_packet( self, pkt, src_port )
            verify_no_other_packets( self )

            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_all_groups( self.controller )

@disabled
class DoubleToUntagged( base_tests.SimpleDataPlane ):
    """
         Verify MPLS IP VPN Initiation from /24 rule using ECMP
         where we receive double tagged packets and output untagged
         packets.

         Each double tagged packet represents a subscriber where Outer tag is pon
         and inner tag is the subrscriber tag.
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

            input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

            output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
            output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )

            inner_vlan = 66
            outer_vlan = 77
            id = 10
            mpls_label = 152

            port = ports[0]
            out_port = ports[1]

            # add l2 interface group
            l2_gid, l2_msg = add_one_l2_interface_group( self.controller, out_port, inner_vlan, False, True )

            # add MPLS interface group
            mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, output_dst_mac, input_dst_mac,
                    inner_vlan, id )

            # add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group( self.controller,
                    subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=id, ref_gid=mpls_gid,
                    push_mpls_header=True, set_mpls_label=mpls_label, set_bos=1, set_ttl=32 )
            ecmp_msg = add_l3_ecmp_group( self.controller, id, [ mpls_label_gid ] )

            do_barrier( self.controller )

            # add vlan flow table
            add_one_vlan_table_flow( self.controller, port, 1, outer_vlan, vrf=0,
                    flag=VLAN_TABLE_FLAG_ONLY_STACKED )

            add_one_vlan_1_table_flow( self.controller, port, outer_vlan_id=outer_vlan, inner_vlan_id=inner_vlan,
                    flag=VLAN_TABLE_FLAG_ONLY_UNTAG )

            # add termination flow
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x0800, input_dst_mac, inner_vlan )
            else:
                add_termination_flow( self.controller, port, 0x0800, input_dst_mac, inner_vlan )

            # add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0, mpls_label_gid, vrf=2)
            add_unicast_routing_flow( self.controller, 0x0800, dip, 0xffffff00, ecmp_msg.group_id,
                    vrf=0 )
            Groups._put( l2_gid )
            Groups._put( mpls_gid )
            Groups._put( mpls_label_gid )
            Groups._put( ecmp_msg.group_id )

            do_barrier( self.controller )

            ip_src = '192.168.5.5'
            ip_dst = '192.168.0.5'
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=inner_vlan, outer_vlan=outer_vlan,
                    eth_dst=input_dst_mac_str, eth_src=input_src_mac_str, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( parsed_pkt )

            # print("Expected %s" % format_packet(pkt))

            self.dataplane.send( port, pkt )

            # build expect packet
            label = (mpls_label, 0, 1, 32)
            exp_pkt = mpls_packet( pktlen=96, dl_vlan_enable=False, ip_ttl=63,
                    ip_src=ip_src, ip_dst=ip_dst, eth_dst=output_dst_mac_str, eth_src=input_dst_mac_str,
                    label=[ label ] )
            pkt = str( exp_pkt )
            verify_packet( self, pkt, out_port )
            verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class DoubleToUntaggedMultipleSubscribers( base_tests.SimpleDataPlane ):
    """
         Verify MPLS IP VPN Initiation from /24 rule using ECMP
         where we receive double tagged packets and output untagged
         packets.

         Each double tagged packet represents a subscriber where Outer tag is pon
         and inner tag is the subrscriber tag.
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            # each entry represents a subscriber [id, ip in hex, inner_vlan, outer_vlan, ip in dot form]
            subscriber_info = [ [10, 0xc0a80001, 10, 100, "192.168.0.1"],
                                [20, 0xc0a80002, 10, 101, "192.168.0.2"],
                                [30, 0xc0a80003, 11, 100, "192.168.0.3"],
                                [40, 0xc0a80004, 11, 101, "192.168.0.4"]]

            print("")

            for sub_info in subscriber_info:

                print("Initializing rules for subscriber with id {0}".format(sub_info[0]))

                input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, sub_info[0] ]
                input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

                input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
                input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

                output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
                output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

                dip = sub_info[1]
                ports = config[ "port_map" ].keys( )

                inner_vlan = sub_info[2]
                outer_vlan = sub_info[3]
                id = 10
                mpls_label = 152

                port = ports[0]
                out_port = ports[1]

                # add l2 interface group
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, out_port, inner_vlan, False, True )

                # add MPLS interface group
                mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, output_dst_mac, input_dst_mac,
                        inner_vlan, id )

                # add MPLS L3 VPN group
                mpls_label_gid, mpls_label_msg = add_mpls_label_group( self.controller,
                        subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, index=id, ref_gid=mpls_gid,
                        push_mpls_header=True, set_mpls_label=mpls_label, set_bos=1, set_ttl=32 )
                ecmp_msg = add_l3_ecmp_group( self.controller, id, [ mpls_label_gid ] )

                do_barrier( self.controller )

                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, outer_vlan, vrf=0,
                        flag=VLAN_TABLE_FLAG_ONLY_STACKED )

                add_one_vlan_1_table_flow( self.controller, port, outer_vlan_id=outer_vlan, inner_vlan_id=inner_vlan,
                        flag=VLAN_TABLE_FLAG_ONLY_UNTAG )

                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, input_dst_mac, inner_vlan )
                else:
                    add_termination_flow( self.controller, port, 0x0800, input_dst_mac, inner_vlan )

                # add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0, mpls_label_gid, vrf=2)
                add_unicast_routing_flow( self.controller, 0x0800, dip, 0xffffff00, ecmp_msg.group_id,
                        vrf=0 )
                Groups._put( l2_gid )
                Groups._put( mpls_gid )
                Groups._put( mpls_label_gid )
                Groups._put( ecmp_msg.group_id )

                do_barrier( self.controller )

            for sub_info in subscriber_info:

                print("Sending packet for subscriber with id {0}".format(sub_info[0]))

                input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, sub_info[0] ]
                input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

                input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
                input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

                output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
                output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

                dip = sub_info[1]
                ports = config[ "port_map" ].keys( )

                inner_vlan = sub_info[2]
                outer_vlan = sub_info[3]
                id = 10
                mpls_label = 152

                port = ports[0]
                out_port = ports[1]

                ip_src = sub_info[4]
                ip_dst = '192.168.0.{}'.format(sub_info[0])
                parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True, vlan_vid=inner_vlan, outer_vlan=outer_vlan,
                        eth_dst=input_dst_mac_str, eth_src=input_src_mac_str, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                pkt = str( parsed_pkt )

                # print("Sent %s" % format_packet(pkt))

                self.dataplane.send( port, pkt )

                # build expect packet
                label = (mpls_label, 0, 1, 32)
                exp_pkt = mpls_packet( pktlen=96, dl_vlan_enable=False, ip_ttl=63,
                        ip_src=ip_src, ip_dst=ip_dst, eth_dst=output_dst_mac_str, eth_src=input_dst_mac_str,
                        label=[ label ] )
                pkt = str( exp_pkt )
                verify_packet( self, pkt, out_port )
                verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


@disabled
class UntaggedToDouble ( base_tests.SimpleDataPlane ):
    """
        Verify google senario where we need to go from
        an untagged packet to a double tagged packet.

        This is used for a single subscriber.
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

            input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

            output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
            output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )

            inner_vlan = 66
            outer_vlan = 77
            id = 10
            mpls_label = 152

            port = ports[0]
            out_port = ports[1]

            # add l2 unfiltered interface group
            l2_gid, l2_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            l3_msg = add_l3_unicast_group( self.controller, out_port, vlanid=4094, id=id,
                        src_mac=input_dst_mac, dst_mac=output_dst_mac, gid=l2_gid)

            do_barrier( self.controller )

            # add vlan flow table
            add_one_vlan_table_flow( self.controller, port, 1, 4094,
                    flag=VLAN_TABLE_FLAG_ONLY_BOTH )

            # add termination flow
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x0800, input_dst_mac, 4094 )
            else:
                add_termination_flow( self.controller, port, 0x0800, input_dst_mac, 4094 )

            add_unicast_routing_flow( self.controller, 0x0800, dip, 0xffffffff, l3_msg.group_id,
                    vrf=0 )

            add_one_egress_vlan_table_flow( self.controller, out_port, 4094 , inner_vlan, outer_vlan)

            Groups._put( l2_gid )
            Groups._put( l3_msg.group_id )

            do_barrier( self.controller )

            ip_src = '192.168.5.5'
            ip_dst = '192.168.0.1'
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=False,
                    eth_dst=input_dst_mac_str, eth_src=input_src_mac_str, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( parsed_pkt )

            # print("Input Packet %s" % format_packet(pkt))

            self.dataplane.send( port, pkt )

            # build expect packet
            exp_pkt = simple_tcp_packet( pktlen=108, dl_vlan_enable=True, vlan_vid=inner_vlan, outer_vlan=outer_vlan,
                    eth_dst=output_dst_mac_str, eth_src=input_dst_mac_str, ip_ttl=63, ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( exp_pkt )

            # print("Expected Packet %s" % format_packet(pkt))

            verify_packet( self, pkt, out_port )
            verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class UntaggedToDoubleMultipleSubscribers ( base_tests.SimpleDataPlane ):
    """
        Verify google senario where we need to go from
        an untagged packet to a double tagged packet.

        This is used for multiple subscribers.

        However, this solution does not scale, since we assign an internal vlan to each subscriber
        used in L3 Unicast Group in order to differentiate between them in the Egress Vlan Table.
    """

    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            # each entry represents a subscriber [id, ip in hex, inner_vlan, outer_vlan, ip in dot form, internal vlan]
            subscriber_info = [[1, 0xc0a80001, 10, 100, "192.168.0.1", 4000],
                               [2, 0xc0a80002, 10, 101, "192.168.0.2", 4001],
                               [3, 0xc0a80003, 11, 100, "192.168.0.3", 4002],
                               [4, 0xc0a80004, 11, 101, "192.168.0.4", 4003]]

            print("")

            for sub_info in subscriber_info:

                print("Initializing rules for subscriber with id {0}".format(sub_info[0]))

                input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, sub_info[0] ]
                input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

                input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
                input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

                output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
                output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

                dip = sub_info[1]
                ports = config[ "port_map" ].keys( )

                inner_vlan = sub_info[2]
                outer_vlan = sub_info[3]
                internal_vlan = sub_info[5]
                id = sub_info[0] + 10

                port = ports[0]
                out_port = ports[1]

                # add l2 unfiltered interface group
                l2_gid, l2_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

                l3_msg = add_l3_unicast_group( self.controller, out_port, vlanid=internal_vlan, id=id,
                            src_mac=input_dst_mac, dst_mac=output_dst_mac, gid=l2_gid)

                do_barrier( self.controller )

                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, 1, 4094,
                        flag=VLAN_TABLE_FLAG_ONLY_BOTH )

                # add termination flow
                if config["switch_type"] == "qmx":
                    add_termination_flow( self.controller, 0, 0x0800, input_dst_mac, 4094 )
                else:
                    add_termination_flow( self.controller, port, 0x0800, input_dst_mac, 4094 )

                add_unicast_routing_flow( self.controller, 0x0800, dip, 0xffffffff, l3_msg.group_id,
                        vrf=0 )

                add_one_egress_vlan_table_flow( self.controller, out_port, internal_vlan, inner_vlan, outer_vlan)

                Groups._put( l2_gid )
                Groups._put( l3_msg.group_id )
                do_barrier( self.controller )

            for sub_info in subscriber_info:

                print("Sending packet for subscriber with id {0}".format(sub_info[0]))

                input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, sub_info[0] ]
                input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

                input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
                input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

                output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
                output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

                dip = sub_info[1]
                ports = config[ "port_map" ].keys( )

                inner_vlan = sub_info[2]
                outer_vlan = sub_info[3]
                internal_vlan = sub_info[5]

                id = sub_info[0] + 10
                ip_src = '192.168.5.5'
                ip_dst = '192.168.0.{}'.format(sub_info[0])
                parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=False,
                        eth_dst=input_dst_mac_str, eth_src=input_src_mac_str, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                pkt = str( parsed_pkt )

                # print("Input Packet %s" % format_packet(pkt))

                self.dataplane.send( port, pkt )

                # build expect packet
                exp_pkt = simple_tcp_packet( pktlen=108, dl_vlan_enable=True, vlan_vid=inner_vlan, outer_vlan=outer_vlan,
                        eth_dst=output_dst_mac_str, eth_src=input_dst_mac_str, ip_ttl=63, ip_src=ip_src, ip_dst=ip_dst )
                pkt = str( exp_pkt )

                # print("Expected Packet %s" % format_packet(pkt))

                verify_packet( self, pkt, out_port )
                verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class UntaggedToDoubleChangeEthertype ( base_tests.SimpleDataPlane ):

    def runTest( self ):
        Groups = Queue.LifoQueue()

        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "port count less than 2, can't run this case" )
                return

            input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

            input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

            output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
            output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

            dip = 0xc0a80001
            ports = config[ "port_map" ].keys( )

            inner_vlan = 66
            outer_vlan = 77
            id = 10

            port = ports[0]
            out_port = ports[1]

            # add l2 unfiltered interface group
            l2_gid, l2_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            l3_msg = add_l3_unicast_group( self.controller, out_port, vlanid=4094, id=id,
                        src_mac=input_dst_mac, dst_mac=output_dst_mac, gid=l2_gid)

            do_barrier( self.controller )

            # add vlan flow table
            add_one_vlan_table_flow( self.controller, port, 1, 4094,
                    flag=VLAN_TABLE_FLAG_ONLY_BOTH )

            # add termination flow
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x0800, input_dst_mac, 4094 )
            else:
                add_termination_flow( self.controller, port, 0x0800, input_dst_mac, 4094 )

            add_unicast_routing_flow( self.controller, 0x0800, dip, 0xffffffff, l3_msg.group_id,
                    vrf=0 )

            add_one_egress_vlan_table_flow( self.controller, out_port, 4094 , inner_vlan, outer_vlan)

            Groups._put( l2_gid )
            Groups._put( l3_msg.group_id )

            # add vlan flow table
            add_one_egress_vlan_tpid_table_flow( self.controller, out_port, outer_vlan+0x1000 )
            do_barrier( self.controller )

            ip_src = '192.168.5.5'
            ip_dst = '192.168.0.1'
            parsed_pkt = simple_tcp_packet( pktlen=100,
                                            dl_vlan_enable=False,
                                            eth_dst=input_dst_mac_str,
                                            eth_src=input_src_mac_str,
                                            ip_ttl=64,
                                            ip_src=ip_src,
                                            ip_dst=ip_dst )
            pkt = str( parsed_pkt )

            print("Input Packet %s" % format_packet(pkt))

            self.dataplane.send( port, pkt )

            # build expect packet
            exp_pkt = simple_tcp_packet_two_vlan( pktlen=108,
                                                  out_dl_vlan_enable=True,
                                                  out_vlan_vid=outer_vlan,
                                                  out_vlan_tpid=0x88a8,
                                                  in_dl_vlan_enable=True,
                                                  in_vlan_vid=inner_vlan,
                                                  eth_dst=output_dst_mac_str,
                                                  eth_src=input_dst_mac_str,
                                                  ip_ttl=63,
                                                  ip_src=ip_src,
                                                  ip_dst=ip_dst )
            pkt = str( exp_pkt )

            print("Expected Packet %s" % format_packet(pkt))

            verify_packet( self, pkt, out_port )
            verify_no_other_packets( self )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class _MplsFwdInterfaceProblem_PW( base_tests.SimpleDataPlane ):
    """
    Reproduces the pseudowire bug with the wrongly set destination mac address.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return

            macs_to_test = [( [ 0x00, 0x00, 0x00, 0x11, 0x11, 0x00 ], [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ],  '00:00:00:11:11:00',  '00:00:00:22:22:00'),
                            ( [ 0x00, 0x00, 0x00, 0x11, 0x22, 0x00 ], [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ],  '00:00:00:11:22:00',  '00:00:00:33:33:00'),
                            ( [ 0x00, 0x00, 0x00, 0x11, 0x33, 0x00 ], [ 0x00, 0x00, 0x00, 0x44, 0x44, 0x00 ],  '00:00:00:11:33:00',  '00:00:00:44:44:00'),
                            ( [ 0x00, 0x00, 0x00, 0x11, 0x44, 0x00 ], [ 0x00, 0x00, 0x00, 0x55, 0x55, 0x00 ],  '00:00:00:11:44:00',  '00:00:00:55:55:00'),
                            ( [ 0x00, 0x00, 0x00, 0x11, 0x55, 0x00 ], [ 0x00, 0x00, 0x00, 0x66, 0x66, 0x00 ],  '00:00:00:11:55:00',  '00:00:00:66:66:00')]

            for dummy_dst_mac, dst_mac, mac_dst_dummy, mac_dst in macs_to_test:

                dip = 0xc0a80001
                intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]

                out_port = 12
                port = 24
                # Shift MPLS label and VLAN ID by 16 to avoid reserved values
                vlan_id = port + 16
                mpls_label = port + 16

                in_port = 24
                ip_src = '192.168.%02d.1' % (in_port)

                # create dummy groups
                id = port
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, out_port, vlan_id, False, False)
                mpls_gid, mpls_msg = add_mpls_intf_group( self.controller, l2_gid, dummy_dst_mac, intf_src_mac,
                       vlan_id, id, send_barrier=True)
                do_barrier( self.controller )

                # PW Case.
                raw_input("Press anything to move on with pseudowire rules, after that you should see the updated groups in the switch.")
                logging.info("Installing entries for pseudowire!")
                switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
                mpls_label      = 100
                mpls_label_SR2 = 100 + 10
                mpls_label_PW = 100 + 15

                print("Install MPLS intf group for dst mac {0}", dst_mac)
                # add MPLS interface group
                mpls_intf_gid, mpls_intf_msg = add_mpls_intf_group(
                    ctrl=self.controller,
                    ref_gid=l2_gid,
                    dst_mac=dst_mac,
                    src_mac=intf_src_mac,
                    vid=vlan_id,
                    index=id,
                    add=False,
                    send_barrier=True
                    )

                # add MPLS flow with BoS=0
                add_mpls_flow_pw(
                    ctrl=self.controller,
                    action_group_id=mpls_intf_gid,
                    label=mpls_label_SR2,
                    ethertype=0x8847,
                    tunnel_index=1,
                    bos=0
                    )

                # add Termination flow
                add_termination_flow(
                    ctrl=self.controller,
                    in_port=in_port,
                    eth_type=0x8847,
                    dst_mac=intf_src_mac,
                    vlanid=vlan_id,
                    goto_table=23
                    )

                # add VLAN flows
                add_one_vlan_table_flow(
                    ctrl=self.controller,
                    of_port=in_port,
                    vlan_id=vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_TAG,
                    )
                add_one_vlan_table_flow(
                    ctrl=self.controller,
                    of_port=in_port,
                    vlan_id=vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                    )
                # Packet generation with sleep
                time.sleep(2)
                label_SR2 = (mpls_label_SR2, 0, 0, 32)
                label_2 = (mpls_label_PW, 0, 1, 32)

                # set to false to test if routing traffic
                # comes through
                raw_input("Press enter to send the packet, inspect the groups in the switch!")
                print("Sending packet with dst mac {0} and labels {1}".format(switch_mac, [label_SR2, label_2]))
                parsed_pkt = mpls_packet(
                    pktlen=104,
                    ip_ttl=63,
                    label=[label_SR2, label_2],
                    encapsulated_ethernet = True,
                    eth_dst=switch_mac
                )

                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                expected_label = (mpls_label_PW, 0, 1, 31)
                print("Expecting packet with dst mac {0} and labels {1}".format(mac_dst, [label_2]))
                parsed_pkt =  mpls_packet(
                    pktlen=100,
                    ip_ttl=63,
                    eth_dst=mac_dst,
                    eth_src=switch_mac,
                    label=[ expected_label ],
                    encapsulated_ethernet = True
                )

                pkt = str( parsed_pkt )
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )

                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_all_groups( self.controller )

        finally:
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_all_groups( self.controller )


class VlanCrossConnect ( base_tests.SimpleDataPlane ):
    """
    Tries the cross connect functionality of the ofdpa switches.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            # each entry represents a subscriber [id, ip in hex, inner_vlan, outer_vlan, ip in dot form]
            subscriber_info = [ [10, 0xc0a80001, 12, 11, "192.168.0.1"] ]

            index = 5
            for sub_info in subscriber_info:

                #print("Initializing rules for subscriber with id {0}".format(sub_info[0]))

                input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, sub_info[0] ]
                input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

                input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
                input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

                output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
                output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

                dip = sub_info[1]
                ports = config[ "port_map" ].keys( )

                inner_vlan = sub_info[2]
                outer_vlan = sub_info[3]

                index = inner_vlan

                port = ports[0]
                out_port = ports[1]

                # add l2 interface group, uncomment for unfiltered
                l2_gid, l2_msg = add_one_l2_interface_group( self.controller, out_port, outer_vlan, True, True)
                #i l2_gid, l2_msg = add_one_l2_unfiltered_group( self.controller, out_port, 1, True)

                # add vlan flow table
                add_one_vlan_table_flow( self.controller, port, inner_vlan, outer_vlan, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_STACKED )
                add_one_vlan_1_table_flow_pw( self.controller, port, index, new_outer_vlan_id=outer_vlan ,outer_vlan_id=outer_vlan, inner_vlan_id=inner_vlan, cross_connect=True, send_barrier=True)
                add_mpls_l2_port_flow(ctrl=self.controller, of_port=port, mpls_l2_port=port, tunnel_index=index, ref_gid=l2_gid, qos_index=0, goto=ACL_FLOW_TABLE)
                index += 1

                Groups._put( l2_gid )
                do_barrier( self.controller )

            for sub_info in subscriber_info:
                #print("Sending packet for subscriber with id {0}".format(sub_info[0]))
                input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, sub_info[0] ]
                input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )

                input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
                input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )

                dip = sub_info[1]
                ports = config[ "port_map" ].keys( )

                inner_vlan = sub_info[2]
                outer_vlan = sub_info[3]

                port = ports[0]
                out_port = ports[1]

                ip_src = sub_info[4]
                ip_dst = '192.168.0.{}'.format(sub_info[0])
                parsed_pkt = qinq_tcp_packet( pktlen=120, vlan_vid=inner_vlan, dl_vlan_outer=outer_vlan,
                        eth_dst=input_dst_mac_str, eth_src=input_src_mac_str, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
                parsed_pkt = simple_tcp_packet_two_vlan( pktlen=120, out_dl_vlan_enable=True, in_dl_vlan_enable=True, in_vlan_vid=inner_vlan, out_vlan_vid=outer_vlan,
                        eth_dst=input_dst_mac_str, eth_src=input_src_mac_str, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )

                pkt = str( parsed_pkt )

                self.dataplane.send( port, pkt )
                verify_packet( self, pkt, out_port )
                verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


@disabled
class Lag( base_tests.SimpleDataPlane ):
    """
    Checks the L2 load balancing (LAG) functionality of the ofdpa switches.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted(config[ "port_map" ].keys( ))
            in_port = ports[0]
            out_port = ports[1]

            # add l2 interface unfiltered group
            l2_o_gid, l2_o_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            # create l2 load-balance group
            lag_gid, lag_msg = add_l2_loadbal_group(self.controller, 1, [l2_o_gid], True)
            Groups.put(l2_o_gid, lag_gid)

            # --- TEST 1: bridging with load-bal----
            vlan_in_port_untagged = 31
            # table 10 flows and bridging flows for dstMac+vlan -> l2-load-bal group
            add_one_vlan_table_flow( self.controller, in_port, vlan_id=vlan_in_port_untagged, flag=VLAN_TABLE_FLAG_ONLY_BOTH,
                                     send_barrier=True)
            mac_dst = [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 ]
            mac_dst_str = '00:11:22:33:44:55'
            add_bridge_flow( self.controller, mac_dst, vlan_in_port_untagged, lag_gid, True )
            # untagged packet input becomes tagged packet at output
            time.sleep(0.1)
            pkt = str( simple_tcp_packet( pktlen=80, eth_dst=mac_dst_str ) )
            exp_pkt = str( simple_tcp_packet( pktlen=84, dl_vlan_enable=True, vlan_vid=vlan_in_port_untagged, eth_dst=mac_dst_str ) )
            self.dataplane.send( in_port, pkt )
            verify_packet( self, exp_pkt, out_port )
            verify_no_other_packets( self )

            # --- TEST 2: flooding with load-bal ----
            # flooding group --> load-bal group --> l2 unfiltered interface
            floodmsg = add_l2_flood_group_with_gids( self.controller, [lag_gid] , vlan_in_port_untagged, id=0 )
            Groups.put( floodmsg.group_id )
            # add bridging flows for flooding groups
            add_bridge_flow( self.controller, dst_mac=None, vlanid=vlan_in_port_untagged, group_id=floodmsg.group_id )
            # unknown dstmac  packet input to hit flood group
            un_mac_dst_str = '00:11:22:ff:ff:ff'
            pkt = str( simple_tcp_packet( pktlen=80, eth_dst=un_mac_dst_str ) )
            exp_pkt = str( simple_tcp_packet( pktlen=84, dl_vlan_enable=True, vlan_vid=vlan_in_port_untagged, eth_dst=un_mac_dst_str ) )
            time.sleep(0.1)
            self.dataplane.send( in_port, pkt )
            verify_packet( self, exp_pkt, out_port )
            verify_no_other_packets( self )

            # --- TEST 3: editing load-bal ----
            # create and add another l2 unfiltered interface group to the load-balancing group
            l2_i_gid, l2_i_msg = add_one_l2_unfiltered_group( self.controller, in_port, True)
            msg = mod_l2_loadbal_group(self.controller, 1, [l2_o_gid, l2_i_gid], True)
            self.dataplane.send( in_port, pkt )
            verify_packet( self, exp_pkt, out_port )

            # delete all buckets in loadbal group
            msg = mod_l2_loadbal_group(self.controller, 1, [], True)
            time.sleep(0.1)
            self.dataplane.send( in_port, pkt )
            verify_no_other_packets( self ) # no buckets

            # only input port in load balancing group
            msg = mod_l2_loadbal_group(self.controller, 1, [l2_i_gid], True)
            self.dataplane.send( in_port, pkt )
            verify_no_other_packets( self ) # packet should not be sent out of in port

            # remove input port and add output port in lag group
            msg = mod_l2_loadbal_group(self.controller, 1, [l2_o_gid], True)
            time.sleep(0.1)
            self.dataplane.send( in_port, pkt )
            verify_packet( self, exp_pkt, out_port )
            verify_no_other_packets( self )

        finally:
            #print("done")
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class FloodLb( base_tests.SimpleDataPlane ):
    """
    Checks L2 flood group pointing to L2 load balance group with 2 buckets (unfiltered).
    The packet from in_port should not be seen on the out_port
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted(config[ "port_map" ].keys( ))
            in_port = ports[0]
            out_port = ports[1]
            vlan_in_port_untagged = 31

            # add l2 unfiltered interface group for outport
            l2_i_gid, l2_i_msg = add_one_l2_unfiltered_group( self.controller, in_port, True)
            l2_o_gid, l2_o_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            # create l2 load-balance group
            lag_gid, lag_msg = add_l2_loadbal_group(self.controller, 1, [l2_i_gid, l2_o_gid], True)

            # create l2 flood group with mix of l2i and l2-loadbal
            floodmsg = add_l2_flood_group_with_gids( self.controller, [lag_gid] , vlan_in_port_untagged, id=0, send_barrier=True )
            Groups.put( l2_i_gid )
            Groups.put( l2_o_gid )
            Groups.put( lag_gid )
            Groups.put( floodmsg.group_id )

            # table 10 flows for untagged input
            add_one_vlan_table_flow( self.controller, in_port, vlan_id=vlan_in_port_untagged, flag=VLAN_TABLE_FLAG_ONLY_BOTH,
                                     send_barrier=True)
            add_one_vlan_table_flow( self.controller, out_port, vlan_id=vlan_in_port_untagged, flag=VLAN_TABLE_FLAG_ONLY_BOTH,
                                     send_barrier=True)

            # add bridging flows for flooding groups
            add_bridge_flow( self.controller, dst_mac=None, vlanid=vlan_in_port_untagged, group_id=floodmsg.group_id )
            # unknown dstmac packet will hit flood group
            un_mac_dst_str = '00:11:22:ff:ff:ff'

            # check one direction -> packet enters through inport should not be seen on the outport
            pkt = str( simple_tcp_packet( pktlen=80, eth_dst=un_mac_dst_str ) )
            self.dataplane.send( in_port, pkt )
            verify_no_other_packets( self )

            # check other direction -> packet enters through outport should not be seen on the inport
            pkt = str( simple_tcp_packet( pktlen=80, eth_dst=un_mac_dst_str ) )
            self.dataplane.send( out_port, pkt )
            verify_no_other_packets( self )

        finally:
            #print("done")
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class FloodMixUntagged( base_tests.SimpleDataPlane ):
    """
    Checks the combination of L2 filtered and L2 load balancing (LAG) groups
    in a flooding group
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted(config[ "port_map" ].keys( ))
            in_port = ports[0]
            out_port = ports[1]
            vlan_in_port_untagged = 31

            # add l2 unfiltered interface group for outport
            l2_o_gid, l2_o_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            # create l2 load-balance group
            lag_gid, lag_msg = add_l2_loadbal_group(self.controller, 1, [l2_o_gid], True)

            # create l2 interface (filtered) group for inport
            l2_i_gid, l2_i_msg = add_one_l2_interface_group( self.controller, in_port, vlan_in_port_untagged,
                                                             is_tagged=False, send_barrier=True)

            # create l2 flood group with mix of l2i and l2-loadbal
            floodmsg = add_l2_flood_group_with_gids( self.controller, [lag_gid, l2_i_gid] , vlan_in_port_untagged, id=0 )
            Groups.put( l2_o_gid )
            Groups.put( lag_gid )
            Groups.put( l2_i_gid )
            Groups.put( floodmsg.group_id )

            # table 10 flows for untagged input
            add_one_vlan_table_flow( self.controller, in_port, vlan_id=vlan_in_port_untagged, flag=VLAN_TABLE_FLAG_ONLY_BOTH,
                                     send_barrier=True)

            # add bridging flows for flooding groups
            add_bridge_flow( self.controller, dst_mac=None, vlanid=vlan_in_port_untagged, group_id=floodmsg.group_id )
            # unknown dstmac packet will hit flood group
            un_mac_dst_str = '00:11:22:ff:ff:ff'

            # check one direction -> packet enters through filtered port (inport) and exits through
            # unfiltered port (outport) via the flood and lag groups
            pkt = str( simple_tcp_packet( pktlen=80, eth_dst=un_mac_dst_str ) )
            exp_pkt = str( simple_tcp_packet( pktlen=84, dl_vlan_enable=True, vlan_vid=vlan_in_port_untagged, eth_dst=un_mac_dst_str ) )
            self.dataplane.send( in_port, pkt )
            verify_packet( self, exp_pkt, out_port )
            verify_no_other_packets( self )

            # check other direction -> packet enters through unfiltered port (outport) and exits through
            # filtered port (inport) via the flood group
            add_one_vlan_table_flow( self.controller, out_port, vlan_id=vlan_in_port_untagged, flag=VLAN_TABLE_FLAG_ONLY_BOTH,
                                     send_barrier=True)
            pkt = str( simple_tcp_packet( pktlen=80, eth_dst=un_mac_dst_str ) )
            exp_pkt = pkt # ingress packet gets internal vlan 31 which gets popped at l2 interface group before egress
            self.dataplane.send( out_port, pkt )
            verify_packet( self, exp_pkt, in_port )
            verify_no_other_packets( self )

        finally:
            print("done")
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class FloodMixTagged( base_tests.SimpleDataPlane ):
    """
    Checks the combination of L2 filtered and L2 load balancing (LAG) groups
    in a flooding group
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted(config[ "port_map" ].keys( ))
            in_port = ports[0]
            out_port = ports[1]
            vlan_in_port_untagged = 31

            # add l2 unfiltered interface group for outport
            l2_o_gid, l2_o_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            # create l2 load-balance group
            lag_gid, lag_msg = add_l2_loadbal_group(self.controller, 1, [l2_o_gid], True)

            # create l2 interface (filtered) group for inport
            l2_i_gid, l2_i_msg = add_one_l2_interface_group( self.controller, in_port, vlan_in_port_untagged,
                                                             is_tagged=True, send_barrier=True)

            # create l2 flood group with mix of l2i and l2-loadbal
            floodmsg = add_l2_flood_group_with_gids( self.controller, [lag_gid, l2_i_gid] , vlan_in_port_untagged, id=0 )
            Groups.put( l2_o_gid )
            Groups.put( lag_gid )
            Groups.put( l2_i_gid )
            Groups.put( floodmsg.group_id )

            # table 10 flows for tagged in_port. Note: VLAN in table 10 must be wildcarded for an unfiltered port
            add_vlan_table_flow_allow_all_vlan(self.controller, in_port, send_barrier=True)

            # add bridging flows for flooding groups
            add_bridge_flow( self.controller, dst_mac=None, vlanid=vlan_in_port_untagged, group_id=floodmsg.group_id )
            # unknown dstmac packet will hit flood group
            un_mac_dst_str = '00:11:22:ff:ff:ff'

            # check one direction -> packet enters through unfiltered port (inport) and exits through
            # unfiltered port (outport) via the flood and lag groups
            pkt = str( simple_tcp_packet( pktlen=80, dl_vlan_enable=True, vlan_vid=vlan_in_port_untagged, eth_dst=un_mac_dst_str ) )
            exp_pkt = pkt
            self.dataplane.send( in_port, pkt )
            verify_packet( self, exp_pkt, out_port )
            verify_no_other_packets( self )

            # check other direction -> packet enters through unfiltered port (outport) and exits through
            # unfiltered port (inport) via the flood group

            # table 10 flows for tagged out_port. Note: VLAN must be wildcarded for an unfiltered port
            add_vlan_table_flow_allow_all_vlan(self.controller, out_port, send_barrier=True)
            pkt = str( simple_tcp_packet( pktlen=80, dl_vlan_enable=True, vlan_vid=vlan_in_port_untagged, eth_dst=un_mac_dst_str ) )
            exp_pkt = pkt
            self.dataplane.send( out_port, pkt )
            verify_packet( self, exp_pkt, in_port )
            verify_no_other_packets( self )

        finally:
            print("done")
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class LagMix( base_tests.SimpleDataPlane ):
    """
    Checks the combination of L2 filtered and unfiltered interface groups
    in a L2 load balancing (LAG) group - this should not work according to spec
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted(config[ "port_map" ].keys( ))
            in_port = ports[0]
            out_port = ports[1]
            vlan_in_port_untagged = 31

            # add l2 unfiltered interface group
            l2_o_gid, l2_o_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            # create  l2 interface (filtered) group
            l2_i_gid, l2_i_msg = add_one_l2_interface_group( self.controller, in_port, vlan_in_port_untagged,
                                                             is_tagged=False, send_barrier=True)

            # create l2 load-balance group with a mix of filtered and unfiltered groups
            """
            XXX the following does not work - the group does not get created but curiously we don't get an openflow
            error message. The ofdpa logs show
            ofdbGroupBucketValidate: Referenced Group Id 0x1f000c not of type L2 Unfiltered Interface.
            We do get an openflow error message for the flood group that follows because it cannot
            find the lag group it points to (because it did not get created).
            """
            lag_gid, lag_msg = add_l2_loadbal_group(self.controller, 1, [l2_o_gid, l2_i_gid], True)

            # create l2 flood group to point to lag group
            floodmsg = add_l2_flood_group_with_gids( self.controller, [lag_gid] , vlan_in_port_untagged, id=0 )
            Groups.put( floodmsg.group_id, l2_i_gid, lag_gid )
            Groups.put( l2_o_gid )

        finally:
            #print("done")
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )


@disabled
class LagXconn( base_tests.SimpleDataPlane ):
    """
    Checks the L2 load balancing (LAG) with vlan crossconnects.
    Note that for this to work, basic VlanCrossConnect test above (without LAG) should work first
    Note: this doesn't work on XGS or QMX yet with premium 1.1.7
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted(config[ "port_map" ].keys( ))
            in_port = ports[0]
            out_port = ports[1]

            # add l2 interface unfiltered group
            l2_o_gid, l2_o_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            # create l2 load-balance group
            lag_gid, lag_msg = add_l2_loadbal_group(self.controller, 1, [l2_o_gid], True)
            Groups.put(l2_o_gid, lag_gid)

            # a subscriber [id, ip in hex, inner_vlan, outer_vlan, ip in dot form]
            sub_info = [10, 0xc0a80001, 12, 11, "192.168.0.1"]

            input_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, sub_info[0] ]
            input_src_mac_str = ':'.join( [ '%02X' % x for x in input_src_mac ] )
            input_dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            input_dst_mac_str = ':'.join( [ '%02X' % x for x in input_dst_mac ] )
            output_dst_mac = [ 0x00, 0x00, 0x00, 0x33, 0x33, 0x00 ]
            output_dst_mac_str = ':'.join( [ '%02X' % x for x in output_dst_mac ] )

            dip = sub_info[1]
            ports = config[ "port_map" ].keys( )
            inner_vlan = sub_info[2]
            outer_vlan = sub_info[3]
            index = inner_vlan
            port = ports[0]
            out_port = ports[1]

            # add vlan flow table
            add_one_vlan_table_flow( self.controller, port, inner_vlan, outer_vlan, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_STACKED )
            add_one_vlan_1_table_flow_pw( self.controller, port, index, new_outer_vlan_id=outer_vlan, outer_vlan_id=outer_vlan,
                                          inner_vlan_id=inner_vlan, cross_connect=True, send_barrier=True)
            """
            XXX The following flow in table 13 is rejected by the switch (qmx) probably due to the reference to lag group
            ofdpa logs say: 08-22 00:43:10.344338 [ofstatemanager] Error from Forwarding while inserting flow: Unknown error
            """
            add_mpls_l2_port_flow(ctrl=self.controller, of_port=port, mpls_l2_port=port, tunnel_index=index, ref_gid=lag_gid,
                                  qos_index=0, goto=ACL_FLOW_TABLE)
            do_barrier( self.controller )

            ip_src = sub_info[4]
            ip_dst = '192.168.0.{}'.format(sub_info[0])
            parsed_pkt = qinq_tcp_packet( pktlen=120, vlan_vid=inner_vlan, dl_vlan_outer=outer_vlan,
                                          eth_dst=input_dst_mac_str, eth_src=input_src_mac_str, ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )
            parsed_pkt = simple_tcp_packet_two_vlan( pktlen=120, out_dl_vlan_enable=True, in_dl_vlan_enable=True,
                                                     in_vlan_vid=inner_vlan, out_vlan_vid=outer_vlan,
                                                     eth_dst=input_dst_mac_str, eth_src=input_src_mac_str,
                                                     ip_ttl=64, ip_src=ip_src, ip_dst=ip_dst )

            pkt = str( parsed_pkt )
            self.dataplane.send( port, pkt )
            verify_packet( self, pkt, out_port )
            verify_no_other_packets( self )

        finally:
            #print("done")
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

@disabled
class LagRouting( base_tests.SimpleDataPlane ):
    """
    Checks the L2 load balancing (LAG) with routing flows.
    Specifically route -> L3Unicast -> Lag -> L2 Unfiltered interface
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted(config[ "port_map" ].keys( ))
            in_port = ports[0]
            out_port = ports[1]

            # add l2 interface unfiltered group
            l2_o_gid, l2_o_msg = add_one_l2_unfiltered_group( self.controller, out_port, True)

            # create l2 load-balance group
            lag_gid, lag_msg = add_l2_loadbal_group(self.controller, 1, [l2_o_gid], True)
            Groups.put(l2_o_gid, lag_gid)

            intf_src_mac = [ 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc ]
            dst_mac = [ 0x00, 0x00, 0x00, 0x22, 0x22, 0x00 ]
            dip = 0xc0a80001
            vlan_id = 31

            # create L3 Unicast group to point to Lag group
            l3_msg = add_l3_unicast_group( self.controller, out_port, vlanid=vlan_id, id=vlan_id,
                                           src_mac=intf_src_mac, dst_mac=dst_mac, gid=lag_gid )
            # add vlan flow table
            add_one_vlan_table_flow( self.controller, in_port, 1, vlan_id, flag=VLAN_TABLE_FLAG_ONLY_TAG )
            # add termination flow
            if config["switch_type"] == "qmx":
                add_termination_flow( self.controller, 0, 0x0800, intf_src_mac, vlan_id )
            else:
                add_termination_flow( self.controller, in_port, 0x0800, intf_src_mac, vlan_id )
            # add unicast routing flow
            add_unicast_routing_flow( self.controller, 0x0800, dip, 0xffffffff, l3_msg.group_id )

            Groups.put( l3_msg.group_id )
            do_barrier( self.controller )

            switch_mac = ':'.join( [ '%02X' % x for x in intf_src_mac ] )
            mac_src = '00:00:00:22:22:%02X' % (in_port)
            ip_src = '192.168.0.2'
            ip_dst = '192.168.0.1'
            parsed_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True,
                                            vlan_vid=vlan_id, eth_dst=switch_mac, eth_src=mac_src, ip_ttl=64,
                                            ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( parsed_pkt )
            self.dataplane.send( in_port, pkt )
            # build expected packet
            mac_dst = '00:00:00:22:22:00'
            exp_pkt = simple_tcp_packet( pktlen=100, dl_vlan_enable=True,
                                         vlan_vid=vlan_id, eth_dst=mac_dst, eth_src=switch_mac, ip_ttl=63,
                                         ip_src=ip_src, ip_dst=ip_dst )
            pkt = str( exp_pkt )
            verify_packet( self, pkt, out_port )
            verify_no_other_packets( self )

        finally:
            #print("done")
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )
