
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
from oftest.testutils import *
from accton_util import *
from utils import *

MAX_INTERNAL_VLAN = 4094

class L2ForwardingStackedVLAN( base_tests.SimpleDataPlane ):
    """
        Verify the proper operation of the pipeline part which includes VLAN table
        and VLAN 1 table. This is necessary for classify packets in VPWS

        One rules is necessary in VLAN table (10):
        1)  inPort = 12 (Physical)  vlanId:mask = 0x1ff2:0x1fff (VLAN 4082) |
            GoTo = 11 (VLAN 1) popVlanAction ovid = 8178 |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 1

        One rules is necessary in VLAN 1 table (11):
        2)  inPort = 12 (Physical)  vlanId = 0x1f8e (VLAN 3982) ovid = 0x1ff2 (VLAN 4082) |
            GoTo = 20 (Termination MAC) newTpid2 = 0x8100 newVlanId2 = 0x1ff2 (VLAN 4082) |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 2

        In this test case outer_vlan_id = (MAX_INTERNAL_VLAN - port_no) and
        inner_vlan_id = (MAX_INTERNAL_VLAN - 100 - port_no)
        The remaining part of the test is based on the use of the bridging table
    """

    def runTest( self ):
        groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 2:
                logging.info( "Port count less than 2, can't run this case" )
                return

            ports = sorted( config[ "port_map" ].keys( ) )
            for in_port in ports:
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                add_one_vlan_table_flow(
                    self.controller,
                    in_port,
                    vlan_id=outer_vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_STACKED
                    )
                add_one_vlan_1_table_flow(
                    self.controller,
                    in_port,
                    new_outer_vlan_id=-1,
                    outer_vlan_id=outer_vlan_id,
                    inner_vlan_id=inner_vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_TAG
                    )
                for out_port in ports:
                    if out_port == in_port:
                        continue
                    L2gid, l2msg = add_one_l2_interface_group(
                        self.controller,
                        out_port,
                        outer_vlan_id,
                        True,
                        False
                        )
                    groups.put( L2gid )
                    add_bridge_flow(
                        self.controller,
                        [ 0x00, 0x12, 0x34, 0x56, 0x78, in_port ],
                        outer_vlan_id,
                        L2gid,
                        True
                        )

            do_barrier( self.controller )

            for in_port in ports:
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                mac_dst = '00:12:34:56:78:%02X' % in_port

                parsed_pkt = simple_tcp_packet_two_vlan(
                        pktlen=108,
                        out_dl_vlan_enable=True,
                        out_vlan_vid=outer_vlan_id,
                        in_dl_vlan_enable=True,
                        in_vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                # change dest based on port number
                for out_port in ports:
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, groups )
            delete_all_groups( self.controller )

class L2ForwardingStackedVLAN2( base_tests.SimpleDataPlane ):
    """
        Verify the proper operation of the pipeline part which includes VLAN table
        and VLAN 1 table. This is necessary for classify packets in VPWS. In this test
        case we verify the change of outer vlan VLAN 1 table.

        One rules is necessary in VLAN table (10):
        1)  inPort = 12 (Physical)  vlanId:mask = 0x1ff2:0x1fff (VLAN 4082) |
            GoTo = 11 (VLAN 1) popVlanAction ovid = 8178 |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 1

        One rules is necessary in VLAN 1 table (11):
        2)  inPort = 12 (Physical)  vlanId = 0x1f8e (VLAN 3982) ovid = 0x1ff2 (VLAN 4082) |
            GoTo = 20 (Termination MAC) newTpid2 = 0x8100 newVlanId2 = 0x1f2a (VLAN 3882) |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 2

        In this test case:
        1) outer_vlan_id = (MAX_INTERNAL_VLAN - port_no)
        2) inner_vlan_id = (MAX_INTERNAL_VLAN - 100 - port_no)
        3) new_outer_vlan_id = (MAX_INTERNAL_VLAN - 200 - port_no)

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
            for in_port in ports:
                new_outer_vlan_id = MAX_INTERNAL_VLAN  - 200 - in_port
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                add_one_vlan_table_flow(
                    self.controller,
                    in_port,
                    vlan_id=outer_vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_STACKED
                    )
                add_one_vlan_1_table_flow(
                    self.controller,
                    in_port,
                    new_outer_vlan_id=new_outer_vlan_id,
                    outer_vlan_id=outer_vlan_id,
                    inner_vlan_id=inner_vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_TAG
                    )
                for out_port in ports:
                    if out_port == in_port:
                        continue
                    L2gid, l2msg = add_one_l2_interface_group(
                        self.controller,
                        out_port,
                        new_outer_vlan_id,
                        True,
                        False
                        )
                    groups.put( L2gid )
                    add_bridge_flow(
                        self.controller,
                        [ 0x00, 0x12, 0x34, 0x56, 0x78, in_port ],
                        new_outer_vlan_id,
                        L2gid,
                        True
                        )

            do_barrier( self.controller )

            for in_port in ports:
                new_outer_vlan_id = MAX_INTERNAL_VLAN  - 200 - in_port
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                mac_dst = '00:12:34:56:78:%02X' % in_port

                parsed_pkt = simple_tcp_packet_two_vlan(
                        pktlen=108,
                        out_dl_vlan_enable=True,
                        out_vlan_vid=outer_vlan_id,
                        in_dl_vlan_enable=True,
                        in_vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                # change dest based on port number
                for out_port in ports:
                    parsed_pkt = simple_tcp_packet_two_vlan(
                        pktlen=108,
                        out_dl_vlan_enable=True,
                        out_vlan_vid=new_outer_vlan_id,
                        in_dl_vlan_enable=True,
                        in_vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, groups )
            delete_all_groups( self.controller )

class L2ForwardingStackedVLAN3( base_tests.SimpleDataPlane ):
    """
        Verify the proper operation of the pipeline part which includes VLAN table.
        This is necessary for classify packets in VPWS. In this test
        case we verify the change of outer vlan pushing another vlan in VLAN table.

        One rules is necessary in VLAN table (10):
        1)  inPort = 12 (Physical)  vlanId:mask = 0x1f8e:0x1fff (VLAN 3982) |
            GoTo = 20 (Termination MAC) newTpid2 = 0x8100 newVlanId2 = 0x1ff2 (VLAN 4082) |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 1

        In this test case:
        1) outer_vlan_id = (MAX_INTERNAL_VLAN - port_no)
        2) inner_vlan_id = (MAX_INTERNAL_VLAN - 100 - port_no)

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
            for in_port in ports:
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                add_vlan_table_flow_pvid(
                    self.controller,
                    in_port,
                    match_vid=inner_vlan_id,
                    pvid=outer_vlan_id,
                    send_barrier=True
                    )
                for out_port in ports:
                    if out_port == in_port:
                        continue
                    L2gid, l2msg = add_one_l2_interface_group(
                        self.controller,
                        out_port,
                        outer_vlan_id,
                        True,
                        False
                        )
                    groups.put( L2gid )
                    add_bridge_flow(
                        self.controller,
                        [ 0x00, 0x12, 0x34, 0x56, 0x78, in_port ],
                        outer_vlan_id,
                        L2gid,
                        True
                        )

            do_barrier( self.controller )

            for in_port in ports:
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                mac_dst = '00:12:34:56:78:%02X' % in_port

                parsed_pkt = simple_tcp_packet(
                        pktlen=108,
                        dl_vlan_enable=True,
                        vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                # change dest based on port number
                for out_port in ports:
                    parsed_pkt = simple_tcp_packet_two_vlan(
                        pktlen=112,
                        out_dl_vlan_enable=True,
                        out_vlan_vid=outer_vlan_id,
                        in_dl_vlan_enable=True,
                        in_vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, groups )
            delete_all_groups( self.controller )

class L2ForwardingStackedVLAN4( base_tests.SimpleDataPlane ):
    """
        Verify the proper operation of the pipeline part which includes VLAN table
        and VLAN 1 table. This is necessary for classify packets in VPWS. In this test
        case we verify the change of outer vlan popping the tag in VLAN 1 table.

        One rules is necessary in VLAN table (10):
        1)  inPort = 12 (Physical)  vlanId:mask = 0x1ff2:0x1fff (VLAN 4082) |
            GoTo = 11 (VLAN 1) popVlanAction ovid = 8178 |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 1

        One rules is necessary in VLAN table (11):
        1)  inPort = 12 (Physical)  vlanId = 0x1f8e (VLAN 3982) ovid = 0x1ff2 (VLAN 4082) |
            GoTo = 20 (Termination MAC) |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 2

        In this test case:
        1) outer_vlan_id = (MAX_INTERNAL_VLAN - port_no)
        2) inner_vlan_id = (MAX_INTERNAL_VLAN - 100 - port_no)

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
            for in_port in ports:
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                add_one_vlan_table_flow(
                    self.controller,
                    in_port,
                    vlan_id=outer_vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_STACKED
                    )
                add_one_vlan_1_table_flow(
                    self.controller,
                    in_port,
                    new_outer_vlan_id=-1,
                    outer_vlan_id=outer_vlan_id,
                    inner_vlan_id=inner_vlan_id,
                    flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                    )
                for out_port in ports:
                    if out_port == in_port:
                        continue
                    L2gid, l2msg = add_one_l2_interface_group(
                        self.controller,
                        out_port,
                        inner_vlan_id,
                        True,
                        False
                        )
                    groups.put( L2gid )
                    add_bridge_flow(
                        self.controller,
                        [ 0x00, 0x12, 0x34, 0x56, 0x78, in_port ],
                        inner_vlan_id,
                        L2gid,
                        True
                        )

            do_barrier( self.controller )

            for in_port in ports:
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                mac_dst = '00:12:34:56:78:%02X' % in_port

                parsed_pkt = simple_tcp_packet_two_vlan(
                        pktlen=112,
                        out_dl_vlan_enable=True,
                        out_vlan_vid=outer_vlan_id,
                        in_dl_vlan_enable=True,
                        in_vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                # change dest based on port number
                for out_port in ports:
                    parsed_pkt = simple_tcp_packet(
                        pktlen=108,
                        dl_vlan_enable=True,
                        vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, groups )
            delete_all_groups( self.controller )

class L2ForwardingStackedVLAN5( base_tests.SimpleDataPlane ):
    """
        Verify the proper operation of the pipeline part which includes VLAN table
        and VLAN 1 table. This is necessary for classify packets in VPWS. In this test
        case we verify the change of outer vlan in VLAN table.

        One rules is necessary in VLAN table (10):
        1)  inPort = 12 (Physical)  vlanId:mask = 0x1ff2:0x1fff (VLAN 4082) |
            GoTo = 20 (VLAN 1) newVlanId = 0x1f2a (VLAN 3882) |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 1

        In this test case:
        1) outer_vlan_id = (MAX_INTERNAL_VLAN - port_no)
        3) new_outer_vlan_id = (MAX_INTERNAL_VLAN - 200 - port_no)

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
            for in_port in ports:
                new_outer_vlan_id = MAX_INTERNAL_VLAN  - 200 - in_port
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                add_one_vlan_table_flow_translation(
                    self.controller,
                    in_port,
                    vlan_id=outer_vlan_id,
                    new_vlan_id=new_outer_vlan_id,
                    vrf=0,
                    flag=VLAN_TABLE_FLAG_ONLY_TAG,
                    send_barrier=False
                    )
                for out_port in ports:
                    if out_port == in_port:
                        continue
                    L2gid, l2msg = add_one_l2_interface_group(
                        self.controller,
                        out_port,
                        new_outer_vlan_id,
                        True,
                        False
                        )
                    groups.put( L2gid )
                    add_bridge_flow(
                        self.controller,
                        [ 0x00, 0x12, 0x34, 0x56, 0x78, in_port ],
                        new_outer_vlan_id,
                        L2gid,
                        True
                        )

            do_barrier( self.controller )

            for in_port in ports:
                new_outer_vlan_id = MAX_INTERNAL_VLAN  - 200 - in_port
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id =MAX_INTERNAL_VLAN - 100 - in_port
                mac_dst = '00:12:34:56:78:%02X' % in_port

                parsed_pkt = simple_tcp_packet_two_vlan(
                        pktlen=112,
                        out_dl_vlan_enable=True,
                        out_vlan_vid=outer_vlan_id,
                        in_dl_vlan_enable=True,
                        in_vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                # change dest based on port number
                for out_port in ports:
                    parsed_pkt = simple_tcp_packet_two_vlan(
                        pktlen=112,
                        out_dl_vlan_enable=True,
                        out_vlan_vid=new_outer_vlan_id,
                        in_dl_vlan_enable=True,
                        in_vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, groups )
            delete_all_groups( self.controller )

class L2ForwardingStackedVLAN6( base_tests.SimpleDataPlane ):
    """
        Verify the proper operation of the pipeline part which includes VLAN table.
        This is necessary for classify packets priority tagged. In this test
        case we verify the change of outer vlan in VLAN table.

        Two rules are necessary in VLAN table (10):
        1)  inPort = 12 (Physical)  vlanId:mask = 0x1000:0x1fff (VLAN 0) |
            GoTo = 20 (Termination MAC) newVlanId = 0x1f8e (VLAN 3982) newTpid2 = 0x8100 newVlanId2 = 0x1ff2 (VLAN 4082) |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 3
        2)  inPort = 12 (Physical)  vlanId:mask = 0x1ff2:0x1fff (VLAN 4082) |
            GoTo = 20 (Termination MAC) |
            priority = 0 hard_time = 0 idle_time = 0 cookie = 1


        In this test case:
        1) outer_vlan_id = (MAX_INTERNAL_VLAN - port_no)
        3) inner_vlan_id = (MAX_INTERNAL_VLAN - 100 - port_no)

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
            for in_port in ports:
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                add_one_vlan_table_flow(
                    ctrl=self.controller,
                    of_port=in_port,
                    vlan_id=outer_vlan_id,
                    vrf=0,
                    flag=VLAN_TABLE_FLAG_ONLY_BOTH,
                    send_barrier=False
                    )
                add_one_vlan_table_flow(
                    ctrl=self.controller,
                    of_port=in_port,
                    out_vlan_id=outer_vlan_id,
                    vlan_id=inner_vlan_id,
                    vrf=0,
                    flag=VLAN_TABLE_FLAG_PRIORITY,
                    send_barrier=False
                    )
                for out_port in ports:
                    if out_port == in_port:
                        continue
                    L2gid, l2msg = add_one_l2_interface_group(
                        self.controller,
                        out_port,
                        outer_vlan_id,
                        True,
                        False
                        )
                    groups.put( L2gid )
                    add_bridge_flow(
                        self.controller,
                        [ 0x00, 0x12, 0x34, 0x56, 0x78, in_port ],
                        outer_vlan_id,
                        L2gid,
                        True
                        )

            do_barrier( self.controller )

            for in_port in ports:
                outer_vlan_id = MAX_INTERNAL_VLAN - in_port
                inner_vlan_id = MAX_INTERNAL_VLAN - 100 - in_port
                mac_dst = '00:12:34:56:78:%02X' % in_port

                parsed_pkt = simple_tcp_packet(
                        pktlen=112,
                        dl_vlan_enable=True,
                        vlan_vid=0,
                        eth_dst=mac_dst,
                        )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )

                # change dest based on port number
                for out_port in ports:
                    parsed_pkt = simple_tcp_packet_two_vlan(
                        pktlen=116,
                        out_dl_vlan_enable=True,
                        out_vlan_vid=outer_vlan_id,
                        in_dl_vlan_enable=True,
                        in_vlan_vid=inner_vlan_id,
                        eth_dst=mac_dst,
                        )
                    pkt = str( parsed_pkt )
                    if out_port == in_port:
                        verify_no_packet( self, pkt, in_port )
                        continue
                    verify_packet( self, pkt, out_port )
                    verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, groups )
            delete_all_groups( self.controller )
