
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
import time

from oftest import config
import inspect
import logging
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *
from utils import *

class UntaggedPWInitiation_2_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives untagged to the MPLS-TP CE device, it goes out
    untagged, with a new ethernet header and 2 mpls labels.
    """
    def runTest( self ):

        Groups 	= Queue.LifoQueue( )
        Groups2	= Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=0,
                    egress_tag=EGRESS_UNTAGGED,
                    mpls_labels=1
                    )
                # we fill the pipeline for the termination
                # on the reverse path
                (
			        port_to_mpls_label_pw_x,
			        port_to_vlan_2_x,
			        port_to_vlan_1_x,
			        port_to_switch_mac_str_x,
			        Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=0
                    )
                # we send a simple tcp packet
                parsed_pkt = simple_tcp_packet(
                    pktlen=104,
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we verify the pw packet has been generated
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=130,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_1, label_pw],
                    cw=cw
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                # Flush all the rules for the next couple
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class Untagged2PWInitiation_2_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives untagged to the MPLS-TP CE device, it goes out
    tagged, with a new ethernet header and 2 mpls labels.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2	= Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=0,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=1
                    )
                # we fill the pipeline for the termination
                # on the reverse path
                (
			        port_to_mpls_label_pw_x,
			        port_to_vlan_2_x,
			        port_to_vlan_1_x,
			        port_to_switch_mac_str_x,
			        Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=0
                    )
                # we send a simple tcp packet
                parsed_pkt = simple_tcp_packet(
                    pktlen=104,
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we verify the pw packet has been generated
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=134,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

                # Flush all the rules for the next couple
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class UntaggedPWInitiation_3_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives untagged to the MPLS-TP CE device, it goes out
    untagged, with a new ethernet header and 3 mpls labels.
    """
    def runTest( self ):

        Groups 	= Queue.LifoQueue( )
        Groups2	= Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=0,
                    egress_tag=EGRESS_UNTAGGED,
                    mpls_labels=2
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
			        port_to_mpls_label_pw_x,
			        port_to_vlan_2_x,
			        port_to_vlan_1_x,
			        port_to_switch_mac_str_x,
			        Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=0
                    )
                # we generate a simple tcp packet
                parsed_pkt = simple_tcp_packet(
                    pktlen=104,
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the pw packet we expect on the out port
                label_2  = (port_to_mpls_label_2[in_port], 0, 0, 63)
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=134,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_2, label_1, label_pw],
                    cw=cw
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class Untagged2PWInitiation_3_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives untagged to the MPLS-TP CE device, it goes out
    tagged with a new ethernet header and 3 mpls labels.
    """
    def runTest( self ):

        Groups 	= Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=0,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=2
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
			        port_to_mpls_label_pw_x,
			        port_to_vlan_2_x,
			        port_to_vlan_1_x,
			        port_to_switch_mac_str_x,
			        Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=0
                    )
                # we generate a simple tcp packet
                parsed_pkt = simple_tcp_packet(
                    pktlen=104,
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the pw packet we expect on the out port
                label_2  = (port_to_mpls_label_2[in_port], 0, 0, 63)
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=138,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_2, label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                # Asserions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class TaggedPWInitiation_2_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives tagged to the MPLS-TP CE device, it goes out
    with the same tag, a new ethernet header and 2 mpls labels.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=1,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=1
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
                    port_to_mpls_label_pw_x,
                    port_to_vlan_2_x,
                    port_to_vlan_1_x,
                    port_to_switch_mac_str_x,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=1
                    )
                # we generate a simple tcp packet tagged
                parsed_pkt = simple_tcp_packet(
                    pktlen=104,
                    dl_vlan_enable=True,
                    vlan_vid=port_to_in_vlan_1[in_port]
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected pw packet
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=130,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class Tagged2PWInitiation_2_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives tagged to the MPLS-TP CE device, it goes out
    with a different vlan, with a new ethernet header and 2 mpls labels.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=1,
                    egress_tag=EGRESS_TAGGED_TRANS,
                    mpls_labels=1
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
                    port_to_mpls_label_pw_x,
                    port_to_vlan_2_x,
                    port_to_vlan_1_x,
                    port_to_switch_mac_str_x,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=1
                    )
                # we generate a simple tcp packet tagged
                parsed_pkt = simple_tcp_packet(
                    pktlen=104,
                    dl_vlan_enable=True,
                    vlan_vid=port_to_in_vlan_1[in_port]
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected pw packet
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=130,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_3[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class TaggedPWInitiation_3_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives tagged to the MPLS-TP CE device, it goes out
    with the same vlan, with a new ethernet header and 3 mpls labels.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=1,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=2
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
                    port_to_mpls_label_pw_x,
                    port_to_vlan_2_x,
                    port_to_vlan_1_x,
                    port_to_switch_mac_str_x,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=1
                    )
                # we generate a simple tcp packet tagged
                parsed_pkt = simple_tcp_packet(
                    pktlen=104,
                    dl_vlan_enable=True,
                    vlan_vid=port_to_in_vlan_1[in_port]
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expect pw packet
                label_2  = (port_to_mpls_label_2[in_port], 0, 0, 63)
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=134,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_2, label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2)
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2)
            delete_all_groups( self.controller )

class Tagged2PWInitiation_3_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives tagged to the MPLS-TP CE device, it goes out
    with a different vlam, with a new ethernet header and 3 mpls labels.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=1,
                    egress_tag=EGRESS_TAGGED_TRANS,
                    mpls_labels=2
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
                    port_to_mpls_label_pw_x,
                    port_to_vlan_2_x,
                    port_to_vlan_1_x,
                    port_to_switch_mac_str_x,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=1
                    )
                # we generate a simple tcp packet tagged
                parsed_pkt = simple_tcp_packet(
                    pktlen=104,
                    dl_vlan_enable=True,
                    vlan_vid=port_to_in_vlan_1[in_port]
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expect pw packet
                label_2  = (port_to_mpls_label_2[in_port], 0, 0, 63)
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=134,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_2, label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_3[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class DoubleTaggedPWInitiation_2_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives double tagged to the MPLS-TP CE device, it goes out
    with the same outer vlan, with a new ethernet header and 2 mpls labels.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=2,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=1
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
                    port_to_mpls_label_pw_x,
                    port_to_vlan_2_x,
                    port_to_vlan_1_x,
                    port_to_switch_mac_str_x,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=2
                    )
                # we generate a simple tcp packet with two vlans
                parsed_pkt = simple_tcp_packet_two_vlan(
                    pktlen=108,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_2[in_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected pw packet
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=134,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_2[in_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class DoubleTagged2PWInitiation_2_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives double tagged to the MPLS-TP CE device and goes out
    with a new ethernet header and 2 mpls labels.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=2,
                    egress_tag=EGRESS_TAGGED_TRANS,
                    mpls_labels=1
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
                    port_to_mpls_label_pw_x,
                    port_to_vlan_2_x,
                    port_to_vlan_1_x,
                    port_to_switch_mac_str_x,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=2
                    )
                # we generate a simple tcp packet with two vlans
                parsed_pkt = simple_tcp_packet_two_vlan(
                    pktlen=108,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_2[in_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected pw packet
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=134,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_3[in_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class DoubleTaggedPWInitiation_3_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives double tagged to the MPLS-TP CE device and goes out
    with a new ethernet header and 3 mpls labels.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=2,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=2
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
                    port_to_mpls_label_pw_x,
                    port_to_vlan_2_x,
                    port_to_vlan_1_x,
                    port_to_switch_mac_str_x,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=2
                    )
                # we generate a simple tcp packet with two wlan
                parsed_pkt = simple_tcp_packet_two_vlan(
                    pktlen=108,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_2[in_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected pw packet
                label_2  = (port_to_mpls_label_2[in_port], 0, 0, 63)
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=138,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_2, label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_2[in_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class DoubleTagged2PWInitiation_3_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Initiation. The traffic
    arrives double tagged to the MPLS-TP CE device and goes out
    with a new ethernet header and 3 mpls labels.
    """
    def runTest( self ):

        Groups = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    ingress_tags=2,
                    egress_tag=EGRESS_TAGGED_TRANS,
                    mpls_labels=2
                    )
                # we fill the pipeline for the pw termination
                # on the reverse path
                (
                    port_to_mpls_label_pw_x,
                    port_to_vlan_2_x,
                    port_to_vlan_1_x,
                    port_to_switch_mac_str_x,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    egress_tags=2
                    )
                # we generate a simple tcp packet with two wlan
                parsed_pkt = simple_tcp_packet_two_vlan(
                    pktlen=108,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_2[in_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected pw packet
                label_2  = (port_to_mpls_label_2[in_port], 0, 0, 63)
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 63)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=138,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    out_eth_src=port_to_src_mac_str[out_port],
                    label=[label_2, label_1, label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_3[in_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[in_port],
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )


class IntraCO_2_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW intermediate transport.
    Incoming packet has 2 labels (SR/PW) (intermediate leaf switch).
    There is no VLAN tag in the incoming packet. Pop outer MPLS label
    """
    def runTest( self ):

        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            # we fill the pw pipeline for the intermediate transport
            (
                port_to_mpls_label_2,
                port_to_mpls_label_1,
                port_to_mpls_label_pw,
                port_to_switch_mac_str,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                Groups
            ) = fill_pw_intermediate_transport_pipeline(
                self.controller,
                logging,
                ports,
                mpls_labels=3
                )

            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we geneate the pw packet
                label_1  = (port_to_mpls_label_2[in_port], 0, 0, 32)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 32)
                parsed_pkt = mpls_packet(
                    pktlen=104,
                    ip_ttl=63,
                    eth_dst=port_to_switch_mac_str[in_port],
                    label=[ label_1, label_pw ]
                )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we geneate the expected pw packet
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 31)
                parsed_pkt = mpls_packet(
                    pktlen=100,
                    ip_ttl=63,
                    eth_dst=port_to_dst_mac_str[in_port],
                    eth_src=port_to_src_mac_str[out_port],
                    label=[ label_pw ]
                )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class IntraCO_3_Labels( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW intermediate transport.
    Incoming packet has 3 labels (SR/SR/PW) (spine switch).
    There is no VLAN tag in the incoming packet. Pop outer MPLS label
    """
    def runTest( self ):

        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            # we fill the pipeline for the intermediate transport
            (
                port_to_mpls_label_2,
                port_to_mpls_label_1,
                port_to_mpls_label_pw,
                port_to_switch_mac_str,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                Groups
            ) = fill_pw_intermediate_transport_pipeline(
                self.controller,
                logging,
                ports,
                mpls_labels=3
                )
            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we generate the pw packet
                label_2  = (port_to_mpls_label_2[in_port], 0, 0, 32)
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 32)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 32)
                parsed_pkt = mpls_packet(
                    pktlen=104,
                    ip_ttl=63,
                    eth_dst=port_to_switch_mac_str[in_port],
                    label=[ label_2, label_1, label_pw ]
                )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected pw packet
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 31)
                parsed_pkt = mpls_packet(
                    pktlen=100,
                    ip_ttl=63,
                    eth_dst=port_to_dst_mac_str[in_port],
                    eth_src=port_to_src_mac_str[out_port],
                    label=[ label_1, label_pw ]
                )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class InterCO( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW intermediate transport.
    Incoming packet has 1 labels (PW) (Intermediate CO leaf switch).
    There is no VLAN tag in the incoming packet. Push up to 2 MPLS labels
    """
    def runTest( self ):

        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            # we fill the pipeline for the intermediate transport
            (
                port_to_mpls_label_2,
                port_to_mpls_label_1,
                port_to_mpls_label_pw,
                port_to_switch_mac_str,
                port_to_src_mac_str,
                port_to_dst_mac_str,
                Groups
            ) = fill_pw_intermediate_transport_pipeline(
                self.controller,
                logging,
                ports,
                mpls_labels=1
                )
            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we generate the pw packet
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 32)
                parsed_pkt = mpls_packet(
                    pktlen=104,
                    ip_ttl=63,
                    eth_dst=port_to_switch_mac_str[in_port],
                    label=[ label_pw ]
                )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected pw packet
                label_2  = (port_to_mpls_label_2[in_port], 0, 0, 31)
                label_1  = (port_to_mpls_label_1[in_port], 0, 0, 31)
                label_pw = (port_to_mpls_label_pw[in_port], 0, 1, 31)
                parsed_pkt = mpls_packet(
                    pktlen=112,
                    ip_ttl=63,
                    eth_dst=port_to_dst_mac_str[in_port],
                    eth_src=port_to_src_mac_str[out_port],
                    label=[ label_2, label_1, label_pw ]
                )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class UntaggedPWTermination( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Termination. The traffic
    arrives untagged to the MPLS-TP CE device and goes out
    without the outer ethernet header and untagged.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                # on the reverse path
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    ingress_tags=0,
                    egress_tag=EGRESS_UNTAGGED,
                    mpls_labels=1
                    )
                # we fill the pipeline for the pw termination
                (
                    port_to_mpls_label_pw,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_dst_mac_str,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    egress_tags=0
                    )
                # we generate the pw packet
                label_pw = (port_to_mpls_label_pw[out_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=104,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    label=[label_pw],
                    cw=cw
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected tcp packet
                parsed_pkt = simple_tcp_packet(
                    pktlen=82,
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class Untagged2PWTermination( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Termination. The traffic
    arrives untagged to the MPLS-TP CE device and goes out
    without the outer ethernet header and untagged
    but was originally tagged.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            for pair in itertools.product(ports, ports):

                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue

                # we fill the pipeline for the pw initiation
                # on the reverse path

                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    ingress_tags=0,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=1
                    )
		# we fill the pipeline for the pw termination
                (
                    port_to_mpls_label_pw,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_dst_mac_str,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    egress_tags=0
                    )
                # we generate the pw packet
                label_pw = (port_to_mpls_label_pw[out_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=104,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    label=[label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_1[out_port],
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected tcp packet
                parsed_pkt = simple_tcp_packet(
                    pktlen=78,
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

		delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )
        finally:
	    delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class TaggedPWTermination( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Termination. The traffic
    arrives untagged to the MPLS-TP CE device and goes out
    without the outer ethernet header and with a vlan tag.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                # on the reverse path
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    ingress_tags=1,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=1
                    )
                # we fill the pipeline for the pw termination
                (
                    port_to_mpls_label_pw,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_dst_mac_str,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    egress_tags=1
                    )
                # we generate the pw packet
                label_pw = (port_to_mpls_label_pw[out_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=104,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    label=[label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_1[out_port],
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected tcp packet
                # with a vlan tag
                parsed_pkt = simple_tcp_packet(
                    pktlen=82,
                    dl_vlan_enable=True,
                    vlan_vid=port_to_in_vlan_1[out_port]
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class DoubleTaggedPWTermination( base_tests.SimpleDataPlane ):
    """
    This is meant to test the PW Termination. The traffic
    arrives untagged to the MPLS-TP CE device and goes out
    without the outer ethernet header and 2 vlan tags.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                # on the reverse path
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    ingress_tags=2,
                    egress_tag = EGRESS_TAGGED,
                    mpls_labels=1
                    )
                # we fill the pipeline for the pw termination
                (
                    port_to_mpls_label_pw,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_dst_mac_str,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    egress_tags=2
                    )
                # we generate the pw packet
                label_pw = (port_to_mpls_label_pw[out_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=104,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    label=[label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_2[out_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[out_port]
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected tcp
                # packet with two vlan tags
                parsed_pkt = simple_tcp_packet_two_vlan(
                    pktlen=82,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_2[out_port],
                    in_dl_vlan_enable=True,
                    in_vlan_vid=port_to_in_vlan_1[out_port]
                    )
                pkt = str( parsed_pkt )
                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )
                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )

class IntermediateTransport( base_tests.SimpleDataPlane ):
    """
    This test is meant to verify that the alternative approach for handling
    pseudowires in spine switches. Specifically, in the mpls table we install
    2 rules , the match(SR1, BoS=1) and match(SR2, BoS=0). The match(SR2, BoS=0)
    should match and the packet should be forwarded through the port and the label
    for SR2 should be removed.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports           = config[ "port_map" ].keys( )
            in_port         = ports[0]
            out_port        = ports[1]
            out_vlan        = 4094
            src_mac         = [ 0x00, 0x00, 0x00, 0x00, 0x11, 0x01 ]
            src_mac_str     = ':'.join( [ '%02X' % x for x in src_mac ] )
            dst_mac         = [ 0x00, 0x00, 0x00, 0x11, 0x11, 0x01 ]
            dst_mac_str     = ':'.join( [ '%02X' % x for x in dst_mac ] )
            mpls_label      = 100
            mpls_label_SR1 = 100 + 5
            mpls_label_SR2 = 100 + 10
            mpls_label_PW = 100 + 15

            # Add l2 interface group, we have to pop the VLAN;
            l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=out_vlan,
                is_tagged=False,
                send_barrier=False
                )
            Groups._put( l2_intf_gid )

            # add MPLS interface group
            mpls_intf_gid, mpls_intf_msg = add_mpls_intf_group(
                ctrl=self.controller,
                ref_gid=l2_intf_gid,
                dst_mac=dst_mac,
                src_mac=src_mac,
                vid=out_vlan,
                index=in_port
                )
            Groups._put( mpls_intf_gid )

            # Add L3 Unicast  group
            l3_msg = add_l3_unicast_group(
                ctrl=self.controller,
                port=out_port,
                vlanid=out_vlan,
                id=in_port,
                src_mac=src_mac,
                dst_mac=dst_mac
                )
            Groups._put( l3_msg.group_id )

            # Add L3 ecmp group
            ecmp_msg = add_l3_ecmp_group(
                ctrl=self.controller,
                id=in_port,
                l3_ucast_groups=[ l3_msg.group_id ]
                )
            Groups._put( ecmp_msg.group_id )

            # Add MPLS flow with BoS=1
            add_mpls_flow(
                ctrl=self.controller,
                action_group_id=ecmp_msg.group_id,
                label=mpls_label_SR1
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
                dst_mac=src_mac,
                vlanid=out_vlan,
                goto_table=23
                )
            # add VLAN flows
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=out_vlan,
                flag=VLAN_TABLE_FLAG_ONLY_TAG,
                )
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=out_vlan,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )
            # Packet generation with sleep
            time.sleep(2)
            label_SR1 = (mpls_label_SR1, 0, 1, 32)
            label_SR2 = (mpls_label_SR2, 0, 0, 32)
            label_2 = (mpls_label_PW, 0, 1, 32)

	    # set to false to test if routing traffic
	    # comes through

	    pw = True
            if pw:
		    parsed_pkt = mpls_packet(
			pktlen=104,
			ip_ttl=63,
			eth_dst=src_mac_str,
			label=[label_SR2, label_2],
			encapsulated_ethernet = True
		    )
		    pkt = str( parsed_pkt )
		    self.dataplane.send( in_port, pkt )


		    expected_label = (mpls_label_PW, 0, 1, 31)
		    # we geneate the expected pw packet
		    parsed_pkt =  mpls_packet(
			pktlen=100,
			ip_ttl=63,
			eth_dst=dst_mac_str,
			eth_src=src_mac_str,
			label=[ expected_label ],
			encapsulated_ethernet = True
		    )

		    pkt = str( parsed_pkt )
		    verify_packet( self, pkt, out_port )
		    verify_no_packet( self, pkt, in_port )
	    else:
		    # packet for routing traffic
		    parsed_pkt_2 = mpls_packet(
			pktlen=104,
			ip_ttl=63,
			eth_dst=src_mac_str,
			label=[ label_SR1 ]
		    )
		    pkt_2 = str(parsed_pkt_2)
		    self.dataplane.send( in_port, pkt_2 )

		    # we geneate the expected routed packet
		    parsed_pkt_2 = simple_tcp_packet(
			pktlen=100,
			ip_ttl=31,
			eth_dst=dst_mac_str,
			eth_src=src_mac_str,
		    )
		    pkt_2 = str(parsed_pkt_2)

		    verify_packet( self, pkt_2, out_port)
		    verify_no_packet( self, pkt_2, in_port )

            verify_no_other_packets( self )
        finally:

            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_all_groups( self.controller )

class PseudowireSpineTerminationBug( base_tests.SimpleDataPlane ):
    """
    This is meant to demonstrate a bug observed in the termination of
    Leaf-Spine pseudowires, where the termination point at the spine
    is a port connecting to another leaf switch.
    In this case, there exist two L2 interface groups in the device for the
    same port :

    L2 interface for routing : POP_VLAN, output to port
    L2 interface for pseudowire : outpute to port

    The choice of the l2 interface group is associated with the vlan id of the packet.
    In both cases, packets arrive with untagged vlan and are associated with vlan-id 4094.
    However, in pw case the outer l2 is popped, and the vlan-id changes (that of the original
    traffic) which matches the L2 interface group for the pw.

    The bug is that still the group that is chossen is that for routing, which pops the vlan,
    and thus the pseudowire results with untagged traffic.
    """
    def runTest( self ):

        Groups  = Queue.LifoQueue( )
        Groups2 = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports = config[ "port_map" ].keys( )
            for pair in itertools.product(ports, ports):
                # we generate all possible products
                in_port     = pair[0]
                out_port    = pair[1]
                if out_port == in_port:
                    continue
                # we fill the pipeline for the pw initiation
                # on the reverse path
                (
                    port_to_mpls_label_2,
                    port_to_mpls_label_1,
                    port_to_mpls_label_pw,
                    port_to_in_vlan_3,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_src_mac_str,
                    port_to_dst_mac_str,
                    Groups ) = fill_pw_initiation_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=out_port,
                    out_port=in_port,
                    ingress_tags=1,
                    egress_tag=EGRESS_TAGGED,
                    mpls_labels=1
                    )
                # we fill the pipeline for the pw termination
                (
                    port_to_mpls_label_pw,
                    port_to_in_vlan_2,
                    port_to_in_vlan_1,
                    port_to_dst_mac_str,
                    Groups2 ) = fill_pw_termination_pipeline(
                    controller=self.controller,
                    logging=logging,
                    in_port=in_port,
                    out_port=out_port,
                    egress_tags=1
                    )

		print('''\nBefore adding the l2 interface group that pops the vlan we expect to see tagged packets at the output. ''')

                # we generate the pw packet
                label_pw = (port_to_mpls_label_pw[out_port], 0, 1, 63)
                cw = (0, 0, 0, 0)
                parsed_pkt = pw_packet(
                    pktlen=104,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    label=[label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_1[out_port],
                    )
                pkt = str( parsed_pkt )
                self.dataplane.send( in_port, pkt )
                # we generate the expected tcp packet
                # with a vlan tag
                parsed_pkt = simple_tcp_packet(
                    pktlen=82,
                    dl_vlan_enable=True,
                    vlan_vid=port_to_in_vlan_1[out_port]
                    )
                pkt = str( parsed_pkt )

                # Assertions
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

		print('''After adding the l2 interface group that pops the vlan, packets will come out UNTAGGED and test will fail. Check logs for details.''')
	        # we create an l2 interface group for routing that
		# pops the vlan tags
            	l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(
                	ctrl=self.controller,
                	port=out_port,
                	vlan_id=4094,
                	is_tagged=False,
                	send_barrier=False
                	)
		Groups._put( l2_intf_gid )

                parsed_pkt = pw_packet(
                    pktlen=104,
                    out_eth_dst=port_to_dst_mac_str[in_port],
                    label=[label_pw],
                    cw=cw,
                    out_dl_vlan_enable=True,
                    out_vlan_vid=port_to_in_vlan_1[out_port],
                    )
                pkt = str( parsed_pkt )
		self.dataplane.send( in_port, pkt )

                parsed_pkt = simple_tcp_packet(
                    pktlen=82,
                    dl_vlan_enable=True,
                    vlan_vid=port_to_in_vlan_1[out_port]
                    )
                pkt = str( parsed_pkt )

		# send the packet, test should fail now
                verify_packet( self, pkt, out_port )
                verify_no_packet( self, pkt, in_port )
                verify_no_other_packets( self )

                delete_all_flows( self.controller )
                delete_groups( self.controller, Groups )
                delete_groups( self.controller, Groups2 )
                delete_all_groups( self.controller )
        finally:
            delete_all_flows( self.controller )
            delete_groups( self.controller, Groups )
            delete_groups( self.controller, Groups2 )
            delete_all_groups( self.controller )


class BoSBug( base_tests.SimpleDataPlane ):
    """
    This test is meant to verify the forwarding of the default traffic
    when the rule for the PW transport (BoS=0) has been installed in the
    switch, together with the rule for the transport of default routing
    traffic. There is a bug in OFDPA 3.0EA4, which requires BOS=0 flow
    to be installed before BOS=1 flow to generate correct packets. Incoming
    packet has 1 label, and there is no VLAN tag in the incoming packet.
    The expected behvior is the Pop of the outer MPLS label and plain IP
    packet should exit from the switch.
    """
    def runTest( self ):
        Groups = Queue.LifoQueue( )
        try:
            if len( config[ "port_map" ] ) < 1:
                logging.info( "Port count less than 1, can't run this case" )
                assert (False)
                return
            ports           = config[ "port_map" ].keys( )
            in_port         = ports[0]
            out_port        = ports[1]
            out_vlan        = 4094
            src_mac         = [ 0x00, 0x00, 0x00, 0x00, 0x11, 0x01 ]
            src_mac_str     = ':'.join( [ '%02X' % x for x in src_mac ] )
            dst_mac         = [ 0x00, 0x00, 0x00, 0x11, 0x11, 0x01 ]
            dst_mac_str     = ':'.join( [ '%02X' % x for x in dst_mac ] )
            mpls_label      = 100
            # Add l2 interface group, we have to pop the VLAN;
            l2_intf_gid, l2_intf_msg = add_one_l2_interface_group(
                ctrl=self.controller,
                port=out_port,
                vlan_id=out_vlan,
                is_tagged=False,
                send_barrier=False
                )
            Groups._put( l2_intf_gid )
            # add MPLS interface group
            mpls_intf_gid, mpls_intf_msg = add_mpls_intf_group(
                ctrl=self.controller,
                ref_gid=l2_intf_gid,
                dst_mac=dst_mac,
                src_mac=src_mac,
                vid=out_vlan,
                index=in_port
                )
            Groups._put( mpls_intf_gid )
            # Add L3 Unicast  group
            l3_msg = add_l3_unicast_group(
                ctrl=self.controller,
                port=out_port,
                vlanid=out_vlan,
                id=in_port,
                src_mac=src_mac,
                dst_mac=dst_mac
                )
            Groups._put( l3_msg.group_id )
            # Add L3 ecmp group
            ecmp_msg = add_l3_ecmp_group(
                ctrl=self.controller,
                id=in_port,
                l3_ucast_groups=[ l3_msg.group_id ]
                )
            Groups._put( ecmp_msg.group_id )
            # Add MPLS flow with BoS=1
            add_mpls_flow(
                ctrl=self.controller,
                action_group_id=ecmp_msg.group_id,
                label=mpls_label
                )
            # add MPLS flow with BoS=0
            add_mpls_flow_pw(
                ctrl=self.controller,
                action_group_id=mpls_intf_gid,
                label=mpls_label,
                ethertype=0x8847,
                tunnel_index=1,
                bos=0
                )
            # add Termination flow
            add_termination_flow(
                ctrl=self.controller,
                in_port=in_port,
                eth_type=0x8847,
                dst_mac=src_mac,
                vlanid=out_vlan,
                goto_table=23
                )
            # add VLAN flows
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=out_vlan,
                flag=VLAN_TABLE_FLAG_ONLY_TAG,
                )
            add_one_vlan_table_flow(
                ctrl=self.controller,
                of_port=in_port,
                vlan_id=out_vlan,
                flag=VLAN_TABLE_FLAG_ONLY_UNTAG
                )
            # Packet generation with sleep
            time.sleep(2)
            label = (mpls_label, 0, 0, 32)
            parsed_pkt = mpls_packet(
                pktlen=104,
                vlan_vid=out_vlan,
                ip_ttl=63,
                eth_dst=src_mac_str,
                label=[ label ]
            )
            pkt = str( parsed_pkt )
            self.dataplane.send( in_port, pkt )
            # we geneate the expected pw packet
            parsed_pkt = simple_tcp_packet(
                pktlen=100,
                vlan_vid=out_vlan,
                ip_ttl=31,
                eth_dst=dst_mac_str,
                eth_src=src_mac_str,
            )
            pkt = str( parsed_pkt )
            # Assertions
            verify_packet( self, pkt, out_port )
            verify_no_packet( self, pkt, in_port )
            verify_no_other_packets( self )
        finally:
	    print("SHOULD CLEAR STATE HERE")
            # delete_all_flows( self.controller )
            # delete_groups( self.controller, Groups )
            # delete_all_groups( self.controller )

class ClearAll( base_tests.SimpleDataPlane ):

    def runTest( self ):
    	delete_all_flows( self.controller )
    	delete_all_groups( self.controller )




