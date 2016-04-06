"""
The following tests are being done here
1) PacketInSrcMacMiss
2) VlanSupport
3) L2FloodQinQ
4) L2FloodTagged
5) L2Flood Tagged Unknown Src
6) L2 Unicast Tagged
7) MTU 1500
8) MTU 4100
9) MTU 4500
10) L3UnicastTagged
11) L3VPNMPLS
12) MPLS Termination
"""
import Queue

from oftest import config
import inspect
import logging
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *


class PacketInUDP(base_tests.SimpleDataPlane):
    """
    Verify a ACL rule that matches on IP_PROTO 2 will not match a UDP packet.
    Next it verify a rule that matches on IP_PROTO 17 WILL match a UDP packet.
    """

    def runTest(self):
        parsed_vlan_pkt = simple_udp_packet(pktlen=104,
                                            vlan_vid=0x1001,
                                            dl_vlan_enable=True)
        vlan_pkt = str(parsed_vlan_pkt)
        # create match
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x0800))
        match.oxm_list.append(ofp.oxm.ip_proto(2))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(
                            actions=[
                                ofp.action.output(
                                        port=ofp.OFPP_CONTROLLER,
                                        max_len=ofp.OFPCML_NO_BUFFER)]), ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1)
        logging.info("Inserting packet in flow to controller")
        self.controller.message_send(request)

        for of_port in config["port_map"].keys():
            logging.info("PacketInMiss test, port %d", of_port)
            self.dataplane.send(of_port, vlan_pkt)

            verify_no_packet_in(self, vlan_pkt, of_port)
        delete_all_flows(self.controller) 
        do_barrier(self.controller)

        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x0800))
        match.oxm_list.append(ofp.oxm.ip_proto(17))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(
                            actions=[
                                ofp.action.output(
                                        port=ofp.OFPP_CONTROLLER,
                                        max_len=ofp.OFPCML_NO_BUFFER)]), ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1)
        logging.info("Inserting packet in flow to controller")
        self.controller.message_send(request)
        do_barrier(self.controller) 

        for of_port in config["port_map"].keys():
            logging.info("PacketInMiss test, port %d", of_port)
            self.dataplane.send(of_port, vlan_pkt)

            verify_packet_in(self, vlan_pkt, of_port, ofp.OFPR_ACTION)

            verify_no_other_packets(self)

        delete_all_flows(self.controller)


@disabled
class ArpNL2(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        ports = sorted(config["port_map"].keys())
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x0806))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(
                            actions=[
                                ofp.action.output(
                                        port=ofp.OFPP_CONTROLLER,
                                        max_len=ofp.OFPCML_NO_BUFFER)]),
                ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=40000)
        self.controller.message_send(request)
        for port in ports:
            add_one_l2_interface_group(self.controller, port, 1, False, False)
            add_one_vlan_table_flow(self.controller, port, 1,
                                    flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            group_id = encode_l2_interface_group_id(1, port)
            add_bridge_flow(self.controller,
                            [0x00, 0x12, 0x34, 0x56, 0x78, port], 1, group_id,
                            True)
        do_barrier(self.controller)
        parsed_arp_pkt = simple_arp_packet()
        arp_pkt = str(parsed_arp_pkt)

        for out_port in ports:
            self.dataplane.send(out_port, arp_pkt)
            verify_packet_in(self, arp_pkt, out_port, ofp.OFPR_ACTION)
            # change dest based on port number
            mac_dst = '00:12:34:56:78:%02X' % out_port
            for in_port in ports:
                if in_port == out_port:
                    continue
                # change source based on port number to avoid packet-ins from learning
                mac_src = '00:12:34:56:78:%02X' % in_port
                parsed_pkt = simple_tcp_packet(eth_dst=mac_dst, eth_src=mac_src)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)

                verify_no_other_packets(self)


class PacketInArp(base_tests.SimpleDataPlane):
    """
    Verify an ACL rule matching on ethertyper 0x806 will result in a packet-in
    """

    def runTest(self):
        parsed_arp_pkt = simple_arp_packet()
        arp_pkt = str(parsed_arp_pkt)
        # create match
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x0806))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(
                            actions=[
                                ofp.action.output(
                                        port=ofp.OFPP_CONTROLLER,
                                        max_len=ofp.OFPCML_NO_BUFFER)]),
                ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1)

        logging.info("Inserting packet in flow to controller")
        self.controller.message_send(request)
        do_barrier(self.controller)

        for of_port in config["port_map"].keys():
            logging.info("PacketInMiss test, port %d", of_port)
            self.dataplane.send(of_port, arp_pkt)

            verify_packet_in(self, arp_pkt, of_port, ofp.OFPR_ACTION)

            verify_no_other_packets(self)
        delete_all_flows(self.controller)


class L2FloodQinQ(base_tests.SimpleDataPlane):
    """
    Verify a tagged frame can be flooded based on its outer vlan
    """

    def runTest(self):
        ports = sorted(config["port_map"].keys())
        vlan_id = 1

        Groups = Queue.LifoQueue()
        for port in ports:
            L2gid, l2msg = add_one_l2_interface_group(self.controller, port,
                                                      vlan_id, True, False)
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            Groups.put(L2gid)

        msg = add_l2_flood_group(self.controller, ports, vlan_id, vlan_id)
        Groups.put(msg.group_id)
        add_bridge_flow(self.controller, None, vlan_id, msg.group_id, True)
        do_barrier(self.controller)

        # verify flood
        for ofport in ports:
            # change dest based on port number
            mac_src = '00:12:34:56:78:%02X' % ofport
            parsed_pkt = simple_tcp_packet_two_vlan(pktlen=108,
                                                    out_dl_vlan_enable=True,
                                                    out_vlan_vid=vlan_id,
                                                    in_dl_vlan_enable=True,
                                                    in_vlan_vid=10,
                                                    eth_dst='00:12:34:56:78:9a',
                                                    eth_src=mac_src)
            pkt = str(parsed_pkt)
            self.dataplane.send(ofport, pkt)
            # self won't rx packet
            verify_no_packet(self, pkt, ofport)
            # others will rx packet
            tmp_ports = list(ports)
            tmp_ports.remove(ofport)
            verify_packets(self, pkt, tmp_ports)

        verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


@disabled
class L2FloodTagged(base_tests.SimpleDataPlane):
    """
    Test L2 flood to a vlan
    Send a packet with unknown dst_mac and check if the packet is flooded to all ports except inport
    """

    def runTest(self):
        # Hashes Test Name and uses it as id for installing unique groups
        vlan_id = abs(hash(inspect.stack()[0][3])) % (256)
        print vlan_id

        ports = sorted(config["port_map"].keys())

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        # Installing flows to avoid packet-in
        for port in ports:
            add_one_l2_interface_group(self.controller, port, vlan_id, True,
                                       False)
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
        msg = add_l2_flood_group(self.controller, ports, vlan_id, vlan_id)
        add_bridge_flow(self.controller, None, vlan_id, msg.group_id, True)
        do_barrier(self.controller)

        # verify flood
        for ofport in ports:
            # change dest based on port number
            pkt = str(simple_tcp_packet(dl_vlan_enable=True, vlan_vid=vlan_id,
                                        eth_dst='00:12:34:56:78:9a'))
            self.dataplane.send(ofport, pkt)
            # self won't rx packet
            verify_no_packet(self, pkt, ofport)
            # others will rx packet
            tmp_ports = list(ports)
            tmp_ports.remove(ofport)
            verify_packets(self, pkt, tmp_ports)
        verify_no_other_packets(self)


class L2UnicastTagged(base_tests.SimpleDataPlane):
    """
    Verify L2 forwarding works
    """

    def runTest(self):
        ports = sorted(config["port_map"].keys())
        vlan_id = 1;
        Groups = Queue.LifoQueue()
        for port in ports:
            L2gid, l2msg = add_one_l2_interface_group(self.controller, port,
                                                      vlan_id, True, False)
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            Groups.put(L2gid)
            add_bridge_flow(self.controller,
                            [0x00, 0x12, 0x34, 0x56, 0x78, port], vlan_id,
                            L2gid, True)
        do_barrier(self.controller)

        for out_port in ports:
            # change dest based on port number
            mac_dst = '00:12:34:56:78:%02X' % out_port
            for in_port in ports:
                if in_port == out_port:
                    continue
                pkt = str(
                        simple_tcp_packet(dl_vlan_enable=True, vlan_vid=vlan_id,
                                          eth_dst=mac_dst))
                self.dataplane.send(in_port, pkt)
                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class Mtu1500(base_tests.SimpleDataPlane):
    def runTest(self):
        ports = sorted(config["port_map"].keys())
        vlan_id = 18
        Groups = Queue.LifoQueue()
        for port in ports:
            L2gid, msg = add_one_l2_interface_group(self.controller, port,
                                                    vlan_id, True, False)
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            Groups.put(L2gid)
            add_bridge_flow(self.controller,
                            [0x00, 0x12, 0x34, 0x56, 0x78, port], vlan_id,
                            L2gid, True)
        do_barrier(self.controller)

        for out_port in ports:
            # change dest based on port number
            mac_dst = '00:12:34:56:78:%02X' % out_port
            for in_port in ports:
                if in_port == out_port:
                    continue
                pkt = str(simple_tcp_packet(pktlen=1500, dl_vlan_enable=True,
                                            vlan_vid=vlan_id, eth_dst=mac_dst))
                self.dataplane.send(in_port, pkt)
                for ofport in ports:
                    if ofport in [out_port]:
                        verify_packet(self, pkt, ofport)
                    else:
                        verify_no_packet(self, pkt, ofport)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class _32UcastTagged(base_tests.SimpleDataPlane):
    """
    Verify a IP forwarding works for a /32 rule to L3 Unicast Interface
    """

    def runTest(self):
        test_id = 26
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return

        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        ports = config["port_map"].keys()
        Groups = Queue.LifoQueue()
        for port in ports:
            # add l2 interface group
            vlan_id = port + test_id
            l2gid, msg = add_one_l2_interface_group(self.controller, port,
                                                    vlan_id=vlan_id,
                                                    is_tagged=True,
                                                    send_barrier=False)
            dst_mac[5] = vlan_id
            l3_msg = add_l3_unicast_group(self.controller, port, vlanid=vlan_id,
                                          id=vlan_id, src_mac=intf_src_mac,
                                          dst_mac=dst_mac)
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add unicast routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffffff, l3_msg.group_id)
            Groups.put(l2gid)
            Groups.put(l3_msg.group_id)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            mac_src = '00:00:00:22:22:%02X' % (test_id + in_port)
            ip_src = '192.168.%02d.1' % (test_id + in_port)
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % (test_id + out_port)
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=(test_id + in_port),
                                               eth_dst=switch_mac,
                                               eth_src=mac_src, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expected packet
                mac_dst = '00:00:00:22:22:%02X' % (test_id + out_port)
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                            vlan_vid=(test_id + out_port),
                                            eth_dst=mac_dst, eth_src=switch_mac,
                                            ip_ttl=63,
                                            ip_src=ip_src, ip_dst=ip_dst)
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class _32VPN(base_tests.SimpleDataPlane):
    """
            Insert IP packet
            Receive MPLS packet
    """

    def runTest(self):
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return

        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        ports = config["port_map"].keys()
        Groups = Queue.LifoQueue()
        for port in ports:
            # add l2 interface group
            id = port
            vlan_id = port
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port,
                                                        vlan_id, True, True)
            dst_mac[5] = vlan_id
            # add MPLS interface group
            mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid,
                                                     dst_mac, intf_src_mac,
                                                     vlan_id, id)
            # add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group(
                    self.controller,
                    subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                    index=id, ref_gid=mpls_gid, push_mpls_header=True,
                    set_mpls_label=port, set_bos=1, set_ttl=32)
            # ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [mpls_label_gid])
            do_barrier(self.controller)
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, vrf=2,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffffff, mpls_label_gid,vrf=2)
            Groups._put(l2_gid)
            Groups._put(mpls_gid)
            Groups._put(mpls_label_gid)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            ip_src = '192.168.%02d.1' % (in_port)
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % (out_port)
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=(in_port),
                                               eth_dst=switch_mac, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expect packet
                mac_dst = '00:00:00:22:22:%02X' % (out_port)
                label = (out_port, 0, 1, 32)
                exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True,
                                      vlan_vid=(out_port), ip_ttl=63,
                                      ip_src=ip_src,
                                      ip_dst=ip_dst, eth_dst=mac_dst,
                                      eth_src=switch_mac, label=[label])
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)

class _32EcmpVpn(base_tests.SimpleDataPlane):
    """
            Insert IP packet
            Receive MPLS packet
    """

    def runTest(self):
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return

        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        ports = config["port_map"].keys()
        Groups = Queue.LifoQueue()
        for port in ports:
            # add l2 interface group
            id = port
            vlan_id = port
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port,
                                                        vlan_id, True, True)
            dst_mac[5] = vlan_id
            # add MPLS interface group
            mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid,
                                                     dst_mac, intf_src_mac,
                                                     vlan_id, id)
            # add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group(
                    self.controller,
                    subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                    index=id, ref_gid=mpls_gid, push_mpls_header=True,
                    set_mpls_label=port, set_bos=1, set_ttl=32)
            ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [mpls_label_gid])
            do_barrier(self.controller)
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, vrf=0,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffffff, ecmp_msg.group_id)
            Groups._put(l2_gid)
            Groups._put(mpls_gid)
            Groups._put(mpls_label_gid)
            Groups._put(ecmp_msg.group_id)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            ip_src = '192.168.%02d.1' % (in_port)
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % (out_port)
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=(in_port),
                                               eth_dst=switch_mac, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expect packet
                mac_dst = '00:00:00:22:22:%02X' % (out_port)
                label = (out_port, 0, 1, 32)
                exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True,
                                      vlan_vid=(out_port), ip_ttl=63,
                                      ip_src=ip_src,
                                      ip_dst=ip_dst, eth_dst=mac_dst,
                                      eth_src=switch_mac, label=[label])
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)

class _32ECMPL3(base_tests.SimpleDataPlane):
    """
    Port1(vid=in_port, src=00:00:00:22:22:in_port, 192.168.outport.1) ,
    Port2(vid=outport, dst=00:00:00:22:22:outport, 192.168.outport.1)
    """

    def runTest(self):
        Groups = Queue.LifoQueue()
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return

        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        # Hashes Test Name and uses it as id for installing unique groups
        ports = config["port_map"].keys()
        for port in ports:
            vlan_id = port
            id = port
            # add l2 interface group
            l2_gid, msg = add_one_l2_interface_group(self.controller, port,
                                                     vlan_id=vlan_id,
                                                     is_tagged=True,
                                                     send_barrier=False)
            dst_mac[5] = vlan_id
            l3_msg = add_l3_unicast_group(self.controller, port, vlanid=vlan_id,
                                          id=id, src_mac=intf_src_mac,
                                          dst_mac=dst_mac)
            ecmp_msg = add_l3_ecmp_group(self.controller, id, [l3_msg.group_id])
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add unicast routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffffff, ecmp_msg.group_id)
            Groups._put(l2_gid)
            Groups._put(l3_msg.group_id)
            Groups._put(ecmp_msg.group_id)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            mac_src = '00:00:00:22:22:%02X' % in_port
            ip_src = '192.168.%02d.1' % in_port
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % out_port
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=in_port,
                                               eth_dst=switch_mac,
                                               eth_src=mac_src, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expected packet
                mac_dst = '00:00:00:22:22:%02X' % out_port
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                            vlan_vid=out_port,
                                            eth_dst=mac_dst, eth_src=switch_mac,
                                            ip_ttl=63,
                                            ip_src=ip_src, ip_dst=ip_dst)
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class _24VPN(base_tests.SimpleDataPlane):
    """
            Insert IP packet
            Receive MPLS packet
    """

    def runTest(self):
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return

        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        ports = config["port_map"].keys()
        Groups = Queue.LifoQueue()
        for port in ports:
            # add l2 interface group
            id = port
            vlan_id = port
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port,
                                                        vlan_id, True, True)
            dst_mac[5] = vlan_id
            # add MPLS interface group
            mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid,
                                                     dst_mac, intf_src_mac,
                                                     vlan_id, id)
            # add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group(
                    self.controller,
                    subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                    index=id, ref_gid=mpls_gid, push_mpls_header=True,
                    set_mpls_label=port, set_bos=1, set_ttl=32)
            # ecmp_msg=add_l3_ecmp_group(self.controller, vlan_id, [mpls_label_gid])
            do_barrier(self.controller)
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, vrf=0,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffff00, mpls_label_gid)
            Groups._put(l2_gid)
            Groups._put(mpls_gid)
            Groups._put(mpls_label_gid)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            ip_src = '192.168.%02d.1' % (in_port)
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % (out_port)
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=(in_port),
                                               eth_dst=switch_mac, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expect packet
                mac_dst = '00:00:00:22:22:%02X' % (out_port)
                label = (out_port, 0, 1, 32)
                exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True,
                                      vlan_vid=(out_port), ip_ttl=63,
                                      ip_src=ip_src,
                                      ip_dst=ip_dst, eth_dst=mac_dst,
                                      eth_src=switch_mac, label=[label])
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class _24EcmpVpn(base_tests.SimpleDataPlane):
    """
	    Insert IP packet
	    Receive MPLS packet
    """

    def runTest(self):
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return
        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        Groups = Queue.LifoQueue()
        ports = config["port_map"].keys()
        for port in ports:
            # add l2 interface group
            id = port
            vlan_id = id
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port,
                                                        vlan_id, True, True)
            dst_mac[5] = vlan_id
            # add MPLS interface group
            mpls_gid, mpls_msg = add_mpls_intf_group(self.controller, l2_gid,
                                                     dst_mac, intf_src_mac,
                                                     vlan_id, id)
            # add MPLS L3 VPN group
            mpls_label_gid, mpls_label_msg = add_mpls_label_group(
                    self.controller,
                    subtype=OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL,
                    index=id, ref_gid=mpls_gid, push_mpls_header=True,
                    set_mpls_label=port, set_bos=1, set_ttl=32)
            ecmp_msg = add_l3_ecmp_group(self.controller, id, [mpls_label_gid])
            do_barrier(self.controller)
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id, vrf=0,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add routing flow
            dst_ip = dip + (vlan_id << 8)
            # add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0, mpls_label_gid, vrf=2)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffff00, ecmp_msg.group_id, vrf=0)
            Groups._put(l2_gid)
            Groups._put(mpls_gid)
            Groups._put(mpls_label_gid)
            Groups._put(ecmp_msg.group_id)

        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            mac_src = '00:00:00:22:22:%02X' % (in_port)
            ip_src = '192.168.%02d.1' % (in_port)
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % (out_port)
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=(in_port),
                                               eth_dst=switch_mac,
                                               eth_src=mac_src, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expect packet
                mac_dst = '00:00:00:22:22:%02X' % out_port
                label = (out_port, 0, 1, 32)
                exp_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True,
                                      vlan_vid=(out_port), ip_ttl=63,
                                      ip_src=ip_src,
                                      ip_dst=ip_dst, eth_dst=mac_dst,
                                      eth_src=switch_mac, label=[label])
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)



class _24ECMPL3(base_tests.SimpleDataPlane):
    """
    Port1(vid=in_port, src=00:00:00:22:22:in_port, 192.168.outport.1) ,
    Port2(vid=outport, dst=00:00:00:22:22:outport, 192.168.outport.1)
    """

    def runTest(self):
        Groups = Queue.LifoQueue()
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return

        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        # Hashes Test Name and uses it as id for installing unique groups
        ports = config["port_map"].keys()
        for port in ports:
            vlan_id = port
            id = port
            # add l2 interface group
            l2_gid, msg = add_one_l2_interface_group(self.controller, port,
                                                     vlan_id=vlan_id,
                                                     is_tagged=True,
                                                     send_barrier=False)
            dst_mac[5] = vlan_id
            l3_msg = add_l3_unicast_group(self.controller, port, vlanid=vlan_id,
                                          id=id, src_mac=intf_src_mac,
                                          dst_mac=dst_mac)
            ecmp_msg = add_l3_ecmp_group(self.controller, id, [l3_msg.group_id])
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add unicast routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffff00, ecmp_msg.group_id)
            Groups._put(l2_gid)
            Groups._put(l3_msg.group_id)
            Groups._put(ecmp_msg.group_id)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            mac_src = '00:00:00:22:22:%02X' % in_port
            ip_src = '192.168.%02d.1' % in_port
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % out_port
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=in_port,
                                               eth_dst=switch_mac,
                                               eth_src=mac_src, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expected packet
                mac_dst = '00:00:00:22:22:%02X' % out_port
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                            vlan_vid=out_port,
                                            eth_dst=mac_dst, eth_src=switch_mac,
                                            ip_ttl=63,
                                            ip_src=ip_src, ip_dst=ip_dst)
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)

@disabled
class MPLSBUG(base_tests.SimpleDataPlane):
    def runTest(self):
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return
        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        Groups = Queue.LifoQueue()
        ports = config["port_map"].keys()
        for port in ports:
            # add l2 interface group
            vlan_id = port
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port,
                                                        vlan_id, True, False)
            dst_mac[5] = vlan_id
            # add L3 Unicast  group
            l3_msg = add_l3_unicast_group(self.controller, port, vlanid=vlan_id,
                                          id=vlan_id, src_mac=intf_src_mac,
                                          dst_mac=dst_mac)
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            # add termination flow
            add_termination_flow(self.controller, port, 0x8847, intf_src_mac,
                                 vlan_id, goto_table=24)
            # add mpls flow
            add_mpls_flow(self.controller, l3_msg.group_id, port)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add unicast routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffffff, l3_msg.group_id)
            Groups._put(l2_gid)
            Groups._put(l3_msg.group_id)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            mac_src = '00:00:00:22:22:%02X' % in_port
            ip_src = '192.168.%02d.1' % in_port
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % out_port
                switch_mac = "00:00:00:cc:cc:cc"
                label = (out_port, 0, 1, 32)
                parsed_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True,
                                         vlan_vid=in_port, ip_src=ip_src,
                                         ip_dst=ip_dst, eth_dst=switch_mac,
                                         eth_src=mac_src, label=[label])
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                # build expect packet
                mac_dst = '00:00:00:22:22:%02X' % out_port
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                            vlan_vid=out_port,
                                            eth_dst=mac_dst, eth_src=switch_mac,
                                            ip_ttl=31, ip_src=ip_src,
                                            ip_dst=ip_dst)
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)

                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=in_port,
                                               eth_dst=switch_mac,
                                               eth_src=mac_src, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expected packet
                mac_dst = '00:00:00:22:22:%02X' % out_port
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                            vlan_vid=out_port,
                                            eth_dst=mac_dst, eth_src=switch_mac,
                                            ip_ttl=63,
                                            ip_src=ip_src, ip_dst=ip_dst)
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class L3McastToL2(base_tests.SimpleDataPlane):
    """
    Mcast routing to L2
    """

    def runTest(self):
        """
        port1 (vlan 300)-> All Ports (vlan 300)
        """
        if len(config["port_map"]) < 3:
            logging.info("Port count less than 3, can't run this case")
            assert (False)
            return
        Groups = Queue.LifoQueue()
        vlan_id = 300
        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        intf_src_mac_str = ':'.join(['%02X' % x for x in intf_src_mac])
        dst_mac = [0x01, 0x00, 0x5e, 0x01, 0x01, 0x01]
        dst_mac_str = ':'.join(['%02X' % x for x in dst_mac])
        port1_mac = [0x00, 0x11, 0x11, 0x11, 0x11, 0x11]
        port1_mac_str = ':'.join(['%02X' % x for x in port1_mac])
        src_ip = 0xc0a80101
        src_ip_str = "192.168.1.1"
        dst_ip = 0xe0010101
        dst_ip_str = "224.1.1.1"

        port1 = config["port_map"].keys()[0]
        port2 = config["port_map"].keys()[1]

        switch_mac = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x00]

        # add l2 interface group
        l2_intf_group_list = []
        for port in config["port_map"].keys():
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            if port == port2:
                continue
            l2_intf_gid, msg = add_one_l2_interface_group(self.controller, port,
                                                          vlan_id=vlan_id,
                                                          is_tagged=True,
                                                          send_barrier=False)
            l2_intf_group_list.append(l2_intf_gid)
            Groups.put(l2_intf_gid)

        # add termination flow
        add_termination_flow(self.controller, port1, 0x0800, switch_mac,
                             vlan_id)

        # add l3 interface group
        mcat_group_msg = add_l3_mcast_group(self.controller, vlan_id, 2,
                                            l2_intf_group_list)
        add_mcast4_routing_flow(self.controller, vlan_id, src_ip, 0, dst_ip,
                                mcat_group_msg.group_id)
        Groups._put(mcat_group_msg.group_id)

        parsed_pkt = simple_udp_packet(pktlen=100,
                                       dl_vlan_enable=True,
                                       vlan_vid=vlan_id,
                                       eth_dst=dst_mac_str,
                                       eth_src=port1_mac_str,
                                       ip_ttl=64,
                                       ip_src=src_ip_str,
                                       ip_dst=dst_ip_str)
        pkt = str(parsed_pkt)
        self.dataplane.send(port1, pkt)
        for port in config["port_map"].keys():
            if port == port2 or port == port1:
                verify_no_packet(self, pkt, port)
                continue
            verify_packet(self, pkt, port)
        verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class L3McastToL3(base_tests.SimpleDataPlane):
    """
    Mcast routing
    """

    def runTest(self):
        """
        port1 (vlan 1)-> port 2 (vlan 2)
        """
        Groups = Queue.LifoQueue()
        if len(config["port_map"]) < 3:
            logging.info("Port count less than 3, can't run this case")
            assert (False)
            return

        vlan_id = 1
        port2_out_vlan = 2
        port3_out_vlan = 3
        in_vlan = 1  # macast group vid shall use input vlan diffe from l3 interface use output vlan
        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        intf_src_mac_str = ':'.join(['%02X' % x for x in intf_src_mac])
        dst_mac = [0x01, 0x00, 0x5e, 0x01, 0x01, 0x01]
        dst_mac_str = ':'.join(['%02X' % x for x in dst_mac])
        port1_mac = [0x00, 0x11, 0x11, 0x11, 0x11, 0x11]
        port1_mac_str = ':'.join(['%02X' % x for x in port1_mac])
        src_ip = 0xc0a80101
        src_ip_str = "192.168.1.1"
        dst_ip = 0xe0010101
        dst_ip_str = "224.1.1.1"

        port1 = config["port_map"].keys()[0]
        port2 = config["port_map"].keys()[1]
        port3 = config["port_map"].keys()[2]

        # add l2 interface group
        for port in config["port_map"].keys():
            l2gid, msg = add_one_l2_interface_group(self.controller, port,
                                                    vlan_id=vlan_id,
                                                    is_tagged=False,
                                                    send_barrier=False)
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            vlan_id += 1
            Groups._put(l2gid)

        # add termination flow
        add_termination_flow(self.controller, port1, 0x0800,
                             [0x01, 0x00, 0x5e, 0x00, 0x00, 0x00], vlan_id)

        # add l3 interface group
        port2_ucast_msg = add_l3_interface_group(self.controller, port2,
                                                 port2_out_vlan, 2,
                                                 intf_src_mac)
        port3_ucast_msg = add_l3_interface_group(self.controller, port3,
                                                 port3_out_vlan, 3,
                                                 intf_src_mac)
        mcat_group_msg = add_l3_mcast_group(self.controller, in_vlan, 2,
                                            [port2_ucast_msg.group_id,
                                             port3_ucast_msg.group_id])
        add_mcast4_routing_flow(self.controller, in_vlan, src_ip, 0, dst_ip,
                                mcat_group_msg.group_id)
        Groups._put(port2_ucast_msg.group_id)
        Groups._put(port3_ucast_msg.group_id)
        Groups._put(mcat_group_msg.group_id)
        parsed_pkt = simple_udp_packet(pktlen=100, dl_vlan_enable=True,
                                       vlan_vid=1,
                                       eth_dst=dst_mac_str,
                                       eth_src=port1_mac_str,
                                       ip_ttl=64,
                                       ip_src=src_ip_str,
                                       ip_dst=dst_ip_str)
        pkt = str(parsed_pkt)
        self.dataplane.send(port1, pkt)
        parsed_pkt = simple_udp_packet(pktlen=96,
                                       eth_dst=dst_mac_str,
                                       eth_src=intf_src_mac_str,
                                       ip_ttl=63,
                                       ip_src=src_ip_str,
                                       ip_dst=dst_ip_str)
        pkt = str(parsed_pkt)
        verify_packet(self, pkt, port2)
        verify_packet(self, pkt, port3)
        verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class _MplsTermination(base_tests.SimpleDataPlane):
    """
        Insert IP packet
        Receive MPLS packet
    """
    def runTest(self):
        Groups = Queue.LifoQueue()
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return
        dip = 0xc0a80001 
        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        # Assigns unique hardcoded test_id to make sure tests don't overlap when writing rules
        ports = config["port_map"].keys()
        for port in ports:
            # add l2 interface group
            id = port
            vlan_id = id
            l2_gid, l2_msg = add_one_l2_interface_group(self.controller, port,
                                                        vlan_id, True, False)
            dst_mac[5] = vlan_id
            # add L3 Unicast  group
            l3_msg = add_l3_unicast_group(self.controller, port, vlanid=vlan_id,
                                          id=id, src_mac=intf_src_mac,
                                          dst_mac=dst_mac)
            # add L3 ecmp group
            ecmp_msg = add_l3_ecmp_group(self.controller, id, [l3_msg.group_id])
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x8847, intf_src_mac,
                                 vlan_id, goto_table=24)
            add_mpls_flow(self.controller, ecmp_msg.group_id, port)
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip, 0xffffff00,
                      ecmp_msg.group_id, 1)
            Groups._put(l2_gid)
            Groups._put(l3_msg.group_id)
            Groups._put(ecmp_msg.group_id)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            ip_src = '192.168.%02d.1' % (in_port)
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % (out_port)

                label = (out_port, 0, 1, 32)
                parsed_pkt = mpls_packet(pktlen=104, dl_vlan_enable=True,
                                         vlan_vid=(in_port), ip_src=ip_src,
                                         ip_dst=ip_dst, eth_dst=switch_mac,
                                         label=[label])
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)

                # build expect packet
                mac_dst = '00:00:00:22:22:%02X' % (out_port)
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                            vlan_vid=(out_port),
                                            eth_dst=mac_dst, eth_src=switch_mac,
                                            ip_ttl=31, ip_src=ip_src,
                                            ip_dst=ip_dst)
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)


class _24UcastTagged(base_tests.SimpleDataPlane):
    """
    Verify a IP forwarding works for a /32 rule to L3 Unicast Interface
    """

    def runTest(self):
        test_id = 26
        if len(config["port_map"]) < 2:
            logging.info("Port count less than 2, can't run this case")
            return

        intf_src_mac = [0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc]
        dst_mac = [0x00, 0x00, 0x00, 0x22, 0x22, 0x00]
        dip = 0xc0a80001
        ports = config["port_map"].keys()
        Groups = Queue.LifoQueue()
        for port in ports:
            # add l2 interface group
            vlan_id = port + test_id
            l2gid, msg = add_one_l2_interface_group(self.controller, port,
                                                    vlan_id=vlan_id,
                                                    is_tagged=True,
                                                    send_barrier=False)
            dst_mac[5] = vlan_id
            l3_msg = add_l3_unicast_group(self.controller, port, vlanid=vlan_id,
                                          id=vlan_id, src_mac=intf_src_mac,
                                          dst_mac=dst_mac)
            # add vlan flow table
            add_one_vlan_table_flow(self.controller, port, vlan_id,
                                    flag=VLAN_TABLE_FLAG_ONLY_TAG)
            # add termination flow
            add_termination_flow(self.controller, port, 0x0800, intf_src_mac,
                                 vlan_id)
            # add unicast routing flow
            dst_ip = dip + (vlan_id << 8)
            add_unicast_routing_flow(self.controller, 0x0800, dst_ip,
                                     0xffffff00, l3_msg.group_id)
            Groups.put(l2gid)
            Groups.put(l3_msg.group_id)
        do_barrier(self.controller)

        switch_mac = ':'.join(['%02X' % x for x in intf_src_mac])
        for in_port in ports:
            mac_src = '00:00:00:22:22:%02X' % (test_id + in_port)
            ip_src = '192.168.%02d.1' % (test_id + in_port)
            for out_port in ports:
                if in_port == out_port:
                    continue
                ip_dst = '192.168.%02d.1' % (test_id + out_port)
                parsed_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                               vlan_vid=(test_id + in_port),
                                               eth_dst=switch_mac,
                                               eth_src=mac_src, ip_ttl=64,
                                               ip_src=ip_src,
                                               ip_dst=ip_dst)
                pkt = str(parsed_pkt)
                self.dataplane.send(in_port, pkt)
                # build expected packet
                mac_dst = '00:00:00:22:22:%02X' % (test_id + out_port)
                exp_pkt = simple_tcp_packet(pktlen=100, dl_vlan_enable=True,
                                            vlan_vid=(test_id + out_port),
                                            eth_dst=mac_dst, eth_src=switch_mac,
                                            ip_ttl=63,
                                            ip_src=ip_src, ip_dst=ip_dst)
                pkt = str(exp_pkt)
                verify_packet(self, pkt, out_port)
                verify_no_other_packets(self)
        delete_all_flows(self.controller)
        delete_groups(self.controller, Groups)
