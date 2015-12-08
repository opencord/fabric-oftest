"""
Nat Test

Test each flow table can set entry, and packet rx correctly.
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class dnat(base_tests.SimpleDataPlane):
    """
    [DNAT]
      DNAT (inbound)

    Inject  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 200.0.0.1, DIP 100.0.0.01, Sport 2828, Dport 5000
    Output  eth 1/1 DA000000000101, SA000000000100, Tag 100, SIP 200.0.0.1, DIP 10.0.0.01, Sport 2828, Dport 2000

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x10c8/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x640001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x640001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x23000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        
        add_one_vlan_table_flow(self.controller, input_port, vlan_id=200, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_BOTH, send_barrier=False)           
        add_termination_flow(self.controller, input_port, 0x0800, [0x00,0x00,0x00,0x00,0x02,0x00], 200, goto_table=28, send_barrier=False)        
        
        add_one_l2_interface_group(self.controller, port=output_port, vlan_id=100, is_tagged=True, send_barrier=False)
        msg1=add_l3_unicast_group(self.controller, port=output_port, vlanid=100, id=0x3000001, src_mac=[0x00,0x00,0x00,0x00,0x01,0x00], dst_mac=[0x00,0x00,0x00,0x00,0x01,0x01])
        add_dnat_flow(self.controller, eth_type=0x0800, ip_dst=0x64000001, ip_proto=6, tcp_dst=5000, set_ip_dst=0x0a000001, set_tcp_dst=2000, action_group_id=msg1.group_id)

        input_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:00:00:02:00",
                                       eth_src="00:00:00:00:02:01",
                                       dl_vlan_enable = True,
                                       vlan_vid = 200,
                                       ip_ttl=64,                                       
                                       ip_src="200.0.0.1",
                                       ip_dst='100.0.0.1',
                                       tcp_dport=5000)
        output_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:00:00:01:01",
                                       eth_src="00:00:00:00:01:00",
                                       dl_vlan_enable = True,
                                       vlan_vid = 100,                                       
                                       ip_ttl=63,                                       
                                       ip_src="200.0.0.1",
                                       ip_dst='10.0.0.1',
                                       tcp_dport=2000)
                                       
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
         
        
        
class dnatEcmp(base_tests.SimpleDataPlane):
    """
    [DNAT ECMP]
      DNAT (inbound) with ECMP

    Inject  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 200.0.0.1, DIP 100.0.0.01, Sport 2828, Dport 5000 [increase SIP]
    Output  eth 1/1 DA000000000101, SA000000000100, Tag 100, SIP 200.0.0.X, DIP 10.0.0.01, Sport 2828, Dport 2000
    Output  eth 1/5 DA000005224466, SA000005223355, Tag 2, SIP 200.0.0.X, DIP 10.0.0.01, Sport 2828, Dport 2000

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x10c8/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x640001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x23000001 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:01:00,set_field=eth_dst=00:00:00:00:01:01,set_field=vlan_vid=100,group=0x640001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20005 group=any,port=any,weight=0 output=5    
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x23000005 group=any,port=any,weight=0 set_field=eth_src=00:00:05:22:33:55,set_field=eth_dst=00:00:05:22:44:66,set_field=vlan_vid=2,group=0x20005    
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=sel,group=0x71000001 group=any,port=any,weight=0 group=0x23000001 group=any,port=any,weight=0 group=0x23000005    
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=200/0xfff,eth_dst=00:00:00:00:02:00,eth_type=0x0800 goto:28
    
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=28,cmd=add,prio=281 eth_type=0x800,ip_dst=100.0.0.1,ip_proto=6,tcp_dst=5000 write:set_field=ip_dst:10.0.0.1,set_field=tcp_dst:2000,group=0x71000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = config["port_map"].keys()
        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]

        add_one_vlan_table_flow(self.controller, input_port, vlan_id=200, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_TAG, send_barrier=False)   
        add_one_l2_interface_group(self.controller, port=output_port, vlan_id=100, is_tagged=True, send_barrier=False)
        #Bits 27:24 is for realm id, so unicast group id give 0x3000001
        msg1=add_l3_unicast_group(self.controller, port=output_port, vlanid=100, id=0x3000001, src_mac=[0x00,0x00,0x00,0x00,0x01,0x00], dst_mac=[0x00,0x00,0x00,0x00,0x01,0x01])
        add_one_l2_interface_group(self.controller, port=output_port2, vlan_id=2, is_tagged=True, send_barrier=False)
        #Bits 27:24 is for realm id, so unicast group id give 0x3000005
        msg2=add_l3_unicast_group(self.controller, port=output_port2, vlanid=2, id=0x3000005, src_mac=[0x00,0x00,0x05,0x22,0x33,0x55], dst_mac=[0x00,0x00,0x05,0x22,0x44,0x66])
        ecmp=add_l3_ecmp_group(self.controller, id=0x1000001, l3_ucast_groups=[msg1.group_id, msg2.group_id])
        add_termination_flow(self.controller, 0, 0x0800, [0x00,0x00,0x00,0x00,0x02,0x00], 200, goto_table=28, send_barrier=False)
        add_dnat_flow(self.controller, eth_type=0x0800, ip_dst=0x64000001, ip_proto=6, tcp_dst=5000, set_ip_dst=0x0a000001, set_tcp_dst=2000, action_group_id=ecmp.group_id)
        
        
        input_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:00:00:02:00",
                                       eth_src="00:00:00:00:02:01",
                                       dl_vlan_enable = True,
                                       vlan_vid = 200,
                                       ip_ttl=64,                                       
                                       ip_src="200.0.0.1",
                                       ip_dst='100.0.0.1',
                                       tcp_dport=5000)
        output_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:00:00:01:01",
                                       eth_src="00:00:00:00:01:00",
                                       dl_vlan_enable = True,
                                       vlan_vid = 100,                                       
                                       ip_ttl=63,                                       
                                       ip_src="200.0.0.1",
                                       ip_dst='10.0.0.1',
                                       tcp_dport=2000)
        output_pkt2 = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:05:22:44:66",
                                       eth_src="00:00:05:22:33:55",
                                       dl_vlan_enable = True,
                                       vlan_vid = 2,                                       
                                       ip_ttl=63,                                       
                                       ip_src="200.0.0.1",
                                       ip_dst='10.0.0.1',
                                       tcp_dport=2000)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt2), output_port2)
        #self.dataplane.send(input_port, str(input_pkt))
        #verify_packet(self, str(output_pkt2), output_port2)
        
class snat_ecmp(base_tests.SimpleDataPlane):
    """
    [SNAT ECMP]
      SNAT (outbound) with ECMP

    Inject  eth 1/1 DA000000000100, SA000000000101, Tag 100, SIP 10.0.0.1, DIP 200.0.0.01, Sport 2000, Dport 2828 [increase DIP]
    Output  eth 1/3 DA000000000200, SA000000000201, Tag 200, SIP 100.0.0.1, DIP 200.0.0.X, Sport 5000, Dport 2828
    Output  eth 1/5 DA000000000500, SA000000000501, Tag 5, SIP 100.0.0.1, DIP 200.0.0.X, Sport 5000, Dport 2828

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1064/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=100/0xfff,eth_dst=00:00:00:00:01:00,eth_type=0x0800 goto:29
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0xC80003 group=any,port=any,weight=0 output=3   
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x22000002 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:02:00,set_field=eth_dst=00:00:00:00:02:01,set_field=vlan_vid=200,group=0xC80003    
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x50005 group=any,port=any,weight=0 output=5
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x22000005 group=any,port=any,weight=0 set_field=eth_src=00:00:00:00:05:00,set_field=eth_dst=00:00:00:00:05:01,set_field=vlan_vid=5,group=0x50005
    
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=sel,group=0x71000001 group=any,port=any,weight=0 group=0x22000002 group=any,port=any,weight=0 group=0x22000005
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=29,cmd=add,prio=291 eth_type=0x800,ip_src=10.0.0.1,ip_proto=6,tcp_src=2000 write:set_field=ip_src:100.0.0.1,set_field=tcp_src:5000 goto:30
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=200.0.0.1/255.255.255.0 write:group=0x71000001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]
        
        add_one_vlan_table_flow(self.controller, input_port, vlan_id=100, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_TAG, send_barrier=False)   
        add_termination_flow(self.controller, 0, 0x0800, [0x00,0x00,0x00,0x00,0x01,0x00], 100, goto_table=29, send_barrier=False)
        add_one_l2_interface_group(self.controller, port=output_port, vlan_id=200, is_tagged=True, send_barrier=False)
        #Bits 27:24 is for realm id, so unicast group id give 0x2000002
        msg1=add_l3_unicast_group(self.controller, port=output_port, vlanid=200, id=0x2000002, src_mac=[0x00,0x00,0x00,0x00,0x02,0x00], dst_mac=[0x00,0x00,0x00,0x00,0x02,0x01])
        
        add_one_l2_interface_group(self.controller, port=output_port2, vlan_id=5, is_tagged=True, send_barrier=False)
        #Bits 27:24 is for realm id, so unicast group id give 0x2000002
        msg2=add_l3_unicast_group(self.controller, port=output_port2, vlanid=5, id=0x2000005, src_mac=[0x00,0x00,0x00,0x00,0x05,0x00], dst_mac=[0x00,0x00,0x00,0x00,0x05,0x01])

        ecmp=add_l3_ecmp_group(self.controller, id=0x1000001, l3_ucast_groups=[msg1.group_id, msg2.group_id])
        add_snat_flow(self.controller, 0x0800, 0x0a000001, 6, 2000, 0x64000001, 5000)
        add_unicast_routing_flow(self.controller, 0x0800, 0xc8000001, 0xffffff00, ecmp.group_id, vrf=0, send_barrier=False)

        input_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:00:00:01:00",
                                       eth_src="00:00:00:00:01:01",
                                       dl_vlan_enable = True,
                                       vlan_vid = 100,
                                       ip_ttl=64,                                       
                                       ip_src='10.0.0.1',
                                       ip_dst="200.0.0.1",
                                       tcp_sport=2000)
        output_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:00:00:02:01",
                                       eth_src="00:00:00:00:02:00",
                                       dl_vlan_enable = True,
                                       vlan_vid = 200,                                       
                                       ip_ttl=63,                                       
                                       ip_src="100.0.0.1",
                                       ip_dst='200.0.0.1',
                                       tcp_sport=5000)
        output_pkt2 = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:00:00:05:01",
                                       eth_src="00:00:00:00:05:00",
                                       dl_vlan_enable = True,
                                       vlan_vid = 5,                                       
                                       ip_ttl=63,                                       
                                       ip_src="100.0.0.1",
                                       ip_dst='200.0.0.1',
                                       tcp_sport=5000)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        #self.dataplane.send(input_port, str(input_pkt))
        #verify_packet(self, str(output_pkt2), output_port2)
        
"""just for verify it can work after nat ecmp"""
class l3Route(base_tests.SimpleDataPlane):
    """
    [L3 unicast route]
      Do unicast route and output to specified port
    
    Inject  eth 1/3 Tag2, SA000000112233, DA7072cf7cf3a3, SIP 192.168.1.100, DIP 192.168.2.2
    Output  eth 1/1 Tag3, SA 000004223355, DA 000004224466
    
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=2/0xfff,eth_dst=70:72:cf:7c:f3:a3,eth_type=0x0800 goto:30
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20000003 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=3,group=0x30001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x20000003 goto:60
    """
    def runTest(self):   
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]    

        add_port_table_flow(self.controller, is_overlay=False)
        add_one_vlan_table_flow(self.controller, input_port, vlan_id=2, vrf=0, flag=VLAN_TABLE_FLAG_ONLY_TAG, send_barrier=False)   
        add_termination_flow(self.controller, input_port, 0x0800, [0x70, 0x72, 0xcf, 0x7c, 0xf3, 0xa3], 2, send_barrier=False)
        add_one_l2_interface_group(self.controller, port=output_port, vlan_id=3, is_tagged=True, send_barrier=False)
        msg=add_l3_unicast_group(self.controller, port=output_port, vlanid=3, id=3, src_mac=[0x00,0x00,0x04,0x22,0x33,0x55], dst_mac=[0x00,0x00,0x04,0x22,0x44,0x66])
        add_unicast_routing_flow(self.controller, 0x0800, 0xc0a80202, 0xffffff00, msg.group_id)

        #verify tx/rx packet
        input_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst="70:72:cf:7c:f3:a3",
                                       eth_src="00:00:00:00:02:01",
                                       dl_vlan_enable = True,
                                       vlan_vid = 2,
                                       ip_ttl=64,                                       
                                       ip_src="200.0.0.1",
                                       ip_dst='192.168.2.2')
        output_pkt = simple_tcp_packet(pktlen=100, 
                                       eth_dst="00:00:04:22:44:66",
                                       eth_src="00:00:04:22:33:55",
                                       dl_vlan_enable = True,
                                       vlan_vid = 3,                                       
                                       ip_ttl=63,                                       
                                       ip_src="200.0.0.1",
                                       ip_dst='192.168.2.2')        

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)        
        
        
        
        
        
        
        