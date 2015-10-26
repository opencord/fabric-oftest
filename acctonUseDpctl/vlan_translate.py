import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr


class single_tag_to_double_tag(base_tests.SimpleDataPlane):
    """																					 
	[Single tag to double tag]																				
		Add a specified outer tag to incoming tagged packet																			
																					
	Inject	eth 1/3	Tag 3, SA000000112233, DA000000113355, V4																		
	Output	eth 1/1	Outter Tag 5, inner Tag 3, others not change																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:push_vlan=0x8100,set_field=vlan_vid=5 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=3/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=3 write:group=0x50001																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 pop_vlan,output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x30003 goto:60																				
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:push_vlan=0x8100,set_field=vlan_vid=5 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=3/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output=1"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x50001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 pop_vlan,output="+str(input_port))
        apply_dpctl_mod(self, config, " flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x30003 goto:60")

        input_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      dl_vlan_enable=True,
                                      vlan_vid=3)

        output_pkt = simple_tcp_packet_two_vlan(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      out_dl_vlan_enable=True,
                                      in_dl_vlan_enable=True,
                                      out_vlan_vid=5,
                                      in_vlan_vid=3)
        
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        
        
        

class double_tag_to_single_tag(base_tests.SimpleDataPlane):
    """																					 
	[Double tag to single tag]																				
		Pop outter tag of incoming double tagged packet																			
																					
	Inject	eth 1/3	Outer 0x8100 + 6, Inner 0x8100 +3, SA000000112233, DA000000113355, V4																		
	Output	eth 1/1	Tag 3, others not change																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1006/0x1fff apply:pop_vlan,set_field=ofdpa_ovid:6 goto:11																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=11,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff,ofdpa_ovid=0x1006 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=6/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=3 write:group=0x30001																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x60003 group=any,port=any,weight=0 output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=6,eth_dst=00:00:00:11:22:33 write:group=0x60003 goto:60																				
																				
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1006/0x1fff apply:pop_vlan,set_field=ofdpa_ovid:6 goto:11")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff,ofdpa_ovid=0x1006 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=6/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")        
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x30001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x60003 group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=6,eth_dst=00:00:00:11:22:33 write:group=0x60003 goto:60")

        input_pkt = simple_tcp_packet_two_vlan(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      out_dl_vlan_enable=True,
                                      in_dl_vlan_enable=True,
                                      out_vlan_vid=6,
                                      in_vlan_vid=3)

        output_pkt = simple_tcp_packet(eth_dst="00:00:04:22:44:66",
                                       eth_src="00:00:04:22:33:55",
                                       dl_vlan_enable=True,
                                       vlan_vid=5)
        
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
                
        


class vlan_translate(base_tests.SimpleDataPlane):
    """																					 
	[Double tag to single tag and modify inner tag]																				
		Pop outter tag of incoming double tagged packet and modify inner tag																			
																					
	Inject	eth 1/3	Outer 0x8100 + 6, Inner 0x8100 +3, SA000000112233, DA000000113355, V4																		
	Output	eth 1/1	Tag 4, others not change																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1006/0x1fff apply:pop_vlan,set_field=ofdpa_ovid:6 goto:11																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=11,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff,ofdpa_ovid=0x1006 apply:set_field=vlan_vid=4 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=6/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x40001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=3 write:group=0x40001																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x60003 group=any,port=any,weight=0 output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=6,eth_dst=00:00:00:11:22:33 write:group=0x60003 goto:60																				
															
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1006/0x1fff apply:pop_vlan,set_field=ofdpa_ovid:6 goto:11")
        apply_dpctl_mod(self, config, "flow-mod table=11,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff,ofdpa_ovid=0x1006 apply:set_field=vlan_vid=4 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=6/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")        
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x40001 group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x40001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x60003 group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=6,eth_dst=00:00:00:11:22:33 write:group=0x60003 goto:60")

        input_pkt = simple_tcp_packet_two_vlan(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      out_dl_vlan_enable=True,
                                      in_dl_vlan_enable=True,
                                      out_vlan_vid=6,
                                      in_vlan_vid=3)

        output_pkt = simple_tcp_packet_two_vlan(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      out_dl_vlan_enable=True,
                                      in_dl_vlan_enable=True,
                                      out_vlan_vid=6,
                                      in_vlan_vid=4)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)   



class vlan_translate(base_tests.SimpleDataPlane):
    """																					 
	[VLAN tanslate]																				
		Swap incoming tagged packet to a specified VLAN tag																			
																					
	Inject	eth 1/3	Tag 3, SA000000112233, DA000000113355, V4																		
	Output	eth 1/1	Tag 5, others not change																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=vlan_vid=5 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=3/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=3 write:group=0x50001																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 pop_vlan,output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x30003 goto:60																				
																		
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=vlan_vid=5 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=3/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x50001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 pop_vlan,output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x30003 goto:60")

        input_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                      eth_src="00:00:00:11:22:33",
                                      dl_vlan_enable=True,
                                      vlan_vid=3)

        output_pkt = simple_tcp_packet(eth_dst="00:00:00:11:33:55",
                                       eth_src="00:00:00:11:22:33",
                                       dl_vlan_enable=True,
                                       vlan_vid=5)
        
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)        