
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


import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr
"""	
    [Allow all VLAN and unicast route]																				
		Whatever incoming VLAN tag, do unicast route and output to specified port																			
																					
	Inject	eth 1/3	Tag3, SA000000112233, DA000000113355, SIP 192.168.1.100, DIP 192.168.2.2																		
	Output	eth 1/1	Tag2, SA 000004223355, DA 000004224466																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1000/0x1000 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x20000001 goto:60																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 pop_vlan,output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x30003 goto:60																				
"""

class test1(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1000/0x1000 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x20000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x20000001 goto:60")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(input_port)+" group=any,port=any,weight=0 pop_vlan,output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x3000"+str(input_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 52 00 01 00 00 40 06 f5 ee c0 a8 '
                '01 64 c0 a8 02 02 04 d2 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 6c 46 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '08 00 45 00 00 52 00 01 00 00 3f 06 f6 ee c0 a8 '
                '01 64 c0 a8 02 02 04 d2 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 6c 46 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        
        
        
        
        
        