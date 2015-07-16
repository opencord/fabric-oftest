"""
Group table test
Verify each group table can created correctly
"""
from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class L2InterfaceGroup(base_tests.SimpleDataPlane):
    def runTest(self):    
       delete_all_flows(self.controller)
       delete_all_groups(self.controller)    

       add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)
       add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)       

class L2McastGroup(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)    
        delete_all_groups(self.controller)    
        
        group_list=add_l2_interface_grouop(self.controller, config["port_map"].keys(), 1,  False, False)       
        add_l2_mcast_group(self.controller, config["port_map"].keys(), 1, 1)
        
        add_l2_interface_grouop(self.controller, config["port_map"].keys(), 2,  False, False)               
        add_l2_mcast_group(self.controller, config["port_map"].keys(), 2, 2)
    

