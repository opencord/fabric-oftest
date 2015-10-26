import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *


class features(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
      
        json_result = apply_dpctl_get_cmd(self, config, "features")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertTrue(result["tabs"]==64, "Table size is not correct")
        
class get_config(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
      
        json_result = apply_dpctl_get_cmd(self, config, "get-config")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["conf"], {}, "Config reply nothing")        
        
        