import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *


class table_stats(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "stats-table")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["stats"], {}, "Table stats reply nothing")

class port_stats(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "stats-port")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["stats"], {}, "Ports stats reply nothing")

class queue_stats(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "stats-queue")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["stats"], {}, "Queue stats reply nothing")

class flow_stats(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "stats-flow")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["stats"], {}, "Flow stats reply nothing")

class aggr_stats(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "stats-aggr")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["flow_cnt"], 0, "No flow exist")

class group_stats(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "stats-group")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["stats"], {}, "Group stats reply nothing")

class group_desc_stats(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "stats-group-desc")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["stats"], {}, "Group desc stats reply nothing")

class meter_stats(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "stats-meter")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["stats"], {}, "Meter stats reply nothing")

class meter_config(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "meter-config")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["stats"], {}, "Meter config reply nothing")

