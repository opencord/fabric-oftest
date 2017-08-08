
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


class features(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        json_result = apply_dpctl_get_cmd(self, config, "features")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        #self.assertTrue(result["tabs"]==64, "Table size is not correct")
        self.assertNotEqual(result["caps"], 0, "Invalid capabilities")

class get_config(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        json_result = apply_dpctl_get_cmd(self, config, "get-config")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["conf"], {}, "Config reply nothing")

class desc(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        json_result = apply_dpctl_get_cmd(self, config, "stats-desc")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["mfr"], {}, "DESC MFR reply nothing")

class port_desc(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "port-desc")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["port"], {}, "Port DESC reply nothing")

class table_features(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "table-features")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["table_features"], {}, "Table features reply nothing")

class group_features(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "group-features")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]
        self.assertNotEqual(result["types"], 0, "Not support group types")

class meter_features(base_tests.SimpleDataPlane):
    def runTest(self):
        json_result = apply_dpctl_get_cmd(self, config, "meter-features")
        #pprint(json_result)
        result=json_result["RECEIVED"][1]["features"][0]
        self.assertNotEqual(result["max_meter"], 0, "Not support meter")


