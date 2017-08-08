
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
Test the BSN controller connections request
"""
import struct
import unittest
import logging

import oftest
from oftest import config
import oftest.controller as controller
import ofp
import oftest.base_tests as base_tests

from oftest.testutils import *

class BsnControllerConnectionsRequest(base_tests.SimpleProtocol):
    """
    Verify that the switch sends a bsn_controller_connections_reply in response
    to the request
    """
    def runTest(self):
        request = ofp.message.bsn_controller_connections_request()
        response, _ = self.controller.transact(request)
        self.assertIsInstance(response, ofp.message.bsn_controller_connections_reply)
