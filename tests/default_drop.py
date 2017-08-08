
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
These tests require a switch that drops packet-ins.
"""

import logging

from oftest import config
import oftest.controller as controller
import ofp
import oftest.dataplane as dataplane
import oftest.base_tests as base_tests

from oftest.testutils import *

@nonstandard
class PacketInDefaultDrop(base_tests.SimpleDataPlane):
    """
    Verify that packet-ins are not received.
    """

    def runTest(self):
        delete_all_flows(self.controller)
        do_barrier(self.controller)

        for of_port in config["port_map"].keys():
            pkt = str(simple_tcp_packet())
            self.dataplane.send(of_port, pkt)
            verify_no_packet_in(self, pkt, of_port)
