
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
Latency tests

These tests are mostly helpful for finding an optimal value for the
--default-negative-timeout option. If this value is too large it will
unnecessarily some down testing, but if it is too small then tests
may pass when they should have failed.

Most of this latency is caused by OFTest. Actual switch latency should be just
a few microseconds, but OFTest can add milliseconds on top of that.
"""

import logging
import unittest
import time

from oftest import config
import ofp
import oftest.base_tests as base_tests

from oftest.testutils import *

class DataplaneLatency(base_tests.SimpleDataPlane):
    """
    Measure and assert dataplane latency

    All packets must arrive within the default timeout, and 90% must
    arrive within the default negative timeout.
    """
    def runTest(self):
        in_port, out_port = openflow_ports(2)

        delete_all_flows(self.controller)

        pkt = str(simple_tcp_packet())

        request = ofp.message.flow_add(
            match=ofp.match(wildcards=ofp.OFPFW_ALL),
            buffer_id=0xffffffff,
            actions=[ofp.action.output(out_port)])
        
        self.controller.message_send(request)
        do_barrier(self.controller)

        latencies = []
        for i in xrange(0, 1000):
            start_time = time.time()
            self.dataplane.send(in_port, pkt)
            verify_packet(self, pkt, out_port)
            end_time = time.time()
            latencies.append(end_time - start_time)

        latencies.sort()
        
        latency_min = latencies[0]
        latency_90 = latencies[int(len(latencies)*0.9)]
        latency_max = latencies[-1]

        logging.debug("Minimum latency: %f ms", latency_min * 1000.0)
        logging.debug("90%% latency: %f ms", latency_90 * 1000.0)
        logging.debug("Maximum latency: %f ms", latency_max * 1000.0)

        self.assertGreater(config["default_timeout"], latency_max)
        self.assertGreater(config["default_negative_timeout"], latency_90)

class PktinLatency(base_tests.SimpleDataPlane):
    """
    Measure and assert packet-in latency

    All packet-ins must arrive within the default timeout, and 90% must
    arrive within the default negative timeout.
    """
    def runTest(self):
        in_port, = openflow_ports(1)

        delete_all_flows(self.controller)

        pkt = str(simple_tcp_packet())

        request = ofp.message.flow_add(
            match=ofp.match(wildcards=ofp.OFPFW_ALL),
            buffer_id=0xffffffff,
            actions=[ofp.action.output(ofp.OFPP_CONTROLLER)])
        
        self.controller.message_send(request)
        do_barrier(self.controller)

        latencies = []
        for i in xrange(0, 1000):
            start_time = time.time()
            self.dataplane.send(in_port, pkt)
            verify_packet_in(self, pkt, in_port, ofp.OFPR_ACTION)
            end_time = time.time()
            latencies.append(end_time - start_time)

        latencies.sort()
        
        latency_min = latencies[0]
        latency_90 = latencies[int(len(latencies)*0.9)]
        latency_max = latencies[-1]

        logging.debug("Minimum latency: %f ms", latency_min * 1000.0)
        logging.debug("90%% latency: %f ms", latency_90 * 1000.0)
        logging.debug("Maximum latency: %f ms", latency_max * 1000.0)

        self.assertGreater(config["default_timeout"], latency_max)
        self.assertGreater(config["default_negative_timeout"], latency_90)
