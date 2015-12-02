"""
Flow Test
Test each flow table can set entry, and packet rx correctly.
1) L3UcastRoute
2) QinQ
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class Purge(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        do_barrier(self.controller)
        add_vlan_table_flow(self.controller, config["port_map"].keys(), 1)
        verify_no_other_packets(self)
           

class FlowStats(base_tests.SimpleProtocol):
    """
    Flow stats multipart transaction
    Only verifies we get a reply.
    """
    def runTest(self):
        
        logging.info("Sending flow stats request")
        stats = get_flow_stats(self, ofp.match())
        logging.info("Received %d flow stats entries", len(stats))
        for entry in stats:
            print(entry.show())

