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

@disabled 
class Purge(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        do_barrier(self.controller)
        add_vlan_table_flow(self.controller, config["port_map"].keys(), 1)
        verify_no_other_packets(self)
           
@disabled 
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

class TagFlow20to10(base_tests.SimpleDataPlane):
    def runTest(self):
        do_barrier(self.controller)
        for port in config["port_map"].keys():
            add_one_vlan_table_flow(self.controller, port, 10, flag=VLAN_TABLE_FLAG_ONLY_BOTH)
            do_barrier(self.controller)
            logging.info("Sending flow stats request")
            stats = get_flow_stats(self, ofp.match())
            print "STATS"
            for entry in stats:
                print(entry.show())
            print "END"
        do_barrier(self.controller)
        verify_no_other_packets(self)

@disabled
class UnTagFlow0(base_tests.SimpleDataPlane):
    def runTest(self):
        do_barrier(self.controller)
        for port in config["port_map"].keys():
            add_untag_vlan_table_flow(self.controller, port, 0x0000, 0x1000)
            do_barrier(self.controller)
            logging.info("Sending flow stats request")
            stats = get_flow_stats(self, ofp.match())
            print "STATS"
            for entry in stats:
                print(entry.show())
            print "END"
        do_barrier(self.controller)
        verify_no_other_packets(self)

@disabled
class UnTagFlow10(base_tests.SimpleDataPlane):
    def runTest(self):
        do_barrier(self.controller)
        for port in config["port_map"].keys():
            add_untag_vlan_table_flow(self.controller, port, 0x0000, 0x1fff)
            do_barrier(self.controller)
            logging.info("Sending flow stats request")
            stats = get_flow_stats(self, ofp.match())
            print "STATS"
            for entry in stats:
                print(entry.show())
            print "END"
        do_barrier(self.controller)
        verify_no_other_packets(self)


@disabled
class UnTagFlow1(base_tests.SimpleDataPlane):
    def runTest(self):
        do_barrier(self.controller)
        for port in config["port_map"].keys():
            add_untag_vlan_table(self.controller, port)
            do_barrier(self.controller)
            logging.info("Sending flow stats request")
            stats = get_flow_stats(self, ofp.match())
            print "STATS"
            for entry in stats:
                print(entry.show())
            print "END"
        do_barrier(self.controller)
        verify_no_other_packets(self)
