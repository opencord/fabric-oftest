"""
Flow expire test case.
Similar to Flow expire test case in the perl test harness.

"""

import logging

import unittest
import random

import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action
import oftest.parse as parse
import basic

from testutils import *
from time import sleep

#@var port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
fe_port_map = None
#@var fe_logger Local logger object
fe_logger = None
#@var fe_config Local copy of global configuration data
fe_config = None

def test_set_init(config):
    """
    Set up function for packet action test classes

    @param config The configuration dictionary; see oft
    """

    basic.test_set_init(config)

    global fe_port_map
    global fe_logger
    global fe_config

    fe_logger = logging.getLogger("flow_expire")
    fe_logger.info("Initializing test set")
    fe_port_map = config["port_map"]
    fe_config = config

class FlowExpire(basic.SimpleDataPlane):
    """
    Verify flow expire messages are properly generated.

    Generate a packet
    Generate and install a matching flow with idle timeout = 1 sec
    Verify the flow expiration message is received
    """
    def runTest(self):
        global fe_port_map

        # TODO: set from command-line parameter
        test_timeout = 60

        of_ports = fe_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        rc = delete_all_flows(self.controller, fe_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        pkt = simple_tcp_packet()
        match = parse.packet_to_flow_match(pkt)
        match.wildcards &= ~ofp.OFPFW_IN_PORT
        self.assertTrue(match is not None, 
                        "Could not generate flow match from pkt")
        act = action.action_output()

        of_ports = fe_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        ingress_port = of_ports[0]
        egress_port  = of_ports[1]
        fe_logger.info("Ingress " + str(ingress_port) + 
                       " to egress " + str(egress_port))
        
        match.in_port = ingress_port
        
        request = message.flow_mod()
        request.match = match
        request.cookie = random.randint(0,9007199254740992)
        request.buffer_id = 0xffffffff
        request.idle_timeout = 1
        request.flags |= ofp.OFPFF_SEND_FLOW_REM
        act.port = egress_port
        self.assertTrue(request.actions.add(act), "Could not add action")
        
        fe_logger.info("Inserting flow")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Error installing flow mod")
        do_barrier(self.controller)

        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED,
                                               timeout=test_timeout)

        self.assertTrue(response is not None, 
                        'Did not receive flow removed message ')

        self.assertEqual(request.cookie, response.cookie,
                         'Cookies do not match')

        self.assertEqual(ofp.OFPRR_IDLE_TIMEOUT, response.reason,
                         'Flow table entry removal reason is not idle_timeout')

        self.assertEqual(match, response.match,
                         'Flow table entry does not match')
        
