OFTest OpenFlow Testing Framework

---

# Introduction

OFTest is a Python based framework for OpenFlow switch testing.

In this project we use OFTest to ensure OpenFlow conformance of the switches used to implement the network infrastructure of the OpenCord project.

At this moment the switches supported are OF-DPA based Accton switches. For more information, check the wiki page at wiki.opencord.org/display/CORD/Underlay+Fabric

This code base was forked from [macauleycheng](github.com/macauleycheng/oftest) which was forked from [floodlight](github.com/floodlight/oftest). This documentationn aims to describe the specific test cases developed for OpenCord. To get started on the basics of OFTest please check their documentation.

---

## How it is organized

This codebase is organized by branches. Each OFDPA release correspond to a different branch. At this moment the following releases are available:

OFDPA version | Branch     | Status
------------- | ---------- | ------
i19           | i19        | Archived
i12           | i12        | Archived
i12_1.7       | cord-1.0   | Released
2.0 GA        | 2.0-ga     | Archived
**3.0 EA4**   | **master** | **Developing <- current branch**

The test case collection for OpenCord are under the folder ofdpa. They are listed under the section Test case collection.

## Installing Prerequisites

Following packages need to be installed before running OFTest:

```
sudo apt-get install python python-pip python-dev python-lxml -y
sudo pip install ncclient
sudo pip install scapy pycripto
sudo apt-get install python-ecdsa git
```

## Start Testing

On the switch side (for OF-DPA version 3.0 EA4):

1. Connect the switch to the VM running OFTest on the management network

	```
	launcher ofagentapp  -t <controller_ip>
	```

On the controller side:

1. Clone the source code and switch to the correct branch

	```
	git clone -b master git://github.com/opencord/fabric-oftest
	```

2. Run all test cases (that are not disabled) in a sequence

	```
	sudo ./oft -V1.3 --test-dir=ofdpa flows -i 24@eth1 -i 12@eth2
	```
	This command assumes you connected the switch port 24 to interface eth1 on the OFtest server and port 12 to eth2.
	It runs all the tests that are in ofdpa/flows.py

## Useful commands

* List all available test cases

	```
	./oft -V1.3 --list --test-dir=ofdpa flows
	```

* Run only specific test case. Can also be used to run tests that are currently disabled.

	```
	sudo ./oft -V1.3 --test-dir=ofdpa flows.PacketInArp -i 24@eth1 -i 12@eth2
	```

* Run specific test case for a specific switch type (only special case of switch type supported are Qumran based switches)

	```
	sudo ./oft -V1.3 -Y qmx --test-dir=ofdpa flows.PacketInArp -i 24@eth1 -i 12@eth2
	```

---

# Test Result Summary

The following tests are implemented and these are their results.

Test Results       | i12_1.7 | 2.0 GA | 3.0 EA0 | 3.0 EA4 | 3.0 EA4 QMX |
-------            | ------- | ------ | ------- | ------- |-------------
/0Ucast            | X       | ok     | ok      | ok      | X           |
/24UnicastTagged   | ok      | ok     | ok      | ok      | X           |
/32UnicastTagged   | ok      | ok     | ok      | ok      | X           |
/24ECMPL3          | ok      | ok     | ok      | ok      | X           |
/32ECMPL3          | ok      | ok     | ok      | ok      | X           |
/24ECMPVPN~        | ok      | ok     | ok      | ok      | X           |
/32ECMPVPN~        | ok      | ok     | ok      | ok      | X           |
/32VPN~            | ok      | ok     | ok      | ok      | X           |
/24VPN~            | ok      | ok     | ok      | ok      | X           |
EcmpGroupMod       | X       | X      | ok      | ok      | X           |
PacketInArp        | ok      | ok     | ok      | ok      | ok          |
MTU1500            | ok      | ok     | ok      | ok      | ok          |
MplsTermination~   | ok      | ok     | ok      | ok      | X           |
MplsFwd~           | X       | ok     | ok      | ok      | ok          |
L2FloodQinQ        | ok      | ok     | ok      | ok      | X           |
L2UnicastTagged    | ok      | ok     | ok      | ok      | ok          |
L3McastToL3        | ok      | X      | ok      | ok      | X           |
L3McastToL2_1*     | ?       | ?      | ok      | ok      | X           |
L3McastToL2_2**    | ?       | ?      | ok      | ok      | X           |
L3McastToL2_3***   | ?       | ?      | ok      | ok      | X           |
L3McastToL2_4****  | ok      | ?      | ok      | ok      | X           |
L3McastToL2_5***** | ?       | ?      | ok      | ok      | X           |
FloodGroupMod      | X       | X      | ok      | ok      | X           |
PacketInUDP        | ok      | ok     | ok      | ok      | ok          |
Unfiltered         | X       | ok     | X       | ok      | ok          |
Untagged           | ok      | n/a    | ok      | ok      | ok          |
PacketInIPTable~   | X       | X      | ok      | ok      | X           |

```
~       Tests marked with tilda are currently disabled because of a bug which causes
        interference with other tests. The @disabled flag will be removed once the bug is fixed.
*       Untag -> Untag (4094 as internal vlan)
**      Untag -> Tag
***     Tag   -> Untag
****    Tag   -> Tag
*****   Tag   -> Tag (Translated)
```

n/a means test is not available for that version of the pipeline.

# VLAN Test Result Summary

The following tests are implemented in vlan_flows.py and these are their results.

Test Results                | 3.0 EA0 | 3.0 EA4 |
------------------------    | ------- | ------- |
L2ForwardingStackedVLAN     | ok      | ok      |
L2ForwardingStackedVLAN2    | ok      | ok      |
L2ForwardingStackedVLAN3    | ok      | ok      |
L2ForwardingStackedVLAN4    | ok      | ok      |
L2ForwardingStackedVLAN5    | ok      | ok      |

For major details on the test look the comments in the code.

# Pseudowire Test Result Summary

The following tests are implemented in pw_flows.py and these are their results.

Test Results                            | 3.0 EA0 | 3.0 EA4 |
----------------------------------      | ------- | ------- |
UntaggedPWInitiation_2_Labels           | ok      | ok      |
Untagged2PWInitiation_2_Labels          | ok      | ok      |
UntaggedPWInitiation_3_Labels           | ok      | ok      |
Untagged2PWInitiation_3_Labels          | ok      | ok      |
TaggedPWInitiation_2_Labels             | x       | ok*     |
Tagged2PWInitiation_2_Labels            | x       | ok*     |
TaggedPWInitiation_3_Labels             | x       | ok*     |
Tagged2PWInitiation_3_Labels            | x       | ok*     |
DoubleTaggedPWInitiation_2_Labels       | x       | ok*     |
DoubleTagged2PWInitiation_2_Labels      | x       | ok*     |
DoubleTaggedPWInitiation_3_Labels       | x       | ok*     |
DoubleTagged2PWInitiation_3_Labels      | x       | ok*     |
IntraCO_2_Labels                        | ok      | ok*     |
IntraCO_3_Labels                        | ok      | ok*     |
InterCO                                 | ok      | ok*     |
UntaggedPWTermination                   | ok      | ok      |
Untagged2PWTermination                  | x       | x       |
TaggedPWTermination                     | ok      | ok      |
DoubleTaggedPWTermination               | ok      | ok      |
BoSBug                                  | x       | x       |

* The test may fail intermittently

For major details on the test look the comments in the code.

# IPv6 Test Result Summary

The following tests are implemented in ipv6_flows.py and these are their results.

Test Results                | 3.0 EA0 | 3.0 EA4 |
----------------------      | ------- | ------- |
PacketInICMPv6              | ok      | ok      |
PacketInIPv6Table           | ok      | ok      |
_128UcastUnTagged           | ok      | ok      |
_128ECMPVpn                 | ok      | ok      |
_128ECMPL3                  | ok      | ok      |
_64UcastUntagged            | ok      | ok      |
_64ECMPVpn                  | ok      | ok      |
_64ECMPL3                   | ok      | ok      |
_0UcastV6                   | ok      | ok      |
_MPLSTerminationV6          | ok      | ok      |

For major details on the test look the comments in the code.
