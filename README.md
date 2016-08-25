OFTest OpenFlow Testing Framework

---

# Introduction

OFTest is a Python based framework for OpenFlow switch testing.

In this project we use OFTest to ensure OpenFlow conformance of the switches used to implement the network infrastructure of the OpenCord project.

At this moment the switches supported are Accton switches. For more information abot that check the wiki page at wiki.opencord.org

This code base was forked from [macauleycheng](github.com/macauleycheng/oftest) which was forked from [floodlight](github.com/floodlight/oftest). This documentationn aims to describe the specific test cases developed for OpenCord. To get started on the basics of OFTest please check their documentation.

---

## How it is organized

This codebase is organized by branches. Each OFDPA release correspond to a different branch. At this moment the following releases are available:

OFDPA version | Branch       | Status
------------- | ------------ | ------
i19           | i19          | Archived
i12           | i12          | Archived
**i12_1.7**   | **cord-1.0** | **Released <- current branch**
2.0 GA        | 2.0-ga       | Archived
3.0 EA0       | master       | Developing

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

On the switch side:

1. Purge the switch flow/group table by running

	```
	client_cfg_purge
	```

2. Connect the switch to the testing controller

	```
	brcm-indigo-ofdpa-ofagent -t <controller_ip>
	```

On the controller side:

1. Clone the source code and switch to the correct branch

	```
	git clone -b cord-1.0 git://github.com/opencord/fabric-oftest
	```

2. Run **all test cases** in OFTest

	```
	sudo ./oft -V1.3 --test-dir=ofdpa flows -i 24@eth1 -i 12@eth2
	```
	This command assumes you connected the switch port 24 to interface eth1 on the OFtest server and port 12 to eth2

## Useful commands

* List all available test cases

	```
	./oft --list --test-dir=ofdpa flows
	```

* Run only specific test case

	```
	sudo ./oft -V1.3 --test-dir=ofdpa flows.PacketInArp -i 24@eth1 -i 12@eth2
	```

---

# Test Result Summary

The following tests are implemented and these are their results.

Test Results       | i12_1.7 | 2.0 GA | 3.0 EA0
-------            | ------- | ------ | -------
/0Ucast            | X       | ok     | ok
/24UnicastTagged   | ok      | ok     | ok
/32UnicastTagged   | ok      | ok     | ok
/24ECMPL3          | ok      | ok     | ok
/32ECMPL3          | ok      | ok     | ok
/24ECMPVPN         | ok      | ok     | ok
/32ECMPVPN         | ok      | ok     | ok
/32VPN             | ok      | ok     | ok
/24VPN             | ok      | ok     | ok
EcmpGroupMod       | X       | X      | ok
PacketInArp        | ok      | ok     | ok
MTU1500            | ok      | ok     | ok
MplsTermination    | ok      | ok     | ok
MplsFwd            | X       | ok     | ok
L2FloodQinQ        | ok      | ok     | ok
L2UnicastTagged    | ok      | ok     | ok
L3McastToL3        | ok      | X      | ?
L3McastToL2_1*     | ok      | ?      | ?
L3McastToL2_2**    | ok      | ?      | ?
L3McastToL2_3***   | ok      | ?      | ?
L3McastToL2_4****  | ok      | ?      | ?
L3McastToL2_5***** | ok      | ?      | ok
FloodGroupMod      | X       | X      | ok
PacketInUDP        | ok      | ok     | ok
Unfiltered         | X       | ok     | X
Untagged           | ok      | n/a    | ok

*       Untag -> Untag (4094 as internal vlan)
**      Untag -> Tag
***     Tag   -> Untag
****    Tag   -> Tag
*****   Tag   -> Tag (Translated)

n/a means test is not available for that version of the pipeline.