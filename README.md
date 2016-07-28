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
 * i12_17 (master)
 * i19
 * i12
 * ga2.0
 * EA3

The OFDPA release i12_17 is the current stable version utilized by the cord project and is the master branch.
The test case collection for OpenCord are under the folder ofdpa. They are listed under the section Test case collection.

## Installing OFTest

You can check out OFTest with git with the following commands:

    sudo apt-get install python python-pip python-dev python-lxml -y
    sudo pip install ncclient
    sudo pip install scapy pycripto
    sudo apt-get install python-ecdsa git
    git clone git://github.com/opencord/fabric-oftest

## Quick Start

Make sure your switch is running and trying to connect to a controller on the machine where you're running oft (normally port `6653`).

    cd fabric-oftest
    ./oft --list --test-dir=ofdpa flows
    sudo ./oft -V1.3 --test-dir=ofdpa flows.PacketInArp -i 1@veth1 -i 2@veth3

This command assumes you connected the switch port 1 to interface veth1 in the OFtest server and port 2 to veth3

---

## Testing a different release

Don't forget to make sure your switch is attempting to establish a OpenFlow connection to the OFTest server.
To test the ga2.0 release do the following:

    cd fabric-oftest
    git checkout ga2.0
    sudo ./oft -V1.3 --test-dir=ofdpa flows -i 12@eth1 -i 24@eth2

# Test Results

The following tests are implemented and these are their results.

Test Results | i12_1.7 | ga2.0 | EA3
------- | ------- | --- | ----- | ---
/0Ucast | false | ok | ok
/24UnicastTagged | ok | ok | ok
/32UnicastTagged | ok | ok | ok
/24ECMPL3 | ok | ok | ok
/32ECMPL3 | ok | ok | ok
/24ECMPVPN | ok | ok | ok
/32ECMPVPN | ok | ok | ok
/32VPN | ok | ok | ok
/24VPN | ok | ok | ok
EcmpGroupMod | ? | ? | ok
PacketInArp | ok | ok | ok
MTU1500 | ok | ok | ok
MplsTermination | ok | ok | ok
MplsFwd | ? | ok | ok
L2FloodQinQ | ok | ok | ok
L2UnicastTagged | ok | ok | ok
L3McastToL3 | ok | ? | ?
L3McastToL2 | ok | ? | ?
FloodGroupMod | ? | ? | ok
PacketInUDP | ok | ok | ok
Unfiltered | ? | ok | ?

