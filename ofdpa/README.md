Run the following command from the oftest folder

    sudo ./oft -V1.3 --test-dir=ofdpa onos -i 33@ethX -i 34@ethY

Where 33 is the Openflow port you want to test, and ethX identifies the interface connected to it.

The onos filename was chosen because these tests are being made to guarantee conformance with ONOS southbound API.

The following test cases are implemented:

Flow Test
1) PacketInSrcMacMiss
2) L2FloodTagged
3) L2Flood Tagged Unknown Src
4) L2 Unicast Tagged
5) L3 Unicast Tagged
6) MTU 1500
7) MTU 4100
8) MTU 4500

