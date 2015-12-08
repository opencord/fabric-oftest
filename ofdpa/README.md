Run the following command from the oftest folder

    sudo ./oft -V1.3 --test-dir=ofdpa onos -i 33@ethX -i 34@ethY

Where 33 is the Openflow port you want to test, and ethX identifies the interface connected to it.

The onos filename was chosen because these tests are being made to guarantee conformance with ONOS southbound API.

The following test cases are implemented:

The following tests are being done here
1. PacketInSrcMacMiss
2. VlanSupport
3. L2FloodQinQ
4. L2FloodTagged
5. L2Flood Tagged Unknown Src
6. L2 Unicast Tagged
7. MTU 1500
8. MTU 4100
9. MTU 4500
10. L3UnicastTagged
11. L3VPNMPLS
12. MPLS Termination

