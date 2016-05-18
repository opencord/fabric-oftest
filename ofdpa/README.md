Run the following command from the oftest folder

    sudo ./oft -V1.3 --test-dir=ofdpa onos -i 33@ethX -i 34@ethY

Where 33 is the Openflow port you want to test, and ethX identifies the interface connected to it.

The onos filename was chosen because these tests are being made to guarantee conformance with ONOS southbound API.

The following test cases are implemented:

The following tests are being done here
1. PacketIn UDP
2. PacketIn ARP
3. PacketIn from IP table
4. L2FloodQinQ
5. L2 Unicast Tagged
6. MTU 1500
7. /32 L3 Unicast
8. /32 L3 VPN initiation
9. /32 L3 ECMP + VPN
10. /32 L3 ECMP forwarding + L3 unicast
11. /24 L3 Unicast
12. /24 L3 VPN initiation
13. /24 L3 ECMP + VPN
14. /24 L3 ECMP forwarding + L3 unicast
15. Multicast same VLAN
16. Multicast different VLANS
17. MPLS forwarding
18. MPLS termination
19. /0 Unicast
20. Unfiltered group (Incomplete)
21. Multicast to VPN initiation
22. PacketInSrcMacMiss