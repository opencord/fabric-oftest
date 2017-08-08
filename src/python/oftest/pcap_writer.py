
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
Pcap file writer
"""

import struct

PcapHeader = struct.Struct("<LHHLLLL")
PcapPktHeader = struct.Struct("<LLLL")
PPIPktHeader = struct.Struct("<BBHL")
PPIAggregateField = struct.Struct("<HHL")

class PcapWriter(object):
    def __init__(self, filename):
        """
        Open a pcap file
        """
        self.stream = file(filename, 'w')

        self.stream.write(PcapHeader.pack(
            0xa1b2c3d4, # magic
            2, # major
            4, # minor
            0, # timezone offset
            0, # timezone accuracy
            65535, # snapshot length
            192 # PPI linktype
        ))

    def write(self, data, timestamp, port):
        """
        Write a packet to a pcap file

        'data' should be a string containing the packet data.
        'timestamp' should be a float.
        'port' should be an integer port number.
        """
        ppi_len = PPIPktHeader.size + PPIAggregateField.size
        self.stream.write(PcapPktHeader.pack(
            int(timestamp), # timestamp seconds
            int((timestamp - int(timestamp)) * 10**6), # timestamp microseconds
            len(data) + ppi_len, # truncated length
            len(data) + ppi_len # un-truncated length
        ))
        self.stream.write(PPIPktHeader.pack(
            0, # version
            0, # flags
            ppi_len, # length
            1, # ethernet dlt
        ))
        self.stream.write(PPIAggregateField.pack(8, PPIAggregateField.size - 4, port))
        self.stream.write(data)

    def close(self):
        self.stream.close()

if __name__ == "__main__":
    import time
    print("Writing test pcap to test.pcap")
    pcap_writer = PcapWriter("test.pcap")
    pcap_writer.write("\x00\x01\x02\x03\x04\x05\x00\x0a\x0b\x0c\x0d\x0e\x08\x00", time.time(), 42)
    pcap_writer.close()
