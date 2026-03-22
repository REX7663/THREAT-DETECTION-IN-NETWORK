# We import rdpcap from scapy to read pcap files
from scapy.all import rdpcap

# We define the path to the pcap file captured from Wireshark
pcap_path = "../Data/traffic.pcapng"

# We read all packets from the pcap file
packets = rdpcap(pcap_path)

# We print total number of packets captured
print("Total packets captured:", len(packets))

# We print summary of first 10 packets to inspect structure
for packet in packets[:10]:
    print(packet.summary())
