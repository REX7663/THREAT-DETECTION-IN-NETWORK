# We import os to build reliable file paths and create folders
import os

# We import rdpcap from scapy to read packets from a pcap/pcapng file
from scapy.all import rdpcap

# We import pandas to store extracted packet features as a table
import pandas as pd

# -----------------------------
# BUILD CORRECT PROJECT PATHS
# -----------------------------

# We get the folder where THIS script is located (src/scripts/pcap)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# We move up three folders to reach the project root (ThreatDetectionProject)
# pcap -> scripts -> src -> ThreatDetectionProject
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", ".."))

# We build the full path to the Data folder inside the project root
DATA_DIR = os.path.join(PROJECT_ROOT, "Data")

# We build the full path to the output folder inside the project root
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")

# We define the full path to the pcapng file saved from Wireshark
PCAP_PATH = os.path.join(DATA_DIR, "traffic.pcapng")

# We define the full path where extracted features will be saved
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "pcap_features.csv")

# -----------------------------
# VALIDATION / SAFETY CHECKS
# -----------------------------

# We create the output directory if it does not exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# We check if the pcap file exists before trying to read it
if not os.path.exists(PCAP_PATH):
    # We raise a clear error message showing the expected location
    raise FileNotFoundError(f"❌ PCAP file not found at: {PCAP_PATH}")

# -----------------------------
# LOAD PACKETS FROM PCAPNG
# -----------------------------

# We load all packets from the pcap file
packets = rdpcap(PCAP_PATH)

# We print how many packets were loaded
print("✅ Total packets loaded:", len(packets))

# -----------------------------
# EXTRACT PACKET FEATURES
# -----------------------------

# We create an empty list to store extracted packet features
rows = []

# We loop through each packet in the capture
for pkt in packets:
    # We check if the packet contains an IP layer (so it is an IP packet)
    if pkt.haslayer("IP"):
        # We extract the source IP address
        src_ip = pkt["IP"].src

        # We extract the destination IP address
        dst_ip = pkt["IP"].dst

        # We compute packet length in bytes
        pkt_len = len(pkt)

        # We initialize protocol and ports
        proto = "OTHER"
        src_port = None
        dst_port = None

        # If packet contains TCP layer, extract TCP ports
        if pkt.haslayer("TCP"):
            # Set protocol label to TCP
            proto = "TCP"
            # Extract source port
            src_port = int(pkt["TCP"].sport)
            # Extract destination port
            dst_port = int(pkt["TCP"].dport)

        # Else if packet contains UDP layer, extract UDP ports
        elif pkt.haslayer("UDP"):
            # Set protocol label to UDP
            proto = "UDP"
            # Extract source port
            src_port = int(pkt["UDP"].sport)
            # Extract destination port
            dst_port = int(pkt["UDP"].dport)

        # We append one extracted record (one row)
        rows.append({
            "src_ip": src_ip,        # Source IP address
            "dst_ip": dst_ip,        # Destination IP address
            "protocol": proto,       # Protocol: TCP/UDP/OTHER
            "src_port": src_port,    # Source port (TCP/UDP) or None
            "dst_port": dst_port,    # Destination port (TCP/UDP) or None
            "pkt_len": pkt_len       # Packet length
        })

# We convert the list of rows into a DataFrame
df = pd.DataFrame(rows)

# -----------------------------
# SAVE RESULTS
# -----------------------------

# We save the DataFrame to CSV in the output folder
df.to_csv(OUTPUT_CSV, index=False)

# We print confirmation message with the real full path
print("✅ Extracted packet features saved to:", OUTPUT_CSV)

# We print the first 10 rows so you can confirm the output structure
print(df.head(10))