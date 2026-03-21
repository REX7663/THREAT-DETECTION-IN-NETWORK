# We import pandas to store packet and flow tables
import pandas as pd

# We import PcapReader from scapy to read pcap and pcapng files safely
from scapy.all import PcapReader


# We define a function to extract packet-level features from a capture file
def extract_packets_from_capture(uploaded_cap):
    # We create an empty list to store packet rows
    rows = []

    # We open the capture using PcapReader (supports both pcap and pcapng)
    reader = PcapReader(uploaded_cap)

    # We iterate through packets one by one
    for pkt in reader:
        # We only process packets that contain an IP layer
        if pkt.haslayer("IP"):
            # We extract the source IP address
            src_ip = pkt["IP"].src

            # We extract the destination IP address
            dst_ip = pkt["IP"].dst

            # We compute packet length in bytes
            pkt_len = len(pkt)

            # We set default protocol and ports
            protocol = "OTHER"
            src_port = None
            dst_port = None

            # If packet has TCP layer, extract TCP ports
            if pkt.haslayer("TCP"):
                # We set protocol to TCP
                protocol = "TCP"
                # We extract source port
                src_port = int(pkt["TCP"].sport)
                # We extract destination port
                dst_port = int(pkt["TCP"].dport)

            # If packet has UDP layer, extract UDP ports
            elif pkt.haslayer("UDP"):
                # We set protocol to UDP
                protocol = "UDP"
                # We extract source port
                src_port = int(pkt["UDP"].sport)
                # We extract destination port
                dst_port = int(pkt["UDP"].dport)

            # We append one row of packet data
            rows.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "pkt_len": pkt_len
            })

    # We convert the list of rows into a DataFrame
    return pd.DataFrame(rows)


# We define a function to aggregate packets into flows
def build_flows(packet_df):
    # If DataFrame is empty, return empty DataFrame
    if packet_df.empty:
        return pd.DataFrame()

    # We drop rows without destination port (non TCP/UDP)
    packet_df = packet_df.dropna(subset=["dst_port"])

    # If nothing remains after dropping, return empty DataFrame
    if packet_df.empty:
        return pd.DataFrame()

    # We convert destination port to integer
    packet_df["dst_port"] = packet_df["dst_port"].astype(int)

    # We group by destination IP, destination port, and protocol to build flows
    flows = packet_df.groupby(["dst_ip", "dst_port", "protocol"]).agg(
        packet_count=("pkt_len", "count"),
        total_bytes=("pkt_len", "sum"),
        avg_pkt_size=("pkt_len", "mean"),
        unique_src_ips=("src_ip", "nunique")
    ).reset_index()

    # We return the flows DataFrame
    return flows