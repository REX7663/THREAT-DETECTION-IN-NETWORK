# LOCAL USE ONLY
# This script performs live packet sniffing on the local machine.
# It should NOT be imported into the deployed Streamlit app.

from scapy.all import sniff
import pandas as pd
from sklearn.ensemble import IsolationForest

# We create an empty list to store captured packet data
packets_data = []

# We define a function to process each captured packet
def process_packet(pkt):
    # We only continue if the packet has an IP layer
    if pkt.haslayer("IP"):
        # We only continue if the packet has a TCP layer
        if pkt.haslayer("TCP"):
            # We append the destination port and packet length
            packets_data.append({
                "dst_port": int(pkt["TCP"].dport),
                "pkt_len": len(pkt)
            })

# We print a message to show sniffing has started
print("Sniffing packets... Press CTRL+C to stop")

# We start live sniffing
sniff(prn=process_packet, store=False)

# We convert captured packets into a DataFrame
df = pd.DataFrame(packets_data)

# We continue only if data exists
if not df.empty:
    # We group packets by destination port
    df_grouped = df.groupby("dst_port").agg(
        packet_count=("pkt_len", "count"),
        total_bytes=("pkt_len", "sum"),
        avg_pkt_size=("pkt_len", "mean")
    ).reset_index()

    # We select features for anomaly detection
    X = df_grouped[["dst_port", "packet_count", "total_bytes", "avg_pkt_size"]]

    # We create the Isolation Forest model
    model = IsolationForest(contamination=0.1, random_state=42)

    # We predict anomalies
    df_grouped["anomaly"] = model.fit_predict(X)

    # We print results
    print(df_grouped.sort_values("anomaly"))
else:
    # We print a message if no packets were captured
    print("No packets were captured.")