from scapy.all import sniff
import pandas as pd
from sklearn.ensemble import IsolationForest

packets_data = []

def process_packet(pkt):

    if pkt.haslayer("IP"):

        if pkt.haslayer("TCP"):

            packets_data.append({
                "dst_port": int(pkt["TCP"].dport),
                "pkt_len": len(pkt)
            })

print("Sniffing packets... Press CTRL+C to stop")

sniff(prn=process_packet, store=False)

df = pd.DataFrame(packets_data)

if not df.empty:

    df_grouped = df.groupby("dst_port").agg(
        packet_count=("pkt_len", "count"),
        total_bytes=("pkt_len", "sum"),
        avg_pkt_size=("pkt_len", "mean")
    ).reset_index()

    X = df_grouped[["dst_port", "packet_count", "total_bytes", "avg_pkt_size"]]

    model = IsolationForest(contamination=0.1, random_state=42)
    df_grouped["anomaly"] = model.fit_predict(X)

    print(df_grouped.sort_values("anomaly"))
