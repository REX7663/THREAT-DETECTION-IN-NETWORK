# We import time so we can measure time windows (like 10-second batches)
import time

# We import Counter to count destination ports and protocols quickly
from collections import Counter

# We import pandas to organize extracted packet features into a table
import pandas as pd

# We import scapy tools to list interfaces and capture packets
from scapy.all import sniff, get_if_list, IP, TCP, UDP

# We import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest

# -------------------------------
# 1) AUTO-DETECT ACTIVE INTERFACE
# -------------------------------

# We define a function that tries each interface and counts how many packets it sees in a short time
def pick_active_interface(test_seconds=2):
    # We get the list of interfaces available on the machine
    interfaces = get_if_list()

    # We create a dictionary to store packet counts for each interface
    counts = {}

    # We loop through each interface name/device id
    for iface in interfaces:
        # We try capturing packets on that interface, but some interfaces may fail (permission/unsupported)
        try:
            # We sniff for a short time and count packets (store=0 keeps memory usage low)
            pkt_count = sniff(iface=iface, timeout=test_seconds, store=0).__len__()
            # We store the count for this interface
            counts[iface] = pkt_count
        except Exception:
            # If an interface fails, we treat it as 0 packets
            counts[iface] = 0

    # We choose the interface with the highest packet count
    best_iface = max(counts, key=counts.get)

    # We return the best interface and the counts for debugging
    return best_iface, counts

# ---------------------------------------
# 2) EXTRACT FEATURES FROM LIVE PACKETS
# ---------------------------------------

# We define a function that converts scapy packets into feature rows
def packets_to_features(packets):
    # We create an empty list to store feature rows
    rows = []

    # We loop through every captured packet
    for pkt in packets:
        # We only process packets that have an IP layer (so we ignore non-IP frames)
        if IP in pkt:
            # We extract source and destination IP addresses
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # We get packet length (helps detect unusual payload sizes)
            pkt_len = len(pkt)

            # Default values if no TCP/UDP
            proto = "OTHER"
            dst_port = -1

            # If packet has TCP, extract destination port
            if TCP in pkt:
                proto = "TCP"
                dst_port = int(pkt[TCP].dport)

            # If packet has UDP, extract destination port
            elif UDP in pkt:
                proto = "UDP"
                dst_port = int(pkt[UDP].dport)

            # We add one row (one packet feature record)
            rows.append({
                "src_ip": src_ip,     # Source IP
                "dst_ip": dst_ip,     # Destination IP
                "protocol": proto,    # Protocol type
                "dst_port": dst_port, # Destination port (or -1 if not TCP/UDP)
                "length": pkt_len     # Packet length
            })

    # We convert the rows list into a DataFrame for easy analysis
    return pd.DataFrame(rows)

# ---------------------------------------
# 3) BUILD NUMERIC FEATURES FOR THE MODEL
# ---------------------------------------

# We define a function that takes the packet table and builds numeric ML features
def build_ml_features(df):
    # We create a copy so we don’t modify original unexpectedly
    df = df.copy()

    # We convert protocol to numeric values (TCP=1, UDP=2, OTHER=0)
    df["proto_num"] = df["protocol"].apply(lambda p: 1 if p == "TCP" else (2 if p == "UDP" else 0))

    # We mark whether the port is "high" (often dynamic/ephemeral when used as destination)
    df["is_high_port"] = df["dst_port"].apply(lambda p: 1 if p >= 49152 else 0)

    # We bucket ports into ranges (0=well-known, 1=registered, 2=dynamic, -1=unknown/no port)
    df["port_bucket"] = df["dst_port"].apply(
        lambda p: -1 if p < 0 else (0 if p <= 1023 else (1 if p <= 49151 else 2))
    )

    # We select final numeric columns to train/predict
    X = df[["dst_port", "length", "proto_num", "is_high_port", "port_bucket"]].copy()

    # We return numeric matrix and enriched df
    return X, df

# ---------------------------------------
# 4) LIVE MONITOR LOOP + ALERTS
# ---------------------------------------

# We define the main live detection function
def live_detect(iface, window_seconds=10, contamination=0.10):
    # We print which interface we are listening on
    print(f"✅ Monitoring interface: {iface}")

    # We print instructions for stopping
    print("Press CTRL + C to stop.\n")

    # We create the Isolation Forest model once and re-train every window (simple near real-time)
    model = IsolationForest(
        n_estimators=300,         # Many trees for stability
        contamination=contamination,  # Expected anomaly rate
        random_state=42           # Reproducible behavior
    )

    # We start an infinite loop (until user stops)
    while True:
        # We show a message that we are capturing a new time window
        print(f"--- Capturing {window_seconds}s of traffic ---")

        # We capture packets for the given time window (store=1 keeps them in memory for processing)
        packets = sniff(iface=iface, timeout=window_seconds, store=1)

        # If we captured nothing, we just continue
        if len(packets) == 0:
            print("No packets captured in this window.\n")
            continue

        # Convert packets to a feature table
        df = packets_to_features(packets)

        # If the table is empty (no IP packets), continue
        if df.empty:
            print("No IP packets found in this window.\n")
            continue

        # Build numeric ML features
        X, df2 = build_ml_features(df)

        # Train the model on this window’s traffic (near real-time adaptation)
        model.fit(X)

        # Predict anomalies for this same window
        df2["anomaly"] = model.predict(X)

        # Compute anomaly score (lower = more suspicious)
        df2["anomaly_score"] = model.decision_function(X)

        # Filter anomalies only
        anomalies = df2[df2["anomaly"] == -1].sort_values("anomaly_score", ascending=True)

        # Print summary counts
        print(f"Packets captured: {len(df2)} | Suspicious packets: {len(anomalies)}")

        # If anomalies exist, print top alerts
        if not anomalies.empty:
            # Show the top 10 suspicious packets
            top = anomalies.head(10)

            # Print an alert header
            print("⚠️  TOP SUSPICIOUS TRAFFIC (this window):")

            # Print each suspicious packet line
            for _, row in top.iterrows():
                print(
                    f"  - {row['protocol']} {row['src_ip']} -> {row['dst_ip']} "
                    f"dst_port={row['dst_port']} len={row['length']} "
                    f"score={row['anomaly_score']:.4f}"
                )

            # Show most common suspicious destination ports
            suspicious_ports = [p for p in anomalies["dst_port"].tolist() if p >= 0]
            port_counts = Counter(suspicious_ports)

            # If we have ports, print top 5
            if len(port_counts) > 0:
                print("⚠️  Most common suspicious destination ports:", port_counts.most_common(5))

        # Print a blank line for readability before next window
        print()

# -----------------------
# 5) PROGRAM ENTRY POINT
# -----------------------

# This block runs only when you execute this file directly
if __name__ == "__main__":
    # We auto-detect the interface with the most traffic
    best_iface, counts = pick_active_interface(test_seconds=2)

    # We print packet counts found during auto-detection
    print("Interface packet counts (auto-detect test):")
    for k, v in counts.items():
        print(f"  {k}: {v}")

    # We print the chosen interface
    print(f"\n✅ Auto-selected active interface: {best_iface}\n")

    # Start live detection on the selected interface
    live_detect(iface=best_iface, window_seconds=10, contamination=0.10)
