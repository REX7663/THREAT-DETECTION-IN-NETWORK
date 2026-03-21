# We import subprocess so we can run tshark from Python
import subprocess

# We import pandas to structure packet data into a table
import pandas as pd

# We import time to create fixed monitoring windows
import time

# We import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest

# -----------------------------
# SETTINGS
# -----------------------------

# We use interface number 4 because tshark -D showed Wi-Fi is number 4
TSHARK_INTERFACE_NUMBER = "4"

# Each analysis window will last 10 seconds
WINDOW_SECONDS = 10

# We expect around 10% anomalies
CONTAMINATION = 0.10

# -----------------------------
# BUILD TSHARK COMMAND
# -----------------------------

# We define the tshark command with full path (important on your system)
tshark_cmd = [
    r"C:\Program Files\Wireshark\tshark.exe",  # Full path to tshark
    "-l",                                      # Line-buffered output (important for live)
    "-i", TSHARK_INTERFACE_NUMBER,             # Interface number
    "-T", "fields",                            # Output specific fields
    "-E", "separator=,",                       # Use comma separator
    "-e", "ip.src",                            # Source IP
    "-e", "ip.dst",                            # Destination IP
    "-e", "tcp.dstport",                       # TCP destination port
    "-e", "udp.dstport",                       # UDP destination port
    "-e", "ip.proto",                          # Protocol number
    "-e", "frame.len"                          # Packet length
]

# We start tshark as a subprocess
process = subprocess.Popen(
    tshark_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

# We create the Isolation Forest model
model = IsolationForest(
    n_estimators=300,
    contamination=CONTAMINATION,
    random_state=42
)

# We create an empty buffer to store packets for each window
buffer_rows = []

# Mark the start of the first window
window_start = time.time()

print("✅ Live Wireshark monitoring started (Wi-Fi).")
print("Press CTRL + C to stop.\n")

try:
    while True:
        # Read one line of tshark output
        line = process.stdout.readline()

        if not line:
            continue

        line = line.strip()
        parts = line.split(",")

        # We ensure enough fields exist
        if len(parts) < 6:
            continue

        src_ip = parts[0]
        dst_ip = parts[1]
        tcp_dport = parts[2]
        udp_dport = parts[3]
        proto = parts[4]
        frame_len = parts[5]

        # Determine destination port
        dst_port = -1
        if tcp_dport.isdigit():
            dst_port = int(tcp_dport)
        elif udp_dport.isdigit():
            dst_port = int(udp_dport)

        # Convert protocol and length safely
        proto_num = int(proto) if proto.isdigit() else 0
        pkt_len = int(frame_len) if frame_len.isdigit() else 0

        # Store this packet in the buffer
        buffer_rows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto_num": proto_num,
            "length": pkt_len
        })

        # Check if 10-second window finished
        now = time.time()
        if now - window_start >= WINDOW_SECONDS:

            if len(buffer_rows) == 0:
                window_start = now
                continue

            df = pd.DataFrame(buffer_rows)

            # Build additional numeric features
            df["is_high_port"] = df["dst_port"].apply(lambda p: 1 if p >= 49152 else 0)
            df["port_bucket"] = df["dst_port"].apply(
                lambda p: -1 if p < 0 else (0 if p <= 1023 else (1 if p <= 49151 else 2))
            )

            X = df[["dst_port", "length", "proto_num", "is_high_port", "port_bucket"]]

            # Train model on this window
            model.fit(X)

            # Predict anomalies
            df["anomaly"] = model.predict(X)
            df["anomaly_score"] = model.decision_function(X)

            anomalies = df[df["anomaly"] == -1].sort_values("anomaly_score")

            print(f"--- Window {WINDOW_SECONDS}s ---")
            print(f"Packets: {len(df)} | Suspicious: {len(anomalies)}")

            if not anomalies.empty:
                print("⚠️ Top suspicious traffic:")
                for _, row in anomalies.head(10).iterrows():
                    print(
                        f"  - {row['src_ip']} -> {row['dst_ip']} "
                        f"dst_port={row['dst_port']} len={row['length']} "
                        f"score={row['anomaly_score']:.4f}"
                    )
            print()

            # Reset for next window
            buffer_rows = []
            window_start = now

except KeyboardInterrupt:
    print("\nStopping...")

finally:
    process.terminate()
