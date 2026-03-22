# We import subprocess so we can run tshark and read its live output
import subprocess

# We import pandas to organize packets into tables
import pandas as pd

# We import time for timing baseline and windows
import time

# We import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest

# -----------------------------
# SETTINGS
# -----------------------------

# Wi-Fi interface number from tshark -D
TSHARK_INTERFACE_NUMBER = "4"

# Full path to tshark on your machine
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# Baseline training time in seconds (normal traffic)
BASELINE_SECONDS = 30

# Detection window time in seconds
WINDOW_SECONDS = 10

# Expected anomaly rate (lower = fewer alerts)
CONTAMINATION = 0.05

# -----------------------------
# START TSHARK LIVE CAPTURE
# -----------------------------

# We build a tshark command that ONLY outputs IP + TCP/UDP related fields
tshark_cmd = [
    TSHARK_PATH,                 # Use full path to tshark
    "-l",                        # Line buffered
    "-i", TSHARK_INTERFACE_NUMBER,# Wi-Fi interface
    "-T", "fields",              # Output only fields
    "-E", "separator=,",         # CSV separator
    "-e", "ip.src",              # Source IP
    "-e", "ip.dst",              # Destination IP
    "-e", "tcp.dstport",         # TCP destination port
    "-e", "udp.dstport",         # UDP destination port
    "-e", "ip.proto",            # Protocol number
    "-e", "frame.len"            # Frame length
]

# We start tshark as a background process and capture stdout
process = subprocess.Popen(
    tshark_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

# -----------------------------
# HELPER: PARSE ONE LINE
# -----------------------------

# We define a function that converts one tshark output line into a row dictionary
def parse_tshark_line(line):
    # Remove whitespace
    line = line.strip()

    # Split CSV fields
    parts = line.split(",")

    # If we do not have all fields, return None
    if len(parts) < 6:
        return None

    # Extract fields
    src_ip = parts[0]
    dst_ip = parts[1]
    tcp_dport = parts[2]
    udp_dport = parts[3]
    proto = parts[4]
    frame_len = parts[5]

    # If IP fields are empty, ignore (not IP packet)
    if src_ip == "" or dst_ip == "":
        return None

    # Determine destination port from TCP or UDP
    dst_port = None
    if tcp_dport.isdigit():
        dst_port = int(tcp_dport)
    elif udp_dport.isdigit():
        dst_port = int(udp_dport)
    else:
        # If neither TCP nor UDP port exists, ignore this packet
        return None

    # Convert protocol number safely
    proto_num = int(proto) if proto.isdigit() else 0

    # Convert packet length safely
    pkt_len = int(frame_len) if frame_len.isdigit() else 0

    # Return the parsed row
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto_num": proto_num,
        "length": pkt_len
    }

# -----------------------------
# HELPER: BUILD FEATURES
# -----------------------------

# We define a function to build numeric features used by Isolation Forest
def build_features(df):
    # Add high-port feature
    df["is_high_port"] = df["dst_port"].apply(lambda p: 1 if p >= 49152 else 0)

    # Bucket ports (0=well-known, 1=registered, 2=dynamic)
    df["port_bucket"] = df["dst_port"].apply(lambda p: 0 if p <= 1023 else (1 if p <= 49151 else 2))

    # Build X matrix
    X = df[["dst_port", "length", "proto_num", "is_high_port", "port_bucket"]]

    # Return X and df
    return X, df

# -----------------------------
# 1) BASELINE TRAINING
# -----------------------------

print("✅ Starting BASELINE capture (30 seconds). Please browse normally...")
baseline_rows = []
baseline_start = time.time()

# Capture baseline rows for BASELINE_SECONDS
while time.time() - baseline_start < BASELINE_SECONDS:
    line = process.stdout.readline()
    if not line:
        continue
    row = parse_tshark_line(line)
    if row is not None:
        baseline_rows.append(row)

# Convert baseline to DataFrame
baseline_df = pd.DataFrame(baseline_rows)

# If baseline is too small, warn and exit
if baseline_df.empty:
    print("❌ Baseline capture returned no TCP/UDP IP packets. Check Wi-Fi traffic and try again.")
    process.terminate()
    raise SystemExit(1)

# Build baseline feature matrix
X_base, baseline_df = build_features(baseline_df)

# Create and train the Isolation Forest model on BASELINE ONLY
model = IsolationForest(
    n_estimators=300,
    contamination=CONTAMINATION,
    random_state=42
)

# Train model on baseline traffic
model.fit(X_base)

print(f"✅ Baseline trained with {len(baseline_df)} packets.\n")
print("✅ Now starting LIVE detection (10-second windows). Press CTRL + C to stop.\n")

# -----------------------------
# 2) LIVE DETECTION LOOP
# -----------------------------

buffer_rows = []
window_start = time.time()

try:
    while True:
        # Read live line
        line = process.stdout.readline()
        if not line:
            continue

        # Parse line into packet row
        row = parse_tshark_line(line)

        # If row is valid, add to buffer
        if row is not None:
            buffer_rows.append(row)

        # If window finished, analyze buffer
        now = time.time()
        if now - window_start >= WINDOW_SECONDS:
            # If no data, reset window
            if len(buffer_rows) == 0:
                window_start = now
                continue

            # Convert buffer into DataFrame
            df = pd.DataFrame(buffer_rows)

            # Build features for this window
            X_win, df = build_features(df)

            # Predict anomalies using baseline-trained model
            df["anomaly"] = model.predict(X_win)
            df["anomaly_score"] = model.decision_function(X_win)

            # Get anomalies only
            anomalies = df[df["anomaly"] == -1].sort_values("anomaly_score")

            # Print summary
            print(f"--- Window {WINDOW_SECONDS}s ---")
            print(f"Packets: {len(df)} | Suspicious: {len(anomalies)}")

            # Print top suspicious packets
            if not anomalies.empty:
                print("⚠️ Top suspicious traffic (baseline comparison):")
                for _, r in anomalies.head(10).iterrows():
                    print(
                        f"  - {r['src_ip']} -> {r['dst_ip']} "
                        f"dst_port={r['dst_port']} len={r['length']} "
                        f"score={r['anomaly_score']:.4f}"
                    )

            print()

            # Reset buffer and window timer
            buffer_rows = []
            window_start = now

except KeyboardInterrupt:
    print("\nStopping...")

finally:
    process.terminate()
