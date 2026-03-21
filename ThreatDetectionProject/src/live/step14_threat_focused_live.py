# We import subprocess to run tshark and read live output
import subprocess

# We import pandas to build tables and aggregate flows
import pandas as pd

# We import time to manage baseline and detection windows
import time

# We import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest

# -----------------------------
# SETTINGS
# -----------------------------

# Wi-Fi interface number from tshark -D
TSHARK_INTERFACE_NUMBER = "4"

# Full path to tshark
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# Baseline training time in seconds
BASELINE_SECONDS = 30

# Window time in seconds
WINDOW_SECONDS = 10

# Expected anomaly rate
CONTAMINATION = 0.05

# We set a port threshold to ignore ephemeral destination ports
# Ports above 49151 are usually client ephemeral ports (often normal)
MAX_SERVICE_PORT = 49151

# -----------------------------
# TSHARK COMMAND
# -----------------------------

# We build tshark command to output the needed fields
tshark_cmd = [
    TSHARK_PATH,
    "-l",
    "-i", TSHARK_INTERFACE_NUMBER,
    "-T", "fields",
    "-E", "separator=,",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.dstport",
    "-e", "udp.dstport",
    "-e", "ip.proto",
    "-e", "frame.len"
]

# We start tshark process
process = subprocess.Popen(
    tshark_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

# -----------------------------
# PARSE ONE LINE
# -----------------------------

def parse_line(line):
    # Strip whitespace
    line = line.strip()

    # Split by comma
    parts = line.split(",")

    # Ensure correct number of fields
    if len(parts) < 6:
        return None

    # Extract fields
    src_ip = parts[0]
    dst_ip = parts[1]
    tcp_dport = parts[2]
    udp_dport = parts[3]
    proto = parts[4]
    frame_len = parts[5]

    # Ignore non-IP packets (missing IPs)
    if src_ip == "" or dst_ip == "":
        return None

    # Determine destination port
    dst_port = None
    if tcp_dport.isdigit():
        dst_port = int(tcp_dport)
    elif udp_dport.isdigit():
        dst_port = int(udp_dport)
    else:
        return None

    # Ignore ephemeral destination ports (threat-focused filter)
    if dst_port > MAX_SERVICE_PORT:
        return None

    # Convert protocol and length safely
    proto_num = int(proto) if proto.isdigit() else 0
    pkt_len = int(frame_len) if frame_len.isdigit() else 0

    # Return row
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto_num": proto_num,
        "length": pkt_len
    }

# -----------------------------
# FLOW AGGREGATION
# -----------------------------

def aggregate_flows(df):
    # We group by destination IP, destination port, and protocol
    # Then we count packets and compute mean packet length
    flows = (
        df.groupby(["dst_ip", "dst_port", "proto_num"])
          .agg(
              packet_count=("dst_port", "count"),
              avg_len=("length", "mean"),
              total_len=("length", "sum")
          )
          .reset_index()
    )

    # We create a high-port flag (still useful below threshold)
    flows["is_high_port"] = flows["dst_port"].apply(lambda p: 1 if p >= 1024 else 0)

    # We create port bucket feature
    flows["port_bucket"] = flows["dst_port"].apply(lambda p: 0 if p <= 1023 else 1)

    # Build feature matrix
    X = flows[["dst_port", "packet_count", "avg_len", "total_len", "proto_num", "is_high_port", "port_bucket"]]

    return X, flows

# -----------------------------
# BASELINE TRAINING
# -----------------------------

print("✅ Starting BASELINE capture (30 seconds). Browse normally...")
baseline_rows = []
baseline_start = time.time()

while time.time() - baseline_start < BASELINE_SECONDS:
    line = process.stdout.readline()
    if not line:
        continue
    row = parse_line(line)
    if row is not None:
        baseline_rows.append(row)

baseline_df = pd.DataFrame(baseline_rows)

if baseline_df.empty:
    print("❌ No TCP/UDP service-port packets captured during baseline.")
    process.terminate()
    raise SystemExit(1)

X_base, flows_base = aggregate_flows(baseline_df)

model = IsolationForest(
    n_estimators=300,
    contamination=CONTAMINATION,
    random_state=42
)

model.fit(X_base)

print(f"✅ Baseline trained with {len(flows_base)} flows (service ports only).")
print("✅ Starting LIVE detection (10-second windows). Press CTRL + C to stop.\n")

# -----------------------------
# LIVE DETECTION
# -----------------------------

buffer_rows = []
window_start = time.time()

try:
    while True:
        line = process.stdout.readline()
        if not line:
            continue

        row = parse_line(line)
        if row is not None:
            buffer_rows.append(row)

        now = time.time()
        if now - window_start >= WINDOW_SECONDS:
            if len(buffer_rows) == 0:
                window_start = now
                continue

            df = pd.DataFrame(buffer_rows)

            X_win, flows_win = aggregate_flows(df)

            flows_win["anomaly"] = model.predict(X_win)
            flows_win["anomaly_score"] = model.decision_function(X_win)

            anomalies = flows_win[flows_win["anomaly"] == -1].sort_values("anomaly_score")

            print(f"--- Window {WINDOW_SECONDS}s (service ports only) ---")
            print(f"Flows: {len(flows_win)} | Suspicious flows: {len(anomalies)}")

            if not anomalies.empty:
                print("⚠️ Top suspicious flows:")
                for _, r in anomalies.head(10).iterrows():
                    print(
                        f"  - dst={r['dst_ip']} port={r['dst_port']} proto={r['proto_num']} "
                        f"count={r['packet_count']} avg_len={r['avg_len']:.1f} "
                        f"score={r['anomaly_score']:.4f}"
                    )
            print()

            buffer_rows = []
            window_start = now

except KeyboardInterrupt:
    print("\nStopping...")

finally:
    process.terminate()
