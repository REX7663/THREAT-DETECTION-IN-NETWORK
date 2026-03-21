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

# Baseline training duration
BASELINE_SECONDS = 30

# Window size for live detection
WINDOW_SECONDS = 10

# We still keep a small contamination only for baseline model training
CONTAMINATION = 0.05

# Ignore destination ports above this (ephemeral destination ports)
MAX_SERVICE_PORT = 49151

# Minimum packets per flow to consider (reduces noise)
MIN_FLOW_PACKETS = 3

# Your local IP (we will ignore flows where dst_ip == this to reduce self-noise)
LOCAL_IP = "10.0.0.121"

# How strict the baseline threshold should be:
# Lower percentile = stricter (more alerts). Higher percentile = fewer alerts.
# Example: 5 means "flag anything worse than the worst 5% of baseline"
BASELINE_PERCENTILE = 5

# -----------------------------
# TSHARK COMMAND
# -----------------------------

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
    line = line.strip()
    parts = line.split(",")

    if len(parts) < 6:
        return None

    src_ip, dst_ip, tcp_dport, udp_dport, proto, frame_len = parts

    if src_ip == "" or dst_ip == "":
        return None

    dst_port = None
    if tcp_dport.isdigit():
        dst_port = int(tcp_dport)
    elif udp_dport.isdigit():
        dst_port = int(udp_dport)
    else:
        return None

    if dst_port > MAX_SERVICE_PORT:
        return None

    proto_num = int(proto) if proto.isdigit() else 0
    pkt_len = int(frame_len) if frame_len.isdigit() else 0

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
    flows = (
        df.groupby(["dst_ip", "dst_port", "proto_num"])
          .agg(
              packet_count=("dst_port", "count"),
              avg_len=("length", "mean"),
              total_len=("length", "sum")
          )
          .reset_index()
    )

    # Remove flows targeting your own machine (reduces noise)
    flows = flows[flows["dst_ip"] != LOCAL_IP]

    # Keep only flows that have enough packets (reduces random noise)
    flows = flows[flows["packet_count"] >= MIN_FLOW_PACKETS]

    # If nothing remains, return empty
    if flows.empty:
        return None, flows

    flows["is_high_port"] = flows["dst_port"].apply(lambda p: 1 if p >= 1024 else 0)
    flows["port_bucket"] = flows["dst_port"].apply(lambda p: 0 if p <= 1023 else 1)

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

if X_base is None or flows_base.empty:
    print("❌ Baseline flows became empty after filtering. Lower MIN_FLOW_PACKETS or check traffic.")
    process.terminate()
    raise SystemExit(1)

model = IsolationForest(
    n_estimators=300,
    contamination=CONTAMINATION,
    random_state=42
)

model.fit(X_base)

# Compute baseline anomaly scores
base_scores = model.decision_function(X_base)

# Compute threshold using percentile (example: worst 5% baseline)
threshold = pd.Series(base_scores).quantile(BASELINE_PERCENTILE / 100)

print(f"✅ Baseline trained with {len(flows_base)} flows.")
print(f"✅ Baseline score threshold set to: {threshold:.4f} (worst {BASELINE_PERCENTILE}%)\n")
print("✅ Starting LIVE detection (10-second windows). Press CTRL + C to stop.\n")

# -----------------------------
# LIVE DETECTION LOOP
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

            if X_win is None or flows_win.empty:
                print(f"--- Window {WINDOW_SECONDS}s ---")
                print("No valid flows after filtering.\n")
                buffer_rows = []
                window_start = now
                continue

            # Predict scores using baseline-trained model
            flows_win["anomaly_score"] = model.decision_function(X_win)

            # Mark as suspicious if below baseline threshold
            flows_win["is_suspicious"] = flows_win["anomaly_score"].apply(lambda s: 1 if s < threshold else 0)

            suspicious = flows_win[flows_win["is_suspicious"] == 1].sort_values("anomaly_score")

            print(f"--- Window {WINDOW_SECONDS}s (baseline threshold) ---")
            print(f"Flows: {len(flows_win)} | Suspicious flows: {len(suspicious)}")

            if not suspicious.empty:
                print("⚠️ Top suspicious flows:")
                for _, r in suspicious.head(10).iterrows():
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
