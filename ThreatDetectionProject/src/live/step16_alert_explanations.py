# We import subprocess to run tshark and read live output
import subprocess

# We import pandas to build tables and aggregate flows
import pandas as pd

# We import time to manage baseline and detection windows
import time

# We import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest

# We define a log file path so Streamlit can read alerts
LOG_PATH = "../output/live_alerts.log"


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

# We keep contamination small (used only when fitting baseline model)
CONTAMINATION = 0.05

# Ignore destination ports above this (ephemeral destination ports)
MAX_SERVICE_PORT = 49151

# Minimum packets per flow to consider (reduces noise)
MIN_FLOW_PACKETS = 3

# Your local IP (we ignore flows where dst_ip == this to reduce self-noise)
LOCAL_IP = "10.0.0.121"

# Threshold strictness: worst 5% baseline becomes suspicious boundary
BASELINE_PERCENTILE = 5

# -----------------------------
# TSHARK COMMAND
# -----------------------------

# We build tshark command to output needed fields
tshark_cmd = [
    TSHARK_PATH,                  # Full path to tshark
    "-l",                         # Line-buffered output
    "-i", TSHARK_INTERFACE_NUMBER,# Wi-Fi interface number
    "-T", "fields",               # Output fields only
    "-E", "separator=,",          # CSV separator
    "-e", "ip.src",               # Source IP
    "-e", "ip.dst",               # Destination IP
    "-e", "tcp.dstport",          # TCP destination port
    "-e", "udp.dstport",          # UDP destination port
    "-e", "ip.proto",             # Protocol number
    "-e", "frame.len"             # Packet length
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

# We define a function to parse one tshark line into a dict row
def parse_line(line):
    # Remove whitespace
    line = line.strip()

    # Split by commas
    parts = line.split(",")

    # Ensure correct number of fields
    if len(parts) < 6:
        return None

    # Unpack fields
    src_ip, dst_ip, tcp_dport, udp_dport, proto, frame_len = parts

    # Ignore non-IP packets (empty IPs)
    if src_ip == "" or dst_ip == "":
        return None

    # Determine destination port (TCP preferred, else UDP)
    dst_port = None
    if tcp_dport.isdigit():
        dst_port = int(tcp_dport)
    elif udp_dport.isdigit():
        dst_port = int(udp_dport)
    else:
        return None

    # Ignore destination ports above 49151
    if dst_port > MAX_SERVICE_PORT:
        return None

    # Convert protocol safely
    proto_num = int(proto) if proto.isdigit() else 0

    # Convert packet length safely
    pkt_len = int(frame_len) if frame_len.isdigit() else 0

    # Return structured row
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto_num": proto_num,
        "length": pkt_len
    }

# -----------------------------
# FLOW AGGREGATION + FEATURES
# -----------------------------

# We define a function to aggregate packets into flows and build feature matrix
def aggregate_flows(df):
    # Group by dst_ip, dst_port, protocol and compute statistics
    flows = (
        df.groupby(["dst_ip", "dst_port", "proto_num"])
          .agg(
              packet_count=("dst_port", "count"),  # number of packets in the flow
              avg_len=("length", "mean"),          # average packet length
              total_len=("length", "sum")          # total bytes (approx)
          )
          .reset_index()
    )

    # Remove flows to your own machine (reduces noise)
    flows = flows[flows["dst_ip"] != LOCAL_IP]

    # Keep only flows with enough packets
    flows = flows[flows["packet_count"] >= MIN_FLOW_PACKETS]

    # If empty, return None
    if flows.empty:
        return None, flows

    # Add simple extra features
    flows["is_high_port"] = flows["dst_port"].apply(lambda p: 1 if p >= 1024 else 0)
    flows["port_bucket"] = flows["dst_port"].apply(lambda p: 0 if p <= 1023 else 1)

    # Build numeric feature matrix
    X = flows[["dst_port", "packet_count", "avg_len", "total_len", "proto_num", "is_high_port", "port_bucket"]]

    # Return matrix + flows table
    return X, flows

# -----------------------------
# ALERT EXPLANATION LAYER
# -----------------------------

# We define a function that returns a human-readable reason for a suspicious flow
def explain_flow(row):
    # Extract values
    port = int(row["dst_port"])
    proto = int(row["proto_num"])
    count = int(row["packet_count"])
    total_len = float(row["total_len"])

    # Convert protocol number to name
    proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else f"PROTO-{proto}")

    # Rule 1: risky legacy services
    if port in [21, 23]:
        return f"Suspicious service port {port} ({proto_name}) — legacy/insecure service exposure"

    # Rule 2: unusual management ports (example list)
    if port in [8291, 3389, 5900, 445]:
        return f"Suspicious management/service port {port} ({proto_name}) — investigate access"

    # Rule 3: high-volume UDP on dynamic/registered ports
    if proto == 17 and port >= 1024 and count > 300:
        return f"High-volume UDP flow on port {port} — possible streaming/tunneling or abnormal burst"

    # Rule 4: high packet volume on a service port
    if count > 2000 or total_len > 2_000_000:
        return f"Very high traffic volume on port {port} ({proto_name}) — possible scan/abuse or heavy transfer"

    # Default explanation
    return f"Unusual flow pattern on port {port} ({proto_name}) compared to baseline"

# -----------------------------
# BASELINE TRAINING
# -----------------------------

print("✅ Starting BASELINE capture (30 seconds). Browse normally...")
baseline_rows = []
baseline_start = time.time()

# Collect baseline packets for BASELINE_SECONDS
while time.time() - baseline_start < BASELINE_SECONDS:
    # Read a line from tshark
    line = process.stdout.readline()

    # Skip empty reads
    if not line:
        continue

    # Parse the line into a row
    row = parse_line(line)

    # Store if valid
    if row is not None:
        baseline_rows.append(row)

# Convert baseline packets to DataFrame
baseline_df = pd.DataFrame(baseline_rows)

# If baseline is empty, stop
if baseline_df.empty:
    print("❌ No TCP/UDP packets captured in baseline. Try generating traffic and rerun.")
    process.terminate()
    raise SystemExit(1)

# Aggregate baseline flows and build features
X_base, flows_base = aggregate_flows(baseline_df)

# If baseline flows become empty, stop
if X_base is None:
    print("❌ Baseline flows empty after filtering. Reduce MIN_FLOW_PACKETS or check traffic.")
    process.terminate()
    raise SystemExit(1)

# Create and train Isolation Forest on baseline
model = IsolationForest(
    n_estimators=300,
    contamination=CONTAMINATION,
    random_state=42
)

# Fit the model on baseline flows
model.fit(X_base)

# Compute baseline scores
base_scores = model.decision_function(X_base)

# Compute threshold based on baseline percentile
threshold = pd.Series(base_scores).quantile(BASELINE_PERCENTILE / 100)

print(f"✅ Baseline trained with {len(flows_base)} flows.")
print(f"✅ Threshold set to {threshold:.4f} (worst {BASELINE_PERCENTILE}% baseline)\n")
print("✅ LIVE detection started. Press CTRL + C to stop.\n")

# -----------------------------
# LIVE DETECTION LOOP
# -----------------------------

buffer_rows = []
window_start = time.time()

try:
    while True:
        # Read next tshark line
        line = process.stdout.readline()

        # Skip empty reads
        if not line:
            continue

        # Parse line into row
        row = parse_line(line)

        # Store if valid
        if row is not None:
            buffer_rows.append(row)

        # If window ended, analyze
        now = time.time()
        if now - window_start >= WINDOW_SECONDS:
            # If no data, reset window
            if len(buffer_rows) == 0:
                window_start = now
                continue

            # Build window dataframe
            df_win = pd.DataFrame(buffer_rows)

            # Aggregate flows
            X_win, flows_win = aggregate_flows(df_win)

            # If no flows, reset
            if X_win is None:
                print(f"--- Window {WINDOW_SECONDS}s ---")
                print("No valid flows after filtering.\n")
                buffer_rows = []
                window_start = now
                continue

            # Score flows using baseline-trained model
            flows_win["anomaly_score"] = model.decision_function(X_win)

            # Mark suspicious using baseline threshold
            flows_win["is_suspicious"] = flows_win["anomaly_score"].apply(lambda s: 1 if s < threshold else 0)

            # Filter suspicious flows and sort
            suspicious = flows_win[flows_win["is_suspicious"] == 1].sort_values("anomaly_score")
            

            # Print summary
            print(f"--- Window {WINDOW_SECONDS}s (with explanations) ---")
            print(f"Flows: {len(flows_win)} | Suspicious: {len(suspicious)}")

            # Print top suspicious with explanations
            if not suspicious.empty:
                print("⚠️ Alerts:")
                # We open the log file in append mode to store alerts
    with open(LOG_PATH, "a", encoding="utf-8") as f:
                for _, r in suspicious.head(10).iterrows():
                    reason = explain_flow(r)
                    # We format one alert line to write into the log file
    line = (
                f"{time.strftime('%H:%M:%S')} | "
                f"dst={r['dst_ip']} port={r['dst_port']} "
                f"score={r['anomaly_score']:.4f} | {reason}\n"
            )

    print(
                        f"  - dst={r['dst_ip']} port={r['dst_port']} proto={r['proto_num']} "
                        f"count={r['packet_count']} score={r['anomaly_score']:.4f} | {reason}"
                    )
    print()

            # Reset for next window
    buffer_rows = []
    window_start = now

except KeyboardInterrupt:
    print("\nStopping...")

finally:
    process.terminate()
