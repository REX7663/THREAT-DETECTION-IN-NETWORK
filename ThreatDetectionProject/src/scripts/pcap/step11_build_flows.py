# We import os to build reliable paths no matter where we run the script from
import os

# We import pandas to read and process CSV files
import pandas as pd

# -----------------------------
# BUILD CORRECT PROJECT PATHS
# -----------------------------

# We get the folder where THIS script is located (src/scripts/pcap)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# We move up three folders to reach the project root (ThreatDetectionProject)
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", ".."))

# We build the full path to the output folder
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")

# We define the correct input CSV path (created by step10_extract_pcap_features.py)
INPUT_CSV = os.path.join(OUTPUT_DIR, "pcap_features.csv")

# We define where flow-level features will be saved
OUTPUT_FLOWS_CSV = os.path.join(OUTPUT_DIR, "pcap_flows.csv")

# -----------------------------
# SAFETY CHECK
# -----------------------------

# We stop early with a clear message if the input file does not exist
if not os.path.exists(INPUT_CSV):
    raise FileNotFoundError(f"❌ Input CSV not found. Expected at: {INPUT_CSV}")

# -----------------------------
# LOAD PACKET FEATURES
# -----------------------------

# We load packet-level features into a DataFrame
df = pd.read_csv(INPUT_CSV)

# -----------------------------
# CLEAN / FILTER DATA
# -----------------------------

# We drop rows where dst_port is missing (OTHER protocol packets)
df = df.dropna(subset=["dst_port"])

# We convert dst_port to integer (because it may be read as float due to NaN)
df["dst_port"] = df["dst_port"].astype(int)

# -----------------------------
# BUILD FLOWS (AGGREGATION)
# -----------------------------

# We group by destination IP, destination port, and protocol to form flows
flows = (
    df.groupby(["dst_ip", "dst_port", "protocol"])
      .agg(
          packet_count=("dst_port", "count"),   # Number of packets in this flow
          avg_len=("pkt_len", "mean"),          # Average packet length
          total_len=("pkt_len", "sum")          # Total bytes
      )
      .reset_index()
)

# -----------------------------
# SAVE FLOW FEATURES
# -----------------------------

# We save flows to CSV
flows.to_csv(OUTPUT_FLOWS_CSV, index=False)

# We print confirmation
print("✅ Flow features saved to:", OUTPUT_FLOWS_CSV)

# We print a preview
print(flows.head(10))