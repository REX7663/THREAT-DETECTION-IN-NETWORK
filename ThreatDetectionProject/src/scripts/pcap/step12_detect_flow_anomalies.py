# We import os to build reliable file paths
import os

# We import pandas to load flow data
import pandas as pd

# We import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest

# We import matplotlib to visualize anomaly scores
import matplotlib.pyplot as plt

# -----------------------------
# BUILD CORRECT PROJECT PATHS
# -----------------------------

# Get current script directory (src/scripts/pcap)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Move up three folders to project root
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", ".."))

# Build output folder path
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")

# Input: flow features created by step11
INPUT_CSV = os.path.join(OUTPUT_DIR, "pcap_flows.csv")

# Output: anomaly results
OUTPUT_RESULTS_CSV = os.path.join(OUTPUT_DIR, "pcap_flow_anomalies.csv")

# Output: graph image
OUTPUT_GRAPH = os.path.join(OUTPUT_DIR, "pcap_flow_anomalies.png")

# -----------------------------
# SAFETY CHECK
# -----------------------------

if not os.path.exists(INPUT_CSV):
    raise FileNotFoundError(f"❌ Flow file not found at: {INPUT_CSV}")

# -----------------------------
# LOAD FLOW DATA
# -----------------------------

flows = pd.read_csv(INPUT_CSV)

print("✅ Loaded flows:", len(flows))

# -----------------------------
# PREPARE FEATURES FOR ML
# -----------------------------

# Build numeric feature matrix
X = flows[["dst_port", "packet_count", "avg_len", "total_len"]].copy()

# -----------------------------
# TRAIN ISOLATION FOREST
# -----------------------------

model = IsolationForest(
    n_estimators=300,
    contamination=0.05,
    random_state=42
)

# Fit model
model.fit(X)

# Predict anomalies
flows["anomaly"] = model.predict(X)

# Compute anomaly score
flows["anomaly_score"] = model.decision_function(X)

# Sort by most suspicious first
flows_sorted = flows.sort_values("anomaly_score")

# -----------------------------
# SAVE RESULTS
# -----------------------------

flows_sorted.to_csv(OUTPUT_RESULTS_CSV, index=False)

print("✅ Anomaly results saved to:", OUTPUT_RESULTS_CSV)

# -----------------------------
# VISUALIZE RESULTS
# -----------------------------

plt.figure()
plt.scatter(range(len(flows_sorted)), flows_sorted["anomaly_score"])
plt.title("Flow Anomaly Scores (PCAP)")
plt.xlabel("Flow Index")
plt.ylabel("Anomaly Score")
plt.tight_layout()
plt.savefig(OUTPUT_GRAPH)

print("✅ Graph saved to:", OUTPUT_GRAPH)

# -----------------------------
# SHOW TOP SUSPICIOUS FLOWS
# -----------------------------

print("\n🔥 Top Suspicious Flows:")
print(flows_sorted.head(10)[
    ["dst_ip", "dst_port", "protocol", "packet_count", "anomaly_score"]
])