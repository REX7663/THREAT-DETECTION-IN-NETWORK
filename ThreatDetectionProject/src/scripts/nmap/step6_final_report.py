# Import pandas to load and work with CSV data
import pandas as pd

# Import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest

# Import matplotlib for plotting graphs
import matplotlib.pyplot as plt

# -----------------------------
# 1) LOAD THE PORT DATA CSV
# -----------------------------

# Define the path to the CSV created from the XML scan
input_csv_path = "../output/scan1_ports.csv"

# Load the CSV into a DataFrame
df = pd.read_csv(input_csv_path)

# -----------------------------
# 2) FEATURE ENGINEERING
# -----------------------------

# Create "open" column: open -> 1, everything else -> 0
df["open"] = df["state"].apply(lambda x: 1 if x == "open" else 0)

# Create "service_known" column: unknown -> 0, known -> 1
df["service_known"] = df["service"].apply(lambda x: 0 if x == "unknown" else 1)

# Select only numeric features for the ML model
X = df[["port", "open", "service_known"]]

# -----------------------------
# 3) TRAIN ISOLATION FOREST
# -----------------------------

# Create the Isolation Forest model
model = IsolationForest(
    n_estimators=200,      # More trees = more stable model
    contamination=0.25,    # Expect 25% anomalies (2 out of 8)
    random_state=42        # Reproducible results
)

# Fit the model and predict anomalies (1 normal, -1 anomaly)
df["anomaly"] = model.fit_predict(X)

# Compute anomaly score (higher = more normal, lower = more abnormal)
df["anomaly_score"] = model.decision_function(X)

# -----------------------------
# 4) SAVE FULL RESULTS
# -----------------------------

# Define output path for full results
full_results_path = "../output/final_results.csv"

# Save everything to CSV
df.to_csv(full_results_path, index=False)

# -----------------------------
# 5) CREATE "TOP SUSPICIOUS" TABLE
# -----------------------------

# Filter only anomalies
anomalies_df = df[df["anomaly"] == -1].copy()

# Sort anomalies by score ascending (most suspicious first)
anomalies_df = anomalies_df.sort_values("anomaly_score", ascending=True)

# Define output path for anomalies only
anomalies_path = "../output/top_suspicious_ports.csv"

# Save anomalies report
anomalies_df.to_csv(anomalies_path, index=False)

# -----------------------------
# 6) MAKE A CLEAN GRAPH
# -----------------------------

# Separate normal and anomaly rows
normal = df[df["anomaly"] == 1]
anomalies = df[df["anomaly"] == -1]

# Create a new figure
plt.figure()

# Plot normal ports
plt.scatter(normal.index, normal["port"], label="Normal")

# Plot anomalous ports
plt.scatter(anomalies.index, anomalies["port"], label="Anomaly")

# Add labels for anomalous points (so examiner can see the port numbers)
for idx, row in anomalies.iterrows():
    plt.text(idx, row["port"], f" {row['port']}")

# Add title
plt.title("Threat Detection Results (Isolation Forest)")

# Add axis labels
plt.xlabel("Scan Index")

# Add y label
plt.ylabel("Port Number")

# Add legend
plt.legend()

# Save graph
graph_path = "../output/final_anomaly_graph.png"
plt.savefig(graph_path)

# Show graph
plt.show()

# -----------------------------
# 7) PRINT SUMMARY
# -----------------------------

# Print where files are saved
print("✅ Full results saved to:", full_results_path)
print("✅ Suspicious ports saved to:", anomalies_path)
print("✅ Graph saved to:", graph_path)

# Print suspicious ports summary in terminal
print("\nTop Suspicious Ports (Most Suspicious First):")
print(anomalies_df[["ip", "port", "service", "anomaly_score"]])
