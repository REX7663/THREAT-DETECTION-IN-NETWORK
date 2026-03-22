# We import pandas to load anomaly results
import pandas as pd

# We import time to timestamp alerts
import time

# Input file containing flow anomaly results
INPUT_CSV = "../output/flows_with_anomalies.csv"

# Output alert log file
LOG_FILE = "../output/alerts.log"

# We load the anomaly results
flows = pd.read_csv(INPUT_CSV)

# We filter only suspicious flows (anomaly == -1)
suspicious = flows[flows["anomaly"] == -1]

# We define a function that builds explanation text for a suspicious flow
def build_explanation(row):
    # We check if port is high ephemeral port
    if row["dst_port"] >= 49152:
        return "High ephemeral port with unusual traffic pattern"

    # We check if multicast SSDP
    if row["dst_port"] == 1900:
        return "SSDP multicast traffic anomaly"

    # We check if large packet burst
    if row["packet_count"] > 500:
        return "Large packet burst detected"

    # We check if many unique source IPs
    if row["unique_src_ips"] > 5:
        return "Multiple source IPs targeting same destination"

    # Default explanation
    return "Statistical anomaly detected by Isolation Forest"

# We open the log file in append mode
with open(LOG_FILE, "a", encoding="utf-8") as f:

    # If suspicious flows exist
    if not suspicious.empty:

        print("⚠ ALERTS DETECTED:\n")

        # Loop through suspicious flows
        for _, row in suspicious.iterrows():

            # Generate explanation
            reason = build_explanation(row)

            # Format alert message
            alert_line = (
                f"{time.strftime('%H:%M:%S')} | "
                f"dst={row['dst_ip']} "
                f"port={row['dst_port']} "
                f"score={row['anomaly_score']:.4f} | "
                f"{reason}\n"
            )

            # Write to log file
            f.write(alert_line)

            # Print alert to terminal
            print(alert_line.strip())

    else:
        print("✅ No suspicious flows detected.")
