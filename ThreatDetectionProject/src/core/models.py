# We import pandas for DataFrame operations
import pandas as pd

# We import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest


# We define a function that runs Isolation Forest on flow data
def detect_flow_anomalies(flows_df, contamination):
    # If flows table is empty, return empty DataFrame
    if flows_df.empty:
        return pd.DataFrame()

    # We select numeric columns (features) for the ML model
    X = flows_df[["dst_port", "packet_count", "total_bytes", "avg_pkt_size", "unique_src_ips"]].copy()

    # We create the Isolation Forest model
    model = IsolationForest(
        n_estimators=300,
        contamination=float(contamination),
        random_state=42
    )

    # We train and predict anomaly labels (1 normal, -1 anomaly)
    flows_df["anomaly"] = model.fit_predict(X)

    # We compute anomaly scores (lower means more suspicious)
    flows_df["anomaly_score"] = model.decision_function(X)

    # We sort rows by suspiciousness
    flows_sorted = flows_df.sort_values("anomaly_score", ascending=True).reset_index(drop=True)

    # We return sorted results
    return flows_sorted