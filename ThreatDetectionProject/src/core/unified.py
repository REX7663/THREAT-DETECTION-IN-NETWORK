# We import pandas to merge Nmap and flow data
import pandas as pd

# We import IsolationForest to build the unified model
from sklearn.ensemble import IsolationForest


# We define a function to build a unified merged table using Nmap ports and Wireshark flows
def build_unified_table(nmap_df, flow_df):
    # We create an empty DataFrame if inputs are missing
    if nmap_df is None:
        nmap_df = pd.DataFrame()
    if flow_df is None:
        flow_df = pd.DataFrame()

    # If both are empty, return empty
    if nmap_df.empty and flow_df.empty:
        return pd.DataFrame()

    # ----- Prepare Nmap side -----
    if not nmap_df.empty:
        # We create merge keys (target_ip, port, protocol)
        nmap_df["target_ip"] = nmap_df["ip"].astype(str)
        nmap_df["port"] = nmap_df["port"].astype(int)
        nmap_df["protocol"] = nmap_df["protocol"].fillna("tcp").astype(str).str.lower()

        # We keep only needed columns for unified merge
        nmap_side = nmap_df[[
            "target_ip", "port", "protocol",
            "nmap_open", "nmap_service_known", "nmap_service_risky", "nmap_port_common"
        ]].copy()
    else:
        # We create an empty Nmap side with required columns
        nmap_side = pd.DataFrame(columns=[
            "target_ip", "port", "protocol",
            "nmap_open", "nmap_service_known", "nmap_service_risky", "nmap_port_common"
        ])

    # ----- Prepare flow side -----
    if not flow_df.empty:
        # We create merge keys (target_ip, port, protocol)
        flow_df["target_ip"] = flow_df["dst_ip"].astype(str)
        flow_df["port"] = flow_df["dst_port"].astype(int)
        flow_df["protocol"] = flow_df["protocol"].fillna("tcp").astype(str).str.lower()

        # We rename flow columns to unified names
        flow_side = flow_df[[
            "target_ip", "port", "protocol",
            "packet_count", "total_bytes", "avg_pkt_size", "unique_src_ips"
        ]].copy()

        flow_side = flow_side.rename(columns={
            "packet_count": "flow_packet_count",
            "total_bytes": "flow_total_bytes",
            "avg_pkt_size": "flow_avg_pkt_size",
            "unique_src_ips": "flow_unique_src_ips"
        })
    else:
        # We create an empty flow side with required columns
        flow_side = pd.DataFrame(columns=[
            "target_ip", "port", "protocol",
            "flow_packet_count", "flow_total_bytes", "flow_avg_pkt_size", "flow_unique_src_ips"
        ])

    # ----- Merge both sides -----
    unified = pd.merge(
        nmap_side,
        flow_side,
        on=["target_ip", "port", "protocol"],
        how="outer"
    )

    # We fill missing values with 0 so the model can work
    unified = unified.fillna(0)

    # We return the merged table
    return unified


# We define a function to run a unified Isolation Forest model on the merged table
def run_unified_model(unified_df, contamination):
    # If unified table is empty, return empty
    if unified_df.empty:
        return pd.DataFrame()

    # We select the combined features for training/scoring
    X = unified_df[[
        "nmap_open", "nmap_service_known", "nmap_service_risky", "nmap_port_common",
        "flow_packet_count", "flow_total_bytes", "flow_avg_pkt_size", "flow_unique_src_ips"
    ]].copy()

    # We create the unified Isolation Forest model
    model = IsolationForest(
        n_estimators=400,
        contamination=float(contamination),
        random_state=42
    )

    # We compute combined anomaly labels
    unified_df["combined_anomaly"] = model.fit_predict(X)

    # We compute combined score (lower is more suspicious)
    unified_df["combined_score"] = model.decision_function(X)

    # We sort by suspiciousness
    unified_sorted = unified_df.sort_values("combined_score", ascending=True).reset_index(drop=True)

    # We return results
    return unified_sorted