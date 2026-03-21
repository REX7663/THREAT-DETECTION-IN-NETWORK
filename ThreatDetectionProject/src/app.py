# We import streamlit for the dashboard UI
import streamlit as st

# We import pandas for tables and downloads
import pandas as pd

# We import time for alert timestamps
import time

# We import Nmap core logic
from core.nmap import load_nmap_root_from_bytes, extract_nmap_ports, build_nmap_features

# We import PCAP core logic
from core.pcap import extract_packets_from_capture, build_flows

# We import flow model logic
from core.models import detect_flow_anomalies

# We import explanations
from core.explain import explain_flow, severity_from_score, unified_severity

# We import unified model logic
from core.unified import build_unified_table, run_unified_model


# We set up the Streamlit page
st.set_page_config(page_title="Unified Threat Detection Dashboard", layout="wide")

# We display title
st.title("Unified ML Threat Detection Dashboard")

# Sidebar settings
st.sidebar.header("Settings")

nmap_cont = st.sidebar.slider("Nmap anomaly rate", 0.05, 0.50, 0.25, 0.05)
flow_cont = st.sidebar.slider("Traffic anomaly rate", 0.05, 0.50, 0.10, 0.05)
unified_cont = st.sidebar.slider("Unified anomaly rate", 0.05, 0.50, 0.15, 0.05)
max_alerts = st.sidebar.slider("Max alerts to show", 5, 50, 15, 5)

# Create tabs
tab1, tab2, tab3 = st.tabs(["Nmap XML Scanner", "Wireshark Traffic", "Unified Risk Score"])


# -----------------------------
# TAB 1: NMAP
# -----------------------------
with tab1:
    st.subheader("Nmap XML Port Anomaly Detection")

    uploaded_xml = st.file_uploader("Upload Nmap XML file", type=["xml"], key="nmap_xml")

    if uploaded_xml is not None:
        xml_bytes = uploaded_xml.read()
        root = load_nmap_root_from_bytes(xml_bytes)
        ports_df = extract_nmap_ports(root)

        if ports_df.empty:
            st.warning("No port data found in this XML.")
        else:
            X, ports_df = build_nmap_features(ports_df)

            model = None
            # We reuse IsolationForest via the same detect_flow_anomalies style, but simple here
            from sklearn.ensemble import IsolationForest

            model = IsolationForest(n_estimators=300, contamination=float(nmap_cont), random_state=42)
            ports_df["anomaly"] = model.fit_predict(X)
            ports_df["anomaly_score"] = model.decision_function(X)

            ports_sorted = ports_df.sort_values("anomaly_score", ascending=True).reset_index(drop=True)

            # Save for unified tab
            st.session_state["nmap_ports_df"] = ports_sorted.copy()

            st.write("All Ports (sorted by suspiciousness)")
            st.dataframe(ports_sorted, use_container_width=True)

            suspicious_ports = ports_sorted[ports_sorted["anomaly"] == -1].head(int(max_alerts))

            st.write("⚠ Suspicious Ports Only")
            st.dataframe(suspicious_ports, use_container_width=True)

            st.download_button(
                "Download Nmap Results CSV",
                data=ports_sorted.to_csv(index=False).encode("utf-8"),
                file_name="nmap_ports_with_anomalies.csv",
                mime="text/csv"
            )


# -----------------------------
# TAB 2: WIRESHARK
# -----------------------------
with tab2:
    st.subheader("Wireshark Flow Anomaly Detection")

    uploaded_cap = st.file_uploader("Upload capture file", type=["pcap", "pcapng"], key="pcap_file")

    if uploaded_cap is not None:
        st.info("Reading capture and building flows...")

        packets_df = extract_packets_from_capture(uploaded_cap)

        if packets_df.empty:
            st.warning("No IP packets found in this capture.")
        else:
            flows_df = build_flows(packets_df)

            if flows_df.empty:
                st.warning("No TCP/UDP flows found in this capture.")
            else:
                flows_sorted = detect_flow_anomalies(flows_df, flow_cont)

                flows_sorted["severity"] = flows_sorted["anomaly_score"].apply(severity_from_score)
                flows_sorted["explanation"] = flows_sorted.apply(explain_flow, axis=1)

                # Save for unified tab
                st.session_state["flow_df"] = flows_sorted.copy()

                col1, col2 = st.columns(2)

                with col1:
                    st.write("All flows (sorted)")
                    st.dataframe(flows_sorted, use_container_width=True)

                with col2:
                    st.write("⚠ Alerts")
                    suspicious = flows_sorted[flows_sorted["anomaly"] == -1].head(int(max_alerts))

                    if suspicious.empty:
                        st.success("No suspicious flows detected.")
                    else:
                        st.dataframe(
                            suspicious[["dst_ip", "dst_port", "protocol", "packet_count", "unique_src_ips", "anomaly_score", "severity", "explanation"]],
                            use_container_width=True
                        )

                        st.write("Readable alert lines:")
                        for _, row in suspicious.iterrows():
                            st.write(
                                f"{time.strftime('%H:%M:%S')} | "
                                f"dst={row['dst_ip']} port={row['dst_port']} "
                                f"score={row['anomaly_score']:.4f} severity={row['severity']} | {row['explanation']}"
                            )

                st.download_button(
                    "Download Traffic Results CSV",
                    data=flows_sorted.to_csv(index=False).encode("utf-8"),
                    file_name="flows_with_anomalies.csv",
                    mime="text/csv"
                )


# -----------------------------
# TAB 3: UNIFIED
# -----------------------------
with tab3:
    st.subheader("Unified Isolation Forest (Nmap + Wireshark)")

    nmap_ports_df = st.session_state.get("nmap_ports_df", None)
    flow_df = st.session_state.get("flow_df", None)

    if (nmap_ports_df is None or nmap_ports_df.empty) and (flow_df is None or flow_df.empty):
        st.info("Upload Nmap XML in Tab 1 and/or Wireshark capture in Tab 2 to generate unified score.")
    else:
        # Prepare Nmap dataframe for unified model (ensure the feature columns exist)
        if nmap_ports_df is not None and not nmap_ports_df.empty:
            # If the feature columns are missing (older data), we rebuild features
            if "nmap_open" not in nmap_ports_df.columns:
                _, nmap_ports_df = build_nmap_features(nmap_ports_df)

        # Prepare flow dataframe for unified model (we only need dst_ip/dst_port/protocol + flow stats)
        if flow_df is not None and not flow_df.empty:
            # Ensure protocol is lowercase for merging
            flow_df["protocol"] = flow_df["protocol"].astype(str).str.lower()

        # Build unified table
        unified_df = build_unified_table(nmap_ports_df if nmap_ports_df is not None else pd.DataFrame(),
                                         flow_df if flow_df is not None else pd.DataFrame())

        if unified_df.empty:
            st.warning("Unified table is empty. Try uploading both files again.")
        else:
            # Run unified model
            unified_results = run_unified_model(unified_df, unified_cont)

            # Add severity
            unified_results["severity"] = unified_results["combined_score"].apply(unified_severity)

            # Show results
            st.write("Unified Results (Most Suspicious First)")
            st.dataframe(unified_results, use_container_width=True)

            # Show alerts only
            st.write("⚠ Unified Alerts Only")
            unified_alerts = unified_results[unified_results["combined_anomaly"] == -1].head(int(max_alerts))
            st.dataframe(unified_alerts, use_container_width=True)

            # Download unified CSV
            st.download_button(
                "Download Unified Results CSV",
                data=unified_results.to_csv(index=False).encode("utf-8"),
                file_name="unified_results.csv",
                mime="text/csv"
            )