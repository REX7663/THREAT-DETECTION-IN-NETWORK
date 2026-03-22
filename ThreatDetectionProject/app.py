# ==============================
# IMPORTS
# ==============================

import streamlit as st  # Streamlit for dashboard
import pandas as pd  # For data handling
import sys
import os

# Fix import paths (important for deployment)
sys.path.append(os.path.dirname(__file__))

# Import project modules
from core.pcap import extract_packets_from_capture, build_flows
from core.explain import explain_flow, severity_from_score
from sklearn.ensemble import IsolationForest


# ==============================
# PAGE CONFIGURATION
# ==============================

st.set_page_config(
    page_title="ML Threat Detection Dashboard",
    layout="wide"
)

st.title("🔐 ML Threat Detection Dashboard")
st.write("Upload PCAP files to detect suspicious network activity using Machine Learning.")


# ==============================
# SIDEBAR SETTINGS
# ==============================

contamination = st.sidebar.slider(
    "Anomaly Sensitivity",
    min_value=0.05,
    max_value=0.50,
    value=0.10,
    step=0.05
)


# ==============================
# TABS
# ==============================

tab1, tab2 = st.tabs([
    "📡 PCAP Analysis",
    "📊 Results & Alerts"
])


# ==============================
# TAB 1 — PCAP ANALYSIS
# ==============================

with tab1:

    st.subheader("Upload PCAP / PCAPNG File")

    uploaded_cap = st.file_uploader(
        "Upload capture file",
        type=["pcap", "pcapng"]
    )

    if uploaded_cap is not None:

        st.info("Processing capture file...")

        # ==============================
        # STEP 1 — EXTRACT PACKETS
        # ==============================

        packets_df = extract_packets_from_capture(uploaded_cap)

        # 🔥 CRITICAL FIX (handle cloud scapy issue)
        if packets_df is None:
            st.error("⚠ PCAP processing is not supported in this environment.")
            st.stop()

        if packets_df.empty:
            st.warning("No IP packets found in this capture.")
            st.stop()

        st.success(f"Packets extracted: {len(packets_df)}")

        # ==============================
        # STEP 2 — BUILD FLOWS
        # ==============================

        flows = build_flows(packets_df)

        st.write("### Flow Data")
        st.dataframe(flows.head(20))

        # ==============================
        # STEP 3 — MACHINE LEARNING
        # ==============================

        features = ["dst_port", "packet_count", "total_bytes", "avg_pkt_size"]

        X = flows[features]

        model = IsolationForest(
            contamination=contamination,
            random_state=42
        )

        flows["anomaly"] = model.fit_predict(X)
        flows["anomaly_score"] = model.decision_function(X)

        # Save in session state for next tab
        st.session_state["flows"] = flows

        st.success("Anomaly detection completed")


# ==============================
# TAB 2 — RESULTS
# ==============================

with tab2:

    st.subheader("Detected Threats")

    if "flows" not in st.session_state:
        st.warning("Please upload and process a PCAP file first.")
    else:

        flows = st.session_state["flows"]

        # Sort by anomaly score (most suspicious first)
        flows_sorted = flows.sort_values("anomaly_score")

        # ==============================
        # FILTER ANOMALIES
        # ==============================

        alerts = flows_sorted[flows_sorted["anomaly"] == -1].copy()

        if alerts.empty:
            st.success("No suspicious activity detected.")
        else:

            # ==============================
            # ADD SEVERITY + EXPLANATION
            # ==============================

            alerts["severity"] = alerts["anomaly_score"].apply(severity_from_score)
            alerts["explanation"] = alerts.apply(explain_flow, axis=1)

            st.write("### Alerts Table")
            st.dataframe(alerts)

            # ==============================
            # DOWNLOAD OPTION
            # ==============================

            csv = alerts.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="Download Alerts CSV",
                data=csv,
                file_name="alerts.csv",
                mime="text/csv"
            )