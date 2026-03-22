# ==============================
# IMPORTS
# ==============================

import streamlit as st
import pandas as pd
import sys
import os
import time
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest

# Fix imports for deployment
sys.path.append(os.path.dirname(__file__))

from core.pcap import extract_packets_from_capture, build_flows
from core.explain import explain_flow, severity_from_score


# ==============================
# PAGE CONFIG
# ==============================

st.set_page_config(page_title="Threat Detection Dashboard", layout="wide")

st.title("🔐 Real-Time Threat Detection Dashboard")
st.write("Analyze network scans and traffic using Machine Learning.")

# ==============================
# DARK SOC STYLE
# ==============================

st.markdown("""
<style>
    body {background-color: #0e1117; color: #ffffff;}
    .stApp {background-color: #0e1117;}
    h1, h2, h3 {color: #00ffcc;}
    .stButton>button {background-color: #00ffcc; color: black;}
    .stDownloadButton>button {background-color: #ff4b4b; color: white;}
</style>
""", unsafe_allow_html=True)


# ==============================
# SIDEBAR
# ==============================

contamination = st.sidebar.slider(
    "Anomaly Sensitivity",
    0.05, 0.5, 0.1, 0.05
)

# ==============================
# TABS
# ==============================

tab1, tab2, tab3 = st.tabs([
    "🌐 Nmap XML Scanner",
    "📡 Wireshark Traffic Analysis",
    "🧠 Unified Threat Analysis"
])

# ==============================
# TAB 1 — NMAP
# ==============================

with tab1:

    st.subheader("Upload Nmap XML")

    uploaded_xml = st.file_uploader("Upload Nmap XML", type=["xml"])

    if uploaded_xml:

        tree = ET.parse(uploaded_xml)
        root = tree.getroot()

        data = []

        for host in root.findall("host"):
            ip = host.find("address").get("addr")

            ports = host.find("ports")
            if ports:
                for port in ports.findall("port"):
                    data.append({
                        "ip": ip,
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": port.find("state").get("state"),
                        "service": port.find("service").get("name")
                    })

        df_nmap = pd.DataFrame(data)

        st.dataframe(df_nmap)

        st.session_state["nmap"] = df_nmap

        st.success("Nmap scan processed")


# ==============================
# TAB 2 — PCAP
# ==============================

with tab2:

    st.subheader("Upload PCAP File")

    uploaded_cap = st.file_uploader("Upload PCAP", type=["pcap", "pcapng"])

    if uploaded_cap:

        packets_df = extract_packets_from_capture(uploaded_cap)

        if packets_df is None:
            st.error("⚠ PCAP processing not supported in cloud.")
            st.stop()

        if packets_df.empty:
            st.warning("No packets found.")
            st.stop()

        flows = build_flows(packets_df)

        features = ["dst_port", "packet_count", "total_bytes", "avg_pkt_size"]

        model = IsolationForest(contamination=contamination)

        flows["anomaly"] = model.fit_predict(flows[features])
        flows["anomaly_score"] = model.decision_function(flows[features])

        st.session_state["flows"] = flows

        st.success("PCAP analysis complete")


# ==============================
# TAB 3 — UNIFIED
# ==============================

with tab3:

    st.subheader("Unified Threat Analysis")

    flows = st.session_state.get("flows")
    nmap = st.session_state.get("nmap")

    if flows is None and nmap is None:
        st.warning("Upload data first")
        st.stop()

    st.warning("⚠ LIVE THREAT MONITOR ACTIVE")

    time.sleep(1)

    # ==============================
    # MERGE DATA
    # ==============================

    if flows is not None and nmap is not None:

        flows["dst_port"] = flows["dst_port"].astype(str)
        nmap["port"] = nmap["port"].astype(str)

        unified = pd.merge(flows, nmap, left_on="dst_port", right_on="port", how="left")

        unified["combined_score"] = unified["anomaly_score"] * -1
        unified["combined_score"] += unified["service"].notna().astype(int) * 0.1

        def classify(x):
            if x > 0.3:
                return "HIGH"
            elif x > 0.1:
                return "MEDIUM"
            return "LOW"

        unified["severity"] = unified["combined_score"].apply(classify)

    elif flows is not None:
        unified = flows.copy()
        unified["combined_score"] = unified["anomaly_score"] * -1
        unified["severity"] = unified["combined_score"].apply(
            lambda x: "HIGH" if x > 0.3 else "MEDIUM" if x > 0.1 else "LOW"
        )

    else:
        unified = nmap.copy()
        unified["severity"] = "UNKNOWN"

    unified_sorted = unified.sort_values("combined_score", ascending=False)

    # ==============================
    # METRICS
    # ==============================

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Events", len(unified_sorted))
    col2.metric("High Risk", (unified_sorted["severity"] == "HIGH").sum())
    col3.metric("Medium Risk", (unified_sorted["severity"] == "MEDIUM").sum())

    # ==============================
    # CHARTS
    # ==============================

    st.write("### Top Suspicious Ports")

    top_ports = unified_sorted["dst_port"].value_counts().head(10)

    fig, ax = plt.subplots()
    top_ports.plot(kind="bar", ax=ax)
    st.pyplot(fig)

    st.write("### Severity Distribution")

    fig2, ax2 = plt.subplots()
    unified_sorted["severity"].value_counts().plot(kind="pie", autopct="%1.1f%%", ax=ax2)
    st.pyplot(fig2)

    # ==============================
    # TABLE WITH COLORS
    # ==============================

    def highlight(row):
        if row["severity"] == "HIGH":
            return ["background-color: red"] * len(row)
        elif row["severity"] == "MEDIUM":
            return ["background-color: orange"] * len(row)
        return ["background-color: green"] * len(row)

    st.dataframe(unified_sorted.style.apply(highlight, axis=1))

    # ==============================
    # DOWNLOAD
    # ==============================

    csv = unified_sorted.to_csv(index=False).encode("utf-8")

    st.download_button("Download Results", csv, "results.csv")