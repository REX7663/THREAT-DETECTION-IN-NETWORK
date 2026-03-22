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

sys.path.append(os.path.dirname(__file__))

from core.pcap import extract_packets_from_capture, build_flows
from core.explain import explain_flow, severity_from_score


# ==============================
# PAGE CONFIG
# ==============================

st.set_page_config(page_title="Threat Detection Dashboard", layout="wide")

st.title("🔐 Real-Time Threat Detection Dashboard")
st.write("Analyze Nmap scans and network traffic using Machine Learning.")


# ==============================
# DARK UI
# ==============================

st.markdown("""
<style>
body {background-color:#0e1117;color:white;}
.stApp {background-color:#0e1117;}
h1,h2,h3 {color:#00ffcc;}
</style>
""", unsafe_allow_html=True)


# ==============================
# SIDEBAR
# ==============================

contamination = st.sidebar.slider("Anomaly Sensitivity", 0.05, 0.5, 0.1, 0.05)


# ==============================
# TABS
# ==============================

tab1, tab2, tab3 = st.tabs([
    "🌐 Nmap XML ANALYSIS",
    "📡 PCAP TRAFFIC ANALYSIS",
    "🧠 RESULT AND ALERTS"
])


# ==============================
# TAB 1 — NMAP
# ==============================

with tab1:

    st.subheader("Upload Nmap XML")

    uploaded_xml = st.file_uploader("Upload XML", type=["xml"])

    if uploaded_xml:

        try:
            tree = ET.parse(uploaded_xml)
            root = tree.getroot()
        except:
            st.error("Invalid XML file")
            st.stop()

        data = []

        for host in root.findall("host"):

            address_tag = host.find("address")
            ip = address_tag.get("addr") if address_tag is not None else "unknown"

            ports = host.find("ports")

            if ports:
                for port in ports.findall("port"):

                    state_tag = port.find("state")
                    service_tag = port.find("service")

                    state = state_tag.get("state") if state_tag is not None else "unknown"
                    service = service_tag.get("name") if service_tag is not None else "unknown"

                    data.append({
                        "ip": ip,
                        "port": str(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "state": state,
                        "service": service
                    })

        df_nmap = pd.DataFrame(data)

        if df_nmap.empty:
            st.warning("No ports found")
        else:
            st.dataframe(df_nmap)
            st.session_state["nmap"] = df_nmap
            st.success("Nmap processed")


# ==============================
# TAB 2 — PCAP
# ==============================

with tab2:

    st.subheader("Upload PCAP")

    uploaded_cap = st.file_uploader("Upload PCAP", type=["pcap", "pcapng"])

    if uploaded_cap:

        packets_df = extract_packets_from_capture(uploaded_cap)

        if packets_df is None:
            st.error("PCAP not supported in cloud")
            st.stop()

        if packets_df.empty:
            st.warning("No packets found")
            st.stop()

        flows = build_flows(packets_df)

        if flows is None or flows.empty:
            st.warning("No flows generated")
            st.stop()

        # 🔥 SHOW TABLE (THIS WAS MISSING)
        st.write("### Extracted Flow Data")
        st.dataframe(flows.head(20))

        features = ["dst_port", "packet_count", "total_bytes", "avg_pkt_size"]

        model = IsolationForest(contamination=contamination)

        flows["anomaly"] = model.fit_predict(flows[features])
        flows["anomaly_score"] = model.decision_function(flows[features])

        # 🔥 SHOW ANALYSIS RESULT
        st.write("### Flow Analysis Results")
        st.dataframe(flows.sort_values("anomaly_score"))

        st.session_state["flows"] = flows

        st.success("PCAP processed")

# ==============================
# TAB 3 — UNIFIED
# ==============================

with tab3:

    st.subheader("RESULTS AND ALERTS")

    flows = st.session_state.get("flows")
    nmap = st.session_state.get("nmap")

    if flows is None and nmap is None:
        st.warning("Upload data first")
        st.stop()

    st.warning("⚠ LIVE MONITOR ACTIVE")
    time.sleep(1)

    # ==============================
    # MERGE
    # ==============================

    try:

        if flows is not None:
            flows["dst_port"] = flows["dst_port"].astype(str)

        if nmap is not None:
            nmap["port"] = nmap["port"].astype(str)

        if flows is not None and nmap is not None:
            unified = pd.merge(
                flows,
                nmap,
                left_on="dst_port",
                right_on="port",
                how="left"
            )
        elif flows is not None:
            unified = flows.copy()
        else:
            unified = nmap.copy()

    except Exception as e:
        st.error(f"Merge error: {e}")
        st.stop()

    # ==============================
    # SCORING
    # ==============================

    if "anomaly_score" in unified.columns:
        unified["combined_score"] = unified["anomaly_score"] * -1
    else:
        unified["combined_score"] = 0

    if "service" in unified.columns:
        unified["combined_score"] += unified["service"].notna().astype(int) * 0.1

    def classify(x):
        if x > 0.3:
            return "HIGH"
        elif x > 0.1:
            return "MEDIUM"
        return "LOW"

    unified["severity"] = unified["combined_score"].apply(classify)

    unified_sorted = unified.sort_values("combined_score", ascending=False)

    # ==============================
    # METRICS
    # ==============================

    col1, col2, col3 = st.columns(3)

    col1.metric("Total", len(unified_sorted))
    col2.metric("High", (unified_sorted["severity"] == "HIGH").sum())
    col3.metric("Medium", (unified_sorted["severity"] == "MEDIUM").sum())

    # ==============================
    # CHARTS
    # ==============================

    if "dst_port" in unified_sorted.columns:

        top_ports = unified_sorted["dst_port"].value_counts().head(10)

        if not top_ports.empty:
            fig, ax = plt.subplots()
            top_ports.plot(kind="bar", ax=ax)
            st.pyplot(fig)

    if "severity" in unified_sorted.columns:

        sev = unified_sorted["severity"].value_counts()

        if not sev.empty:
            fig2, ax2 = plt.subplots()
            sev.plot(kind="pie", autopct="%1.1f%%", ax=ax2)
            st.pyplot(fig2)

    # ==============================
    # TABLE
    # ==============================

    def highlight(row):
        if row["severity"] == "HIGH":
            return ["background-color:red"] * len(row)
        elif row["severity"] == "MEDIUM":
            return ["background-color:orange"] * len(row)
        return ["background-color:green"] * len(row)

    st.dataframe(unified_sorted.style.apply(highlight, axis=1))

    # ==============================
    # DOWNLOAD
    # ==============================

    csv = unified_sorted.to_csv(index=False).encode("utf-8")

    st.download_button("Download Results", csv, "results.csv")