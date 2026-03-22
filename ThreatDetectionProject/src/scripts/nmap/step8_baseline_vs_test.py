# Import ElementTree so we can parse XML files
import xml.etree.ElementTree as ET

# Import pandas for handling tables
import pandas as pd

# Import IsolationForest for anomaly detection
from sklearn.ensemble import IsolationForest

# -------------------------
# FUNCTION: Load XML File
# -------------------------
def load_nmap_xml(xml_path):
    # Parse XML file into tree
    tree = ET.parse(xml_path)
    # Return root element
    return tree.getroot()

# -------------------------
# FUNCTION: Extract Port Data
# -------------------------
def extract_port_data(root):
    # Create empty list to store records
    records = []

    # Loop through each host
    for host in root.findall("host"):
        address_elem = host.find("address")
        ip_address = address_elem.get("addr") if address_elem is not None else "unknown"

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        # Loop through each port
        for port in ports_elem.findall("port"):
            port_number = int(port.get("portid"))
            protocol = port.get("protocol", "unknown")

            state_elem = port.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            service_elem = port.find("service")
            service_name = service_elem.get("name") if service_elem is not None else "unknown"

            records.append({
                "ip": ip_address,
                "port": port_number,
                "protocol": protocol,
                "state": state,
                "service": service_name
            })

    return pd.DataFrame(records)

# -------------------------
# FUNCTION: Build Features
# -------------------------
def build_features(df):
    df["open"] = df["state"].apply(lambda x: 1 if x == "open" else 0)
    df["service_known"] = df["service"].apply(lambda x: 0 if x == "unknown" else 1)

    common_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3389}
    df["port_is_common"] = df["port"].apply(lambda p: 1 if int(p) in common_ports else 0)
    df["is_high_port"] = df["port"].apply(lambda p: 1 if int(p) >= 49152 else 0)
    df["port_range_bucket"] = df["port"].apply(lambda p: 0 if int(p) <= 1023 else (1 if int(p) <= 49151 else 2))

    risky_services = {"telnet", "ftp"}
    df["service_is_risky"] = df["service"].apply(lambda s: 1 if str(s).lower() in risky_services else 0)

    X = df[["port", "open", "service_known", "port_is_common", "is_high_port", "port_range_bucket", "service_is_risky"]]

    return X, df

# -------------------------
# MAIN EXECUTION
# -------------------------
if __name__ == "__main__":

    baseline_xml_path = "../data/baseline.xml"
    test_xml_path = "../data/test.xml"

    # Load baseline
    baseline_root = load_nmap_xml(baseline_xml_path)
    baseline_df = extract_port_data(baseline_root)

    # Load test
    test_root = load_nmap_xml(test_xml_path)
    test_df = extract_port_data(test_root)

    # Build features
    X_base, baseline_df = build_features(baseline_df)
    X_test, test_df = build_features(test_df)

    # Train model ONLY on baseline
    model = IsolationForest(n_estimators=300, contamination=0.20, random_state=42)
    model.fit(X_base)

    # Predict on test
    test_df["anomaly"] = model.predict(X_test)
    test_df["anomaly_score"] = model.decision_function(X_test)

    # Sort most suspicious first
    test_sorted = test_df.sort_values("anomaly_score", ascending=True)

    # Save results
    test_sorted.to_csv("../output/baseline_vs_test_results.csv", index=False)

    print("\nTop suspicious ports in TEST (trained on BASELINE):\n")
    print(test_sorted[["ip", "port", "service", "anomaly", "anomaly_score"]])

    print("\n✅ Results saved to output/baseline_vs_test_results.csv")
