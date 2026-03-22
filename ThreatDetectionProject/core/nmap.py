# We import pandas to store extracted port data in tables
import pandas as pd

# We import ElementTree to parse Nmap XML files
import xml.etree.ElementTree as ET


# We define a function to parse Nmap XML bytes into an XML root element
def load_nmap_root_from_bytes(xml_bytes):
    # We parse the XML bytes into a root element
    root = ET.fromstring(xml_bytes)
    # We return the root element for searching
    return root


# We define a function that extracts host ports from an Nmap XML root into a DataFrame
def extract_nmap_ports(root):
    # We create a list for rows
    rows = []

    # We loop through each host element
    for host in root.findall("host"):
        # We find the address element for IP address
        address_elem = host.find("address")

        # We read the IP address if present
        ip_address = address_elem.get("addr") if address_elem is not None else "unknown"

        # We find the ports element
        ports_elem = host.find("ports")

        # If no ports exist, we skip this host
        if ports_elem is None:
            continue

        # We loop through each port record
        for port in ports_elem.findall("port"):
            # We read the port number
            port_number = int(port.get("portid"))

            # We read the protocol
            protocol = port.get("protocol", "unknown")

            # We read the port state
            state_elem = port.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            # We read the service name
            service_elem = port.find("service")
            service_name = service_elem.get("name") if service_elem is not None else "unknown"

            # We add the row to our list
            rows.append({
                "ip": ip_address,
                "port": port_number,
                "protocol": protocol,
                "state": state,
                "service": service_name
            })

    # We convert rows to a DataFrame
    return pd.DataFrame(rows)


# We define a function that builds Nmap exposure features for ML
def build_nmap_features(ports_df):
    # If empty, return empty feature matrix and df
    if ports_df.empty:
        return pd.DataFrame(), ports_df

    # We ensure protocol is lowercase for consistency
    ports_df["protocol"] = ports_df["protocol"].fillna("tcp").astype(str).str.lower()

    # We create numeric open feature: open=1 else 0
    ports_df["nmap_open"] = ports_df["state"].apply(lambda x: 1 if str(x).lower() == "open" else 0)

    # We create service_known feature: unknown=0 else 1
    ports_df["nmap_service_known"] = ports_df["service"].apply(lambda x: 0 if str(x).lower() == "unknown" else 1)

    # We mark risky services
    risky_services = {"ftp", "telnet"}
    ports_df["nmap_service_risky"] = ports_df["service"].apply(lambda s: 1 if str(s).lower() in risky_services else 0)

    # We mark common ports
    common_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3389}
    ports_df["nmap_port_common"] = ports_df["port"].apply(lambda p: 1 if int(p) in common_ports else 0)

    # We select the feature matrix
    X = ports_df[["port", "nmap_open", "nmap_service_known", "nmap_service_risky", "nmap_port_common"]].copy()

    # We return features and updated df
    return X, ports_df