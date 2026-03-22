# We import ElementTree to read and navigate the Nmap XML file
import xml.etree.ElementTree as ET

# We define a function to load and parse the Nmap XML file
def load_nmap_xml(xml_path):
    # Parse the XML file into an ElementTree object
    tree = ET.parse(xml_path)
    # Get the root element (top element) of the XML document
    root = tree.getroot()
    # Return the root so other functions can search inside it
    return root

# We define a function that extracts port/service details from the XML root
def extract_port_data(root):
    # We create an empty list to store each extracted record (each record will be a dictionary)
    records = []

    # Loop through every <host> element in the XML
    for host in root.findall("host"):
        # Find the <address> element inside the host (this contains the IP address)
        address_elem = host.find("address")

        # If an address exists, read the IP, otherwise use "unknown"
        ip_address = address_elem.get("addr") if address_elem is not None else "unknown"

        # Find the <ports> element inside the host (this contains all ports)
        ports_elem = host.find("ports")

        # If there is no <ports> element, skip this host
        if ports_elem is None:
            continue

        # Loop through every <port> element inside <ports>
        for port in ports_elem.findall("port"):
            # Read the port number (portid attribute)
            port_number = port.get("portid")

            # Read the protocol (protocol attribute)
            protocol = port.get("protocol")

            # Find the <state> element (contains open/closed/filtered)
            state_elem = port.find("state")

            # If state exists, read it, otherwise use "unknown"
            state = state_elem.get("state") if state_elem is not None else "unknown"

            # Find the <service> element (contains service name like http, ssh, etc.)
            service_elem = port.find("service")

            # If service exists, read the name, otherwise use "unknown"
            service_name = service_elem.get("name") if service_elem is not None else "unknown"

            # Create one record (row) with the values we extracted
            record = {
                "ip": ip_address,            # IP address of the host
                "port": port_number,         # Port number as string for now
                "protocol": protocol,        # Protocol (tcp/udp)
                "state": state,              # Port state
                "service": service_name      # Service name
            }

            # Add the record to the list
            records.append(record)

    # Return the list of extracted records
    return records

# This block runs only when you execute this file directly
if __name__ == "__main__":
    # Define the path to your XML scan file
    xml_file_path = "../data/scan1.xml"

    # Load the XML and get the root
    root = load_nmap_xml(xml_file_path)

    # Extract the port data into a list of records
    records = extract_port_data(root)

    # Print how many port records we found
    print("Total port records extracted:", len(records))

    # Print the first 20 records so we can confirm the data looks correct
    for record in records[:20]:
        print(record)
