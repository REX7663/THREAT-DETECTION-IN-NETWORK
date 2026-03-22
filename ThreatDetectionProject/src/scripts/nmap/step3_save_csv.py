# We import ElementTree to read and navigate the Nmap XML file
import xml.etree.ElementTree as ET

# We import pandas to create a table (DataFrame) and save it as CSV
import pandas as pd

# We define a function to load and parse the Nmap XML file
def load_nmap_xml(xml_path):
    # Parse the XML file into an ElementTree object
    tree = ET.parse(xml_path)
    # Get the root element (top element) of the XML document
    root = tree.getroot()
    # Return the root so we can search inside it
    return root

# We define a function that extracts port/service details from the XML root
def extract_port_data(root):
    # Create an empty list to store each extracted record (each record is a dictionary)
    records = []

    # Loop through every <host> element in the XML
    for host in root.findall("host"):
        # Find the <address> element to get the IP address
        address_elem = host.find("address")

        # Read IP address if it exists, otherwise use "unknown"
        ip_address = address_elem.get("addr") if address_elem is not None else "unknown"

        # Find the <ports> element which contains port information
        ports_elem = host.find("ports")

        # If there is no ports element, skip this host
        if ports_elem is None:
            continue

        # Loop through each <port> element inside <ports>
        for port in ports_elem.findall("port"):
            # Get the port number from the "portid" attribute
            port_number = port.get("portid")

            # Get the protocol from the "protocol" attribute (tcp/udp)
            protocol = port.get("protocol")

            # Find the <state> element and read the state attribute
            state_elem = port.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            # Find the <service> element and read the service name
            service_elem = port.find("service")
            service_name = service_elem.get("name") if service_elem is not None else "unknown"

            # Build one record (row) as a dictionary
            record = {
                "ip": ip_address,            # Host IP address
                "port": int(port_number),    # Convert port to integer for ML later
                "protocol": protocol,        # Protocol type
                "state": state,              # Port state
                "service": service_name      # Service name
            }

            # Add the record to our list
            records.append(record)

    # Return the complete list of records
    return records

# This block runs only when you execute this script directly
if __name__ == "__main__":
    # Define the path to the input XML file
    xml_file_path = "../data/scan1.xml"

    # Define the output path for the CSV file
    output_csv_path = "../output/scan1_ports.csv"

    # Load the XML file and get its root element
    root = load_nmap_xml(xml_file_path)

    # Extract records from the XML
    records = extract_port_data(root)

    # Convert the list of dictionaries into a pandas DataFrame (table)
    df = pd.DataFrame(records)

    # Save the DataFrame to a CSV file without the index column
    df.to_csv(output_csv_path, index=False)

    # Print confirmation message
    print("CSV saved successfully to:", output_csv_path)

    # Print the DataFrame so you can see the table format
    print(df)
