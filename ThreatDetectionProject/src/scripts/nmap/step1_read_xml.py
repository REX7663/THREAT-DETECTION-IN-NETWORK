# We import ElementTree so we can read and navigate the XML file created by Nmap
import xml.etree.ElementTree as ET

# We define a function that will load and parse an Nmap XML file
def load_nmap_xml(xml_path):
    # ET.parse reads the XML file from the given path and builds an XML tree
    tree = ET.parse(xml_path)
    
    # tree.getroot gets the top/root element of the XML structure
    root = tree.getroot()
    
    # We return the root so we can search inside it later
    return root

# This block runs only if you execute this file directly (not if it is imported)
if __name__ == "__main__":
    # We define the path to the scan file (edit this if your file name is different)
    xml_file_path = "../data/scan1.xml"
    
    # We load the XML and get the root element
    root = load_nmap_xml(xml_file_path)
    
    # We print the root tag just to confirm we successfully loaded the XML
    print("XML loaded successfully. Root tag is:", root.tag)
