# We import scapy’s windows interface listing tool
from scapy.all import get_windows_if_list

# We loop through every interface and print friendly details
for i, iface in enumerate(get_windows_if_list()):
    # We print a readable index + the friendly name + description + GUID
    print("INDEX:", i)
    print("  NAME:", iface.get("name"))
    print("  DESC:", iface.get("description"))
    print("  GUID:", iface.get("guid"))
    print("-" * 50)
