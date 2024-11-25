from panos.firewall import Firewall
from panos.errors import PanDeviceError

def check_paloalto_firewall_status(ip, username, password):
    try:
        # Initialize the connection to the Palo Alto firewall
        fw = Firewall(ip, username, password)
        
        # Get system information
        system_info = fw.op("show system info", xml=True)
        print(system_info)
    
    except PanDeviceError as e:
        print("Error connecting to Palo Alto firewall:", e)

# Przykład użycia
check_paloalto_firewall_status("<firewall_management_ip>", "<login>", "<password>")