from panos.firewall import Firewall
from panos.network import EthernetInterface
from panos.ha import HighAvailability, HA1, HA2, HA3
import time
import xml.etree.ElementTree as ET

def ha_setup(fw, peer_ip, ip_int_ha1, ip_int_ha2, device_id):  
    """
    Configures High Availability (HA) in active-active mode on a Palo Alto firewall.

    Args:
        fw (object): The firewall object to be configured.
        peer_ip (str): IP address of the peer device in the HA pair.
        ip_int_ha1 (str): IP address for the HA1 interface, used for configuration and state synchronization.
        ip_int_ha2 (str): IP address for the HA2 interface, used for state data synchronization.
        device_id (int): Device ID of the firewall in the HA pair (0 or 1).
    """
    eth5 = EthernetInterface(
        name="ethernet1/5",
        mode="ha"
    )
    fw.add(eth5)
    eth5.create()

    eth7 = EthernetInterface(
        name="ethernet1/7",
        mode="ha"
    )
    fw.add(eth7)
    eth7.create()

    eth8 =EthernetInterface(
        name="ethernet1/8",
        mode="ha"
    )
    fw.add(eth8)
    eth8.create()

    ha = HighAvailability(
        group_id = 7,             
        peer_ip = peer_ip, 
        mode = "active-active", 
        state_sync = True,
        device_id = device_id,                        # 0 lub 1
        session_owner_selection = "first-packet",     # The fw that receives the first packet of a new session is the session owner
        session_setup = "first-packet",               # The fw that receives the first packet of a new session performs session setup
        sync_virtual_router = True,
        # sync_qos = True,                            # if QoS is defined
        # tentative_hold_time = 30                    # time in seconds, default is 60
        )
    fw.add(ha)
    ha.create()

    int_ha1 = HA1(
        ip_address = ip_int_ha1,
        netmask = "255.255.255.252",
        port = "ethernet1/5"
        )
    ha.add(int_ha1)
    int_ha1.create()

    int_ha2 = HA2(
        ip_address = ip_int_ha2,
        netmask = "255.255.255.252",
        port = "ethernet1/7"
        )
    ha.add(int_ha2)
    int_ha2.create()

    # interface used to forward packets
    int_ha3 = HA3(
        port = "ethernet1/8"
        )
    ha.add(int_ha3)
    int_ha3.create()

    fw.commit()


def is_commit_in_progress(fw):
    job_status = fw.op("show jobs all", xml=True)
    
    if isinstance(job_status, bytes):
        str_xml = job_status.decode("utf-8")
    else:
        str_xml = str(job_status)
    
    xml_root = ET.fromstring(str_xml)

    for entry in xml_root.findall('result/job'):
        job_type = entry.find("type")
        job_status = entry.find("status")
        
        if job_type is not None and job_status is not None:
            if job_type.text == "Commit" and job_status.text in ["PEND", "ACT"]:
                return True  # Commit in progress
    
    return False  # No active commit found


def main():
    fw13_int_ha1 = "10.0.1.13"
    fw13_int_ha2 = "10.0.2.13"

    fw14_int_ha1 = "10.0.1.14"
    fw14_int_ha2 = "10.0.2.14"

    fw13 = Firewall("<fw13_mgmt_ip>", "<login>", "<password>") 
    fw14 = Firewall("<fw13_mgmt_ip>", "<login>", "<password>") 

    ha_setup(fw13, fw14_int_ha1, fw13_int_ha1, fw13_int_ha2, device_id=0)
    ha_setup(fw14, fw13_int_ha1, fw14_int_ha1, fw14_int_ha2, device_id=1)

    while is_commit_in_progress(fw13) or is_commit_in_progress(fw14):
        print("Commit in progress.... waiting for completion.")
        time.sleep(15)  

    print("Commits completed. Starting configuration synchronization.")

    fw13.set_ha_peers(fw14)
    fw13.refresh_ha_active()
    if not fw13.config_synced():
        fw13.synchronize_config()
    

if __name__ == "__main__":
    main()
