from panos.firewall import Firewall
from panos.network import EthernetInterface
from panos.ha import HighAvailability, HA1, HA2
from xml_functions import ha_election_settings, ha_link_monitoring
from time import sleep

def ha_active_passive_setup(fw, peer_ip, ip_int_ha1, ip_int_ha2, fw_mgmt_ip, api_key, preemptive, device_priority):  
    """
    Configures High Availability (HA) in active-passive mode on a Palo Alto firewall.

    Args:
        fw (object): The firewall object to be configured
        peer_ip (str): IP address of the peer device in the HA pair
        ip_int_ha1 (str): IP address for the HA1 interface, used for configuration and state synchronization
        ip_int_ha2 (str): IP address for the HA2 interface, used for state data synchronization
        fw_mgmt_ip (str): Management IP address of the firewall, used for API communication
        api_key (str): API key for authenticating API calls
        preemptive (bool): Specifies whether preemptive behavior is enabled. If True, the higher-priority device will take over as active after a failover
        device_priority (int): Priority of the device in HA (lower value indicates higher priority)
    """
    eth5 = EthernetInterface(name="ethernet1/5", mode="ha")
    fw.add(eth5)
    eth5.create()

    eth7 = EthernetInterface(name="ethernet1/7", mode="ha")
    fw.add(eth7)
    eth7.create()

    ha = HighAvailability(
        group_id=7,                   # uniquely identifies each HA pair on your network
        peer_ip= peer_ip, 
        mode="active-passive",        # active-pasive is default value
        state_sync=True
        )
    fw.add(ha)
    ha.create()

    int_ha1 = HA1(ip_address = ip_int_ha1, netmask = "255.255.255.252", port = "ethernet1/5")
    ha.add(int_ha1)
    int_ha1.create()

    int_ha2 = HA2(ip_address = ip_int_ha2, netmask = "255.255.255.252", port = "ethernet1/7")
    ha.add(int_ha2)
    int_ha2.create()

    ha_election_settings(fw_mgmt_ip, api_key, preemptive, device_priority)
    ha_link_monitoring(fw_mgmt_ip, api_key, link_group_name="my_link_group", interfaces=["ethernet1/1", "ethernet1/3"])

    return fw.commit()


def main():
    fw13_int_ha1 = "10.0.1.13"
    fw13_int_ha2 = "10.0.2.13"

    fw14_int_ha1 = "10.0.1.14"
    fw14_int_ha2 = "10.0.2.14"

    fw13_ip = "<firewall13_management_ip>"
    fw13 = Firewall(fw13_ip, "<login>", "<password>") 
    fw13_api_key = "<xml_api_key_fw13>"
    fw14_ip = "<firewall14_management_ip>"
    fw14 = Firewall(fw14_ip, "<login>", "<password>") 
    fw14_api_key = "<xml_api_key_fw14>"
    
    commit_id_fw13 = ha_active_passive_setup(fw13, fw14_int_ha1, fw13_int_ha1, fw13_int_ha2, fw13_ip, fw13_api_key, preemptive="yes", device_priority=100)
    commit_id_fw14 = ha_active_passive_setup(fw14, fw13_int_ha1, fw14_int_ha1, fw14_int_ha2, fw14_ip, fw14_api_key, preemptive="yes", device_priority=200)

    message_fw13 = fw13.syncjob(commit_id_fw13, interval=5)
    print(message_fw13["messages"])
    message_fw14 = fw14.syncjob(commit_id_fw14, interval=5)
    print(message_fw14["messages"])

    sleep(5)
    print("Starting configuration synchronization")   

    fw13.set_ha_peers(fw14)
    if not fw13.config_synced():
        fw13.synchronize_config()

if __name__ == "__main__":
    main()
