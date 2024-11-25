from panos import firewall
from panos.network import ManagementProfile, EthernetInterface, VirtualWire, Zone, VirtualRouter
from panos.policies import Rulebase, SecurityRule, NatRule
from xml_functions import dhcp_server

# connect with device 
firewall_ip = "<ffirewall_management_ip>"    
api_key = "<xmlApiKey>"
fw = firewall.Firewall(firewall_ip, "<login>", "<password>")    

wan_profile = ManagementProfile(name = "WAN profile", ping = True, ssh = True, https = True)
fw.add(wan_profile)
wan_profile.create()

lan_profile = ManagementProfile(name = "LAN profile", ping = True,)
fw.add(lan_profile)
lan_profile.create()

eth1 = EthernetInterface(name="ethernet1/1", mode="layer3", enable_dhcp=True, create_dhcp_default_route=True, management_profile = wan_profile)
fw.add(eth1)
eth1.create()

eth3 = EthernetInterface(name="ethernet1/3", mode="layer3", ip="192.168.3.1/24", management_profile = lan_profile)
fw.add(eth3)
eth3.create()

virtual_wire_name = "default-vwire"
vw = VirtualWire(name=virtual_wire_name)
fw.add(vw)
vw.delete() 

dhcp_server(firewall_ip, api_key, "ethernet1/3", "192.168.3.1", "255.255.255.0", "192.168.3.0", "ethernet1/1")

trust = Zone(name = "trust", interface = [])
fw.add(trust)
trust.create()

untrust = Zone(name = "untrust", interface = [])
fw.add(untrust)
untrust.create()

wan = Zone(name="WAN", mode="layer3", interface=["ethernet1/1"])
fw.add(wan)
wan.create()

lan = Zone(name="LAN", mode="layer3", interface=["ethernet1/3"])
fw.add(lan)
lan.create()

router = VirtualRouter(name="default", interface=["ethernet1/1", "ethernet1/3"])
fw.add(router)
router.create()

rb = Rulebase()
fw.add(rb)

internet_acc = SecurityRule(
    name="LAN TO WAN",
    fromzone=["LAN"],
    tozone=["WAN"],
    application=["dns","ntp","ping","rtp","ssl","web-browsing"],
    action="allow"
)
rb.add(internet_acc)
internet_acc.create()

nat_translation = NatRule(
    name="LAN to WAN",
    fromzone=["LAN"],
    tozone=["WAN"],
    to_interface="ethernet1/1",
    source_translation_type="dynamic-ip-and-port",     
    source_translation_address_type = "interface-address",
    source_translation_interface="ethernet1/1"       
)    
rb.add(nat_translation)
nat_translation.create()

commit_response = fw.commit(sync=True, exception=True)
print(commit_response["messages"])