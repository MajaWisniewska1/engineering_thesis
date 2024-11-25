from panos import firewall
from xml_functions import dhcp_server

firewall_ip = "<firewall_management_ip>"
api_key = "<xml_Api_key>"

# connect with device - type in credentials
fw = firewall.Firewall(firewall_ip, "<login>", "<password>")

# management profiles
from panos.network import ManagementProfile

wan_profile = ManagementProfile(name = "WAN profile", ping = True, ssh = True, https = True)
fw.add(wan_profile)
wan_profile.create()

lan_profile = ManagementProfile(name = "LAN profile", ping = True)
fw.add(lan_profile)
lan_profile.create()

# interfaces
from panos.network import EthernetInterface

eth1 = EthernetInterface(
    name="ethernet1/1",
    mode="layer3",
    enable_dhcp=True,
    create_dhcp_default_route=True,
    management_profile = wan_profile
)
fw.add(eth1)
eth1.create()

eth2 = EthernetInterface(
    name="ethernet1/2",
    mode="layer2",
)
fw.add(eth2)
eth2.create()

eth3 = EthernetInterface(
    name="ethernet1/3",
    mode="layer3",
    ip=("192.168.3.1/24"),
    management_profile = lan_profile
)
fw.add(eth3)
eth3.create()

eth4 = EthernetInterface(
    name="ethernet1/4",
    mode="layer3",
    ip=("192.168.4.1/24"),
    management_profile = lan_profile
)
fw.add(eth4)
eth4.create()

from panos.network import VirtualWire

virtual_wire_name = "default-vwire"
vw = VirtualWire(name=virtual_wire_name)
fw.add(vw)
vw.delete() 

# zones
from panos.network import Zone

# w początkowym configu do tej strefy jest przypisany int1/1, co po usunięciu virtual-wire wywoływało błąd przy commicie
trust = Zone(name = "trust", interface = [])
fw.add(trust)
trust.create()

# w początkowym configu do tej strefy jest przypisany int1/2, co po usunięciu virtual-wire wywoływało błąd przy commicie
untrust = Zone(name = "untrust", interface = [])
fw.add(untrust)
untrust.create()

wan = Zone(name="WAN", mode="layer3", interface=["ethernet1/1"])
fw.add(wan)
wan.create()

lan = Zone(name="LAN", mode="layer3",interface=["ethernet1/3","ethernet1/4"])
fw.add(lan)
lan.create()

# virtual router
from panos.network import VirtualRouter, StaticRoute

default_route = StaticRoute(
    name="test",
    destination="0.0.0.0/0",
    nexthop_type="",
    nexthop=""
)

router = VirtualRouter(name="default", interface=["ethernet1/1", "ethernet1/3", "ethernet1/4"])

# append children object
# router.children.append(default_route)
fw.add(router)
router.create()

# Policies

from panos.policies import Rulebase, SecurityRule, NatRule

rb = Rulebase()
fw.add(rb)

internet_access = SecurityRule(
    name="LAN TO WAN",
    fromzone=["LAN"],
    tozone=["WAN"],
    application=["dns","ntp","ping","rtp","ssl","web-browsing"],
    action="allow"
)
rb.add(internet_access)
internet_access.create()

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

dhcp_server(firewall_ip, api_key, "ethernet1/3", "192.168.3.1", "255.255.255.0", "192.168.3.0", "ethernet1/1")
dhcp_server(firewall_ip, api_key, "ethernet1/4", "192.168.4.1", "255.255.255.0", "192.168.4.0", "ethernet1/1")

commit_response = fw.commit(sync=True, exception=True)
print(commit_response["messages"])
