from panos.firewall import Firewall
from panos.device import LocalUserDatabaseUser
from panos.device import AuthenticationProfile
from panos.network import Zone, TunnelInterface
from xml_functions import ssl_tls_profile, generate_certificate
from panos.policies import Rulebase, SecurityRule

firewall_ip = "fw_mgmt_ip"
fw = Firewall(firewall_ip, "<login>", "<password>")
api_key = "xml_api_key"
   
# root certificate
root_cert_name = "RootCert"
generate_certificate(firewall_ip, api_key, root_cert_name, "10.74.1.13", ca="yes")

# client certificate
cert_name = "ClientCert"
generate_certificate(firewall_ip, api_key, cert_name, "10.74.4.13", ca="no", signed_by=root_cert_name)

# ssl/tls profile
ssl_tls_profile_name = "my_ssl_tls_profile"
ssl_tls_profile(firewall_ip, api_key, ssl_tls_profile_name, cert_name)

# creating local user for GP Clientless VPN
new_user = LocalUserDatabaseUser(name = "student", password_hash = "")  

# creating an authentication profile for clientless VPN
auth_profile_name = "Auth_Profile"
auth_profile = AuthenticationProfile(auth_profile_name, profile_type = "local-database", allow_list = ["all"])
fw.add(auth_profile)
auth_profile.create()

# creating a tunnel interface for Clientless GlobalProtect
int_tunnel = TunnelInterface(name = "tunnel", comment = "for GlobalProtect", )
fw.add(int_tunnel)
int_tunnel.create()

# creating a zone for GlobalProtect
vpn_zone = Zone(name = "VPN", mode = "layer3", interface = ["tunnel"], enable_user_identificantion = True)
fw.add(vpn_zone)
vpn_zone.create()

router = VirtualRouter(name="default", interface=["tunnel"])
fw.add(router)
router.create()

# Security policy for GlobalProtect
rb = Rulebase()
fw.add(rb)

sec_policy_for_gp = SecurityRule(name="Security policy for GlobalProtect", fromzone=["VPN", "LAN"], tozone=["LAN", "VPN"], action="allow")
rb.add(sec_policy_for_gp)
sec_policy_for_gp.create()


fw.commit()

 