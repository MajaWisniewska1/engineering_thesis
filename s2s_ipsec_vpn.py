from panos import firewall
from panos.network import Zone, ManagementProfile
from panos.network import TunnelInterface
from panos.network import VirtualRouter, StaticRoute
from panos.network import IkeCryptoProfile, IkeGateway, IpsecCryptoProfile, IpsecTunnel, IpsecTunnelIpv4ProxyId
from panos.policies import SecurityRule, Rulebase
from xml_functions import dhcp_server

def s2s_vpn_setup(fw, tunnel_monitor_ip, remote_wan_ip, tunnel_mon_dest_ip, local, remote, api_key, firewall_ip, dhcp_gateway, ip_pool):  

    vpn_zone = Zone(name = "VPN", mode = "layer3", interface = ["tunnel.1"])
    fw.add(vpn_zone)
    vpn_zone.create()

    vpn_profile = ManagementProfile(name = "VPN profile", ping = True)
    fw.add(vpn_profile)
    vpn_profile.create()

    int_tunnel = TunnelInterface(name = "tunnel.1", ip = tunnel_monitor_ip, management_profile = vpn_profile)
    fw.add(int_tunnel)
    int_tunnel.create()

    static_route = StaticRoute(
        name = "s2s vpn",
        destination = remote,
        nexthop_type = "ip-address",
        nexthop = tunnel_mon_dest_ip,
        interface = "tunnel.1"
    )

    router = VirtualRouter(name = "default", interface = ["tunnel.1"])

    router.children.append(static_route)
    fw.add(router)
    router.create()

    ike_crypto_profile = IkeCryptoProfile(
        name = "My-IKE-crypto-profile",
        dh_group = "group2",
        authentication = "sha256",
        encryption = "aes-256-cbc"
    )
    fw.add(ike_crypto_profile)
    ike_crypto_profile.create()

    ike_gateway = IkeGateway(
        name = "IKE-Gateway",
        version = "ikev1",
        interface = "ethernet1/1",
        peer_ip_value = remote_wan_ip,
        pre_shared_key = "safe_password",
        ikev1_crypto_profile = ike_crypto_profile
    )
    fw.add(ike_gateway)
    ike_gateway.create()

    ipsec_crypto_profile = IpsecCryptoProfile(
        name = "My-IPsec-crypto-profile",
        dh_group = "group2",
        esp_encryption = "aes-256-cbc",
        esp_authentication = "sha256",
        lifetime_hours = 1
    )
    fw.add(ipsec_crypto_profile)
    ipsec_crypto_profile.create()

    ipsec_tunnel = IpsecTunnel(
        name = "IPsecTunnel",
        tunnel_interface = "tunnel.1",
        ak_ike_gateway = "IKE-Gateway",
        ak_ipsec_crypto_profile = "My-IPsec-crypto-profile",
        enable_tunnel_monitor = True,
        tunnel_monitor_dest_ip = tunnel_mon_dest_ip,
    )
    fw.add(ipsec_tunnel)
    ipsec_tunnel.create()

    proxy_id = IpsecTunnelIpv4ProxyId(name = "NetID", local = local, remote = remote, any_protocol = True)
    ipsec_tunnel.add(proxy_id)
    proxy_id.create()

    security_policy = SecurityRule(name="LAN TO VPN", fromzone=["VPN", "LAN"], tozone=["VPN", "LAN"], action="allow")
    rb = Rulebase()
    fw.add(rb)
    rb.add(security_policy)
    security_policy.create()

    dhcp_server(firewall_ip, api_key, "ethernet1/7", dhcp_gateway, "255.255.255.0", ip_pool, "ethernet1/1")

    return fw.commit()


def main():
    
    fw13_ip = "<fw13_mgmt_ip>"
    fw13_api_key = "<xml_api_key>"
    fw13 = firewall.Firewall(fw13_ip, "<login>", "<password>") 
    
    fw14_ip = "<fw14_mgmt_ip>"
    fw14 = firewall.Firewall(fw14_ip, "<login>", "<password>") 
    fw14_api_key = "<xml_api_key>"

    tunnel_monitor_ip_fw13 = "172.16.12.1/24"
    tunnel_monitor_ip_fw14 = "172.16.12.2/24"

    wan_ip_fw13 = "10.74.4.13"
    wan_ip_fw14 = "10.74.4.14"

    fw13_tunnel_monitor_dest = "172.16.12.2"
    fw14_tunnel_monitor_dest = "172.16.12.1"

    netA = "192.168.4.0/24"
    netB = "192.168.2.0/24"

    pool_A = "192.168.4.0"
    default_gw_A = "192.168.4.1"

    pool_B = "192.168.2.0"
    default_gw_B = "192.168.2.1"

    commit_id_fw13 = s2s_vpn_setup(fw13, tunnel_monitor_ip_fw13, wan_ip_fw14, fw13_tunnel_monitor_dest, netA, netB, fw13_api_key, fw13_ip, default_gw_A, pool_A)
    commit_id_fw14 = s2s_vpn_setup(fw14, tunnel_monitor_ip_fw14, wan_ip_fw13, fw14_tunnel_monitor_dest, netB, netA, fw14_api_key, fw14_ip, default_gw_B, pool_B)
    
    message_fw13 = fw13.syncjob(commit_id_fw13, interval=5)
    print(message_fw13["messages"])
    message_fw14 = fw14.syncjob(commit_id_fw14, interval=5)
    print(message_fw14["messages"])

if __name__ == "__main__":
    main()
