import requests

def dhcp_server(firewall_ip, api_key, interface, gateway, netmask, ip_pool, inheritance_source):
    """
    Configures a DHCP server on a specific interface of the firewall.

    Args:
        firewall_ip (str): IP address of the firewall
        api_key (str): API key for authentication
        interface (str): Name of the interface to configure the DHCP server on
        gateway (str): Default gateway for the DHCP clients
        netmask (str): Subnet mask for the DHCP clients
        ip_pool (str): IP range for the DHCP clients
        inheritance_source (str): Specifies where to inherit settings like DNS information from (e.g., another interface)
    """
    dhcp_config = f"<entry name='{interface}'><server><option><dns><primary>inherited</primary><secondary>inherited</secondary></dns><inheritance><source>{inheritance_source}</source></inheritance><lease><unlimited/></lease><gateway>{gateway}</gateway><subnet-mask>{netmask}</subnet-mask></option><ip-pool><member>{ip_pool}</member></ip-pool><mode>auto</mode></server></entry>"

    url = f"https://{firewall_ip}/api/"
    params = {
        "type": "config",
        "action": "set",
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/network/dhcp/interface",
        "element": dhcp_config,
        "key": api_key,
    }

    response = requests.get(url, params=params, verify=False)
    
    if "command succeeded" in response.text:
        print(f"DHCP server configuration on interface {interface} successfully completed!\n")
    else:
        print(f"Error during DHCP server configuration on interface {interface}:\n", response.text)


def ha_election_settings(firewall_ip, api_key, preemptive="no", device_priority=100):
    """
    Configures HA (High Availability) election settings.

    Args:
        firewall_ip (str): IP address of the firewall
        api_key (str): API key for authentication
        preemptive (str, optional): Whether preemption is enabled ("yes" or "no"). Default is "no"
        device_priority (int, optional): Priority value for HA election. Default is 100
    """
    url = f"https://{firewall_ip}/api/"
    params = {
        "key": api_key,
        "type": "config",
        "action": "set",
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/deviceconfig/high-availability/group/election-option",
        "element": f"<preemptive>{preemptive}</preemptive><device-priority>{device_priority}</device-priority>"
    }
    try:
        response = requests.get(url, params=params, verify=False)                      
    except:
        print(response.text)

def ha_link_monitoring(firewall_ip, api_key,link_group_name, interfaces, failure_condition="any", enabled="yes"):
    """
    Configures link monitoring settings for High Availability.

    Args:
        firewall_ip (str): IP address of the firewall.
        api_key (str): API key for authentication.
        link_group_name (str): Name of the link monitoring group.
        interfaces (list): List of interfaces to monitor.
        failure_condition (str, optional): Condition for failure ("any" or "all"). Default is "any".
        enabled (str, optional): Whether link monitoring is enabled ("yes" or "no"). Default is "yes".
    """
    interfaces_str = ""
    for interface in interfaces:
        interfaces_str = "".join([interfaces_str, "<member>", interface, "</member>"])
      
    url = f"https://{firewall_ip}/api/"
    params = {
        "key": api_key,
        "type": "config",
        "action": "set",
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/deviceconfig/high-availability/group/monitoring/link-monitoring/link-group",
        "element": f"<entry name='{link_group_name}'><interface>{interfaces_str}</interface><failure-condition>{failure_condition}</failure-condition><enabled>{enabled}</enabled></entry>"
    }
    try:
        response = requests.get(url, params=params, verify=False)                       
    except:
        print(response.text)

def generate_certificate(firewall_ip, api_key, cert_name, common_name, ca, signed_by=""):
    """
    Generates a certificate on the firewall using the RSA algorithm for key pair generation.

    Args:
        firewall_ip (str): IP address of the firewall.
        api_key (str): API key for authentication.
        cert_name (str): Name of the certificate.
        common_name (str): Common Name (CN) for the certificate.
        ca (str): Whether the certificate is a CA (Certificate Authority) certificate ("yes" or "no").
        signed_by (str, optional): Name of the signing CA, if applicable. Default is an empty string (self-signed).
    """
    url = f"https://{firewall_ip}/api/"

    if signed_by=="":
        cmd = f"<request><certificate><generate><algorithm><RSA><rsa-nbits>2048</rsa-nbits></RSA></algorithm><certificate-name>{cert_name}</certificate-name><name>{common_name}</name><ca>{ca}</ca></generate></certificate></request>"
    else:
        cmd = f"<request><certificate><generate><algorithm><RSA><rsa-nbits>2048</rsa-nbits></RSA></algorithm><certificate-name>{cert_name}</certificate-name><name>{common_name}</name><signed-by>{signed_by}</signed-by><ca>{ca}</ca></generate></certificate></request>"

    params = {
    "type": "op",
    "cmd": cmd,
    "key": api_key,
    }
    try:
        response = requests.get(url, params=params, verify=False)                       
    except:
        print(response.text)


def ssl_tls_profile(firewall_ip, api_key, profile_name, cert_name):
    """
    Configures an SSL/TLS profile on the firewall.

    Args:
        firewall_ip (str): IP address of the firewall.
        api_key (str): API key for authentication.
        profile_name (str): Name of the SSL/TLS profile.
        cert_name (str): Name of the certificate to associate with the profile.
    """
    url = f"https://{firewall_ip}/api/"
    params = {
        "key": api_key,
        "type": "config",
        "action": "set",
        "xpath": f"/config/shared/ssl-tls-service-profile",
        "element": f"<entry name='{profile_name}'><certificate>{cert_name}</certificate></entry>"
    }
    try:
        response = requests.get(url, params=params, verify=False)                       
    except:
        print(response.text)


def new_local_user(firewall_ip, api_key, login, hash):
    """
    Creates a new local user on the firewall.

    Args:
        firewall_ip (str): IP address of the firewall.
        api_key (str): API key for authentication.
        login (str): Username for the new user.
        hash (str): Hashed password for the new user.
    """
    url = f"https://{firewall_ip}/api/"
    params = {
        "key": api_key,
        "type": "config",
        "action": "set",
        "xpath": "/config/shared/local-user-database/user",
        "element": f"<entry name='{login}'><phash>{hash}</phash></entry>"
    }
    try:
        response = requests.get(url, params=params, verify=False)                       
    except:
        print(response.text)


