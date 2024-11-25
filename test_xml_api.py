import requests

api_key = "<xml_api_key"
firewall_ip = "<fw_mgmt_ip>"     

url = f"https://{firewall_ip}/api/"
params = {
    "type": "op",
    "cmd": "<show><system><info></info></system></show>",
    "key": api_key,
}
response = requests.get(url, params=params, verify=False)
print(response.text)