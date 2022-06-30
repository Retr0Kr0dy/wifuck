# WiFuck

WiFuck is a simplifier for wifi bullshitting, such as deauth, mitm, etc...

### Requirements ;

- [aircrack-ng](https://www.aircrack-ng.org/)
- [python3.10](https://www.python.org/downloads/)
- [scapy](https://scapy.net/) (python lib)

## Summary 

- Usage
- WiFuck vs WiFuck-rpi vs Web-WiFuck

## Usage

### Commands options ;

> `<no args>`

WiFuck normal usage, start an AP scanner and then deauth all clients. <br>
> `scan <net-adapter>`                        

Scan for AP. <br>
> `deauth <AP-mac-addr> <client-mac-addr>`    

Deauth with specific mac addrs, (AP and client mac can be replace by X <br>
for broadcast (ff:ff:ff:ff:ff:ff)). <br>


## WiFuck vs WiFuck-rpi vs Web-WiFuck

### WiFuck

Is the bare-bone version of WiFuck, it should work gracefully.

### WiFuck-rpi

Version Raspberry pi, asking less questions, printing less tings, do less things

### Web-WiFuck

No-fonctional Releases.
