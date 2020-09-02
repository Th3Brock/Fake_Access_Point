#pip3 install fake scapy
#airmon-ng check kill
#airmon-ng start wlan0
from scapy.all import *
from threading import Thread
from faker import Faker
from colorama import init, Fore
import sys, random

# some colors
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

def ClownLogo():
    clear = "\x1b[0m"
    colors = [36, 32, 34, 35, 31, 37]

    x = """

  ___     _           _                     ___     _     _   
 | __|_ _| |_____    /_\  __ __ ___ ______ | _ \___(_)_ _| |_ 
 | _/ _` | / / -_)  / _ \/ _/ _/ -_|_-<_-< |  _/ _ \ | ' \  _|
 |_|\__,_|_\_\___| /_/ \_\__\__\___/__/__/ |_| \___/_|_||_\__|
                                                              
Nota! : Scanning Port es un escaner 100% funcional, verifique con nmap.       
    """
    for N, line in enumerate(x.split("\n")):
         sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
         time.sleep(0.05)

def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # type=0:       management frame
    # subtype=8:    beacon frame
    # addr1:        MAC address of the receiver
    # addr2:        MAC address of the sender
    # addr3:        MAC address of the Access Point (AP)

    # beacon frame
    beacon = Dot11Beacon()
    
    # we inject the ssid name
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    
    # stack all the layers and add a RadioTap
    frame = RadioTap()/dot11/beacon/essid

    # send the frame
    if infinite:
        sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)
    else:
        sendp(frame, iface=iface, verbose=0)

if __name__ == "__main__":
    import argparse
    ClownLogo()
    parser = argparse.ArgumentParser(description="Fake Access Point Generator")
    parser.add_argument("interface", default="wlan0mon", help="The interface to send beacon frames with, must be in monitor mode")
    parser.add_argument("-n", "--access-points", dest="n_ap", help="Number of access points to be generated")
    args = parser.parse_args()
    n_ap = args.n_ap
    iface = args.interface
    # generate random SSIDs and MACs
    faker = Faker()
    ssids_macs = [ (faker.name(), faker.mac_address()) for i in range(n_ap) ]
    for ssid, mac in ssids_macs:
        Thread(target=send_beacon, args=(ssid, mac)).start()