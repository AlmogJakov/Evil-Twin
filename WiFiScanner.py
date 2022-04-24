from scapy.all import *
from threading import Thread
import pandas
import time
import os

import warnings
warnings.filterwarnings('ignore')


# RUN EXAMPLE: sudo /bin/python3.8 /home/user/Documents/WiFiScanner.py
# RUN EXAMPLE: sudo python3 WiFiScanner.py
# (Should run with 'sudo')
# Source: https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy

stop_threads= False
users_list=[]

# initialize the networks dataframe that will contain all access points nearby
cols=['BSSID', 'SSID', 'dBm_Signal', 'Channel', 'Crypto']
networks = pandas.DataFrame(columns=cols, dtype=object)
# # set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)


def callback(packet):
    # Packet Details: https://scapy.readthedocs.io/en/latest/api/scapy.packet.html
    if packet.haslayer(Dot11Beacon):
        # Scapy Layers: https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html
        # Scapy Layers Implementation: https://github.com/secdev/scapy/blob/master/scapy/layers/dot11.py
        # packet.show()
        # Details: https://witestlab.poly.edu/blog/802-11-wireless-lan-2/
        # extract the MAC address of the network (address 2 = address mac of the transmitter)
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode() # A Generic 802.11 Element
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # Dot11Beacon class extend _Dot11EltUtils class which contains 'network_stats' method

        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto") # The type of network encryption
        networks.loc[len(networks.index)] = (bssid, ssid, dbm_signal, channel, crypto)
        


def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)
        if stop_threads:
            break


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)
        if stop_threads:
            break



### The argument 'prn' allows us to pass a function that executes with each packet sniffed 
def client_scan_pkt(pkt):
    global client_list
    # ff:ff:ff:ff:ff:ff - broadcast address 
    if (pkt.addr2 == ap_mac or pkt.addr3 == ap_mac) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in client_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                # Add the new found client to the client list
                client_list.append(pkt.addr1)
                print("Client with MAC address: " + pkt + " was found.")



def Users_handler(pkt):
    global users_list
    if (pkt.addr2 == ap_mac or pkt.addr3 == ap_mac) and pkt.addr2 not in networks["BSSID"] and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in users_list:
            users_list.append(pkt.addr1)
            print(f'{len(users_list)}\t{pkt.addr1}')
            print("Client with MAC address: " + pkt + " was found.")




if __name__ == "__main__":
    # Source: https://stackoverflow.com/questions/3837069/how-to-get-network-interface-card-names-in-python
    interfaces = os.listdir('/sys/class/net/')
    print("Interfaces:")
    for (i, item) in enumerate(interfaces, start=1):
        print("   " + str(i) + ". " + item)
    val = input("Please Choose Interface: ")
    while True:
        try:
            choose = int(val)
            interface = interfaces[choose - 1]
            break
        except:
            val = input("Please Choose Again: ")

    # Enable monitor mode
    os.system(f'sudo ifconfig {interface} down')
    os.system(f'sudo iwconfig {interface} mode monitor')
    os.system(f'sudo ifconfig {interface} up')
    
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    # Details: https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sniffing/index.html

    sniff(prn=callback, iface=interface, timeout=60)

    # Stop printing and changing chanell threads
    stop_threads = True

    val = input("\nPlease enter the index of the AP you want to attack: ")
    while True:
        try:
            net = networks.loc[int(val)]
            break
        except:
            val = input("Please Choose Again Network: ")
    print(f"\n{net}\n")

    # Source: https://shushan.co.il/%D7%94%D7%AA%D7%A7%D7%A4%D7%AA-wi-fi-%D7%94%D7%A6%D7%A4%D7%A0%D7%94-%D7%9E%D7%A1%D7%95%D7%92-wep-%D7%95%D7%91%D7%99%D7%A6%D7%95%D7%A2-packet-injecting
    # Source: https://stackoverflow.com/questions/38931002/how-to-stop-airodump-ng-subprocess-in-python
    # Source: https://stackoverflow.com/questions/32850022/how-to-stop-os-system-in-python
    # Use airodump-ng for packet capturing - save the MAC address of the clients in csv file. 
    print("\nPacket capturing:\n")
    proc = subprocess.Popen(['airodump-ng', 'wlan0mon','--bssid',net["BSSID"], '-c',str(net["Channel"]),
    '--write','clients','--output-format', 'csv'])
    time.sleep(20) # <-- time of scanning
    proc.terminate() # <-- terminate the process

    clients = pandas.read_csv("clients-01.csv")

    # Delete the csv file
    os.system('rm *.csv')

    print("\nClient on Network:")
    # The first 2 rows are not neccessary.
    clients = clients.iloc[2: , :]
    clients.reset_index(inplace=True)
    client_lst = clients["BSSID"]
    print(client_lst)

    val = input("\nPlease enter the index of the client you want to attack: ")
    while True:
        try:
            client = client_lst[int(val)]
            break
        except:
            val = input("Please Choose Again Client: ")
    print(f"\n{client}\n")

    # Disable monitor mode
    os.system(f'sudo ifconfig {interface} down')
    os.system(f'sudo iwconfig {interface} mode managed')
    os.system(f'sudo ifconfig {interface} up')
    

