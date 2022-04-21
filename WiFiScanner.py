from scapy.all import *
from threading import Thread
import pandas
import time
import os

# RUN EXAMPLE: sudo /bin/python3.8 /home/user/Documents/WiFiScanner.py
# RUN EXAMPLE: sudo python3 WiFiScanner.py
# (Should run with 'sudo')
# Source: https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy

# initialize the networks dataframe that will contain all access points nearby
cols=['BSSID', 'SSID', 'dBm_Signal', 'Channel', 'Crypto']
networks = pandas.DataFrame(columns=cols, dtype=object)
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

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
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)


def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


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
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=interface, timeout=60)
    # Details: https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sniffing/index.html