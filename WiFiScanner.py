from scapy.all import *
from threading import Thread
import pandas
import time
import os

import warnings
warnings.filterwarnings('ignore')

# RUN EXAMPLE: sudo python3 WiFiScanner.py
# RUN EXAMPLE: sudo /bin/python3.8 /home/user/Documents/WiFiScanner.py
# (Should run with 'sudo')
# Sources can be found here: https://github.com/AlmogJakov/Protection-of-wireless-and-mobile-networks/blob/fc91a2ffe9c7dc98ee32072a3bc1d8fb9bb08943/WiFiScanner.py

stop_threads= False
# initialize the networks dataframe that will contain all access points nearby
cols=['BSSID', 'SSID', 'dBm_Signal', 'Channel', 'Crypto']
networks = pandas.DataFrame(columns=cols, dtype=object)


def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # Extract the MAC address of the network (address 2 = address mac of the transmitter)
        bssid = packet[Dot11].addr2
        if not networks.loc[networks["BSSID"].str.contains(bssid, case=False)].empty:
            return
        # Get the name of the network
        ssid = packet[Dot11Elt].info.decode() # A Generic 802.11 Element
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
    
    # 3. Enable monitor mode
    os.system(f'sudo ifconfig {interface} down')
    os.system(f'sudo iwconfig {interface} mode monitor')
    os.system(f'sudo ifconfig {interface} up')
    
    # 4. Start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()

    # 5. Start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # 6. Start sniffing (Synchronous process)
    sniff(prn=callback, iface=interface, timeout=60)

    # 7. Stop printing and changing channel threads
    stop_threads = True

    # 8 Check if any clients found
    if networks.iloc[: , :]["BSSID"].empty:
            print("\nNo Networks Found! Aborting the process...")
            sys.exit(1)

    # 9. Choose the AP to attack
    val = input("\nPlease enter the index of the AP you want to attack: ")
    while True:
        try:
            net = networks.loc[int(val)]
            break
        except:
            val = input("Please Choose Again Network: ")
    print(f"\n{net}\n")

    # 10. Run airodump-ng in a new process for packet capturing (save the MAC address of the clients in csv file).
    print("\nPacket capturing:\n")
    proc = subprocess.Popen(['airodump-ng', interface,'--bssid',net["BSSID"], '-c',str(net["Channel"]),
    '--write','clients','--output-format', 'csv'])
    time.sleep(20)     # <-- time of scanning
    proc.terminate()   # <-- terminate the process

    # 11. Get the clients from the csv file
    clients = pandas.read_csv("clients-01.csv")

    # 12. Delete the csv file
    os.system('rm *.csv')

    # 13. Check if any clients found
    if clients.iloc[2: , :]["BSSID"].empty:
            print("\nNo clients Found! Aborting the process...")
            sys.exit(1)

    # 14. Print the clients
    print("\nClient on Network:")
    clients = clients.iloc[2: , :] # <-- The first 2 rows are not neccessary.
    clients.reset_index(inplace=True)
    client_lst = clients["BSSID"]
    print(client_lst)

    # 15. Choose the Client to attack
    val = input("\nPlease enter the index of the client you want to attack: ")
    while True:
        try:
            client = client_lst[int(val)]
            break
        except:
            val = input("Please Choose Again Client: ")
    print(f"\n{client}\n")

    # 16. Disable monitor mode
    os.system(f'sudo ifconfig {interface} down')
    os.system(f'sudo iwconfig {interface} mode managed')
    os.system(f'sudo ifconfig {interface} up')