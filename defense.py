import sys

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth
from threading import Thread
import warnings
from DDoS import DDoS

# phone = "a8:9c:ed:69:f0:1b"
wifi = "ec:41:18:b8:e6:4c"
iped = '70:11:24:16:be:68'


class NetworkDetails:
    user_to_save = iped
    right_network = wifi
    right_network_ssid = 'orna_plus'
    fake_ap = ''


class Var:
    num_of_deauth = 0
    time_now = 0
    reset = False
    stop_threads = False


warnings.filterwarnings('ignore')
time_check = 2


def sleep_time():
    while True:
        time.sleep(1)
        Var.time_now += 1



def search_fake_ap(packet):
    if packet.haslayer(Dot11Beacon):
        # Get the name of the network
        ssid = packet[Dot11Elt].info.decode()  # A Generic 802.11 Element

        # Extract the MAC address of the network (address 2 = address mac of the transmitter)
        bssid = packet[Dot11].addr2
        if str(ssid) == NetworkDetails.right_network_ssid and str(bssid) != NetworkDetails.right_network:
            NetworkDetails.fake_ap = bssid
            Var.stop_threads = True


def search_deauth_attack(packet):
    # set timer
    if Var.time_now % time_check == 0 and not Var.reset:
        # it is attack
        if Var.num_of_deauth > 10:
            print('There is attack!')
            Var.stop_threads = True
        print(Var.num_of_deauth)
        Var.num_of_deauth = 0
        Var.reset = True
    if Var.time_now % time_check != 0:
        Var.reset = False

    # check if the packet is Dot11Deauth
    frame = packet[Dot11]
    if packet.haslayer(Dot11Deauth):
        if str(frame.addr2) == NetworkDetails.user_to_save or str(frame.addr1) == NetworkDetails.user_to_save:
            Var.num_of_deauth += 1


def change_channel(interface):
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)
        if Var.stop_threads:
            break


def is_alive(s):
    while True:
        if Var.stop_threads or not s.running:
            break
        time.sleep(1)


def sniffing(interface, callback, timeout=False):
    # Start the channel changer
    channel_changer = Thread(target=change_channel, args=(interface,))
    channel_changer.daemon = True
    channel_changer.start()
    Var.stop_threads = False

    # Start sniffing (Synchronous process)
    s = AsyncSniffer(prn=callback, iface=interface)
    if timeout:
        s = AsyncSniffer(prn=callback, iface=interface, timeout=20) # ,
    s.start()

    # Set timer
    t = threading.Thread(target=is_alive, args=(s, ))
    t.start()
    t.join()

    if not timeout:
        s.stop()



def defense(interface: str, net, user: str):
    # Details of the legal network
    NetworkDetails.right_network_ssid = net['SSID']
    NetworkDetails.right_network = net['BSSID']
    NetworkDetails.user_to_save = user
    # interface = 'wlx5ca6e6a31cec'

    # Set timer
    st = threading.Thread(target=sleep_time)
    st.start()

    while True:
        # Search attack
        print('\nSearch For Evil-Twin Attack...')
        sniffing(interface, search_deauth_attack)

        # Search Fake AP
        print('\nSearch For Fake AP...')
        sniffing(interface, search_fake_ap, timeout=True)

        # DDoS Attack
        if NetworkDetails.fake_ap != '':
            print('\nDDoS Attack!')
            DDoS(interface, NetworkDetails.fake_ap, 40)

        Var.stop_threads = False
