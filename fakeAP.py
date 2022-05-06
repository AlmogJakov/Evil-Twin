import os
import sys


def openAP(net_ssid,net_channel,interface):

    # Source: https://hakin9.org/create-a-fake-access-point-by-anastasis-vasileiadis/

    # os.system("service apache2 start")
    # 1
    # os.system("sudo apt-get update")
    # # 2
    # os.system("sudo apt-get install hostapd dnsmasq")

    # Disable all old proccess
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')

   
    # 5
    conf_text = f"interface={interface}\ndriver=nl80211\nssid={net_ssid}\nhw_mode=g"\
    f"\nchannel={net_channel}\nmacaddr_acl=0\nignore_broadcast_ssid=0\n"\
    "auth_algs=1\nieee80211n=1\nwme_enabled=1"
    conf_file = open("hostapd.conf", "w")
    n = conf_file.write(conf_text)
    conf_file.close()

    
    # 7
    conf_text = f"interface={interface}\ndhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h"\
    "\ndhcp-option=3,192.168.1.1\ndhcp-option=6,192.168.1.1"\
    "\nserver=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address=127.0.0.1"
    conf_file = open("dnsmasq.conf", "w")
    n = conf_file.write(conf_text)
    conf_file.close()


    # 8
    os.system(f"ifconfig {interface} up 192.168.1.1 netmask 255.255.255.0")
    os.system("route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1")

    # 9
    # os.system(f"iptables --table nat --append POSTROUTING -out-interface {interface} -j MASQUERADE")
    # os.system(f"iptables --append FORWARD --in-interface {interface} -j ACCEPT")
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('iptables -P FORWARD ACCEPT')


    # # for clear port 53
    # os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    # os.system('systemctl stop systemd-resolved>/dev/null 2>&1')

    # 6 
    os.system("dnsmasq -C dnsmasq.conf")
    os.system("hostapd hostapd.conf")
    print ("sending client to ap")

    # # 10
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

   	# # ### Enable and start the local DNS stub listener that uses port 53 
    # os.system("systemctl enable systemd-resolved.service >/dev/null 2>&1") 
    # os.system("systemctl start systemd-resolved >/dev/null 2>&1") 

    # os.system("sudo rm /etc/resolv.conf")
    # os.system("sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf")

if __name__ == "__main__":

    openAP(sys.argv[1],sys.argv[2],sys.argv[3])
