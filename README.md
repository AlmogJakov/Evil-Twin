# Evil Twin Attack & Defending

<p align="center"><img src="https://github.com/AlmogJakov/Protection-of-wireless-and-mobile-networks/blob/main/demos/evil_twin.jpg"/></p>

--------------------------------------------------------------------------------------------------

An evil twin attack is a spoofing cyberattack that works by tricking users into connecting to a fake Wi-Fi access point that mimics a legitimate network. Once a user is connected to an “evil twin” network, hackers can access everything from their network traffic to private login credentials.

Please note that this utility is for educational purposes only.

--------------------------------------------------------------------------------------------------

<h3>Requirements</h3>    

The following requirements are required for running the program
   
<b>Network hardware requirements:</b>
1. Network adapter with monitor mode support (used for attack)
2. Network adapter with AP setup support (used for fake network)
3. Accessing the network by one of the following interfaces:
    * Additional wired internet interface
    * Interface created by splitting one of the interfaces of the network adapters above

* for checking adapter supported options run 'iw list'

<b>Software requirements:</b>

|||||
| ------------- | ------------- | ------------- | ------------- |
| <b>python3</b> | <b>pandas</b> | <b>numpy</b> | <b>scapy</b>  |
| <b>hostapd</b> | <b>dnsmasq</b> | <b>iptables</b> | <b>net-tools</b> |
| <b>apache2</b> | <b>php (libapache2-mod-php)</b> | | |
 
  --------------------------------------------------------------------------------------------------

<h3>Checking Wifi Adapter</h3>   
Install Details: https://www.aircrack-ng.org/doku.php?id=install_aircrack (Under Compiling and installing)   

AirCrack Dependencies:   
- 'sudo apt-get update -y'   
- 'sudo apt-get install libz-dev'   
- 'sudo apt-get install libssl-dev'   
- 'sudo apt-get install ethtool'   
    
Utility At: 'sudo aircrack-ng'   

Injection Test Details: https://www.aircrack-ng.org/doku.php?id=injection_test   
   
   
Interfaces Details: 'sudo /usr/local/sbin/airmon-ng' OR 'sudo /usr/sbin/airmon-ng'   
    (can be found with 'find / -name airmon-ng')
    
Start: 'sudo airmon-ng start wlan0'   

Injection Test: 'sudo aireplay-ng -9 wlan0mon'   

Checking attack types (2 cards are needed): 'sudo aireplay-ng -9 -i wlan1mon wlan0mon'   
    (When the attacking card is wlan0mon)   
    
 Should run before: 'sudo airmon-ng check kill'   
 
 
 --------------------------------------------------------------------------------------------------
 
  <h3>Screenshots</h3>    
  
 
| Network Scanning Screen | Welcome Screen |
| ------------- | ------------- |
| <p align="center"><img src="https://github.com/AlmogJakov/Protection-of-wireless-and-mobile-networks/blob/main/demos/scanning.jpg"/></p>  | <p align="center"><img src="https://github.com/AlmogJakov/Protection-of-wireless-and-mobile-networks/blob/main/demos/welcome.jpg"/></p>  |


| Fake AP Screen | Deauth Attack Screen |
| ------------- | ------------- |
| <p align="center"><img src="https://github.com/AlmogJakov/Protection-of-wireless-and-mobile-networks/blob/main/demos/fakeap.jpg"/></p>  | <p align="center"><img src="https://github.com/AlmogJakov/Protection-of-wireless-and-mobile-networks/blob/main/demos/deauth.jpg"/></p>  |

  --------------------------------------------------------------------------------------------------
 
 <h3>Troubleshooting</h3>    
 
 <b>Error:</b> Could not set interface flags (UP): No such device   
 <b>Solution:</b> Re-plug the adapter   
    
 <b>Error:</b> Failed to set beacon parameters   
 <b>Solution:</b> Disable NetworkAdapter from managing the interface via 'nmcli device set {NAME} managed no'   


   --------------------------------------------------------------------------------------------------
