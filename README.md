
# Intrusion Detection System (PCAP)

A simple Intrusion Detection System (IDS). The
IDS will analyze all the packets from a file with the help of the pcap library and generate
alerts based on provided rules.

## Usage 
    The rule format should be the following:
    <src IP address> <src port> <dst IP address> <dst port> “ALERT”
    1. Read a file named “alerts.txt” which will contain the alerts, each one in a separate
    line
    2. Read the traffic from a .pcap file
    3. Inspect the packets for matching rules and print the alerts

