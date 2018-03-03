# Xmas Scan
This repository contains code for detecting Xmas Scans.

# Prerequisites
* dpkt==1.9.1

# Installing Prerequisites
pip install dpkt

# Introduction
An attacker uses a TCP Xmas Scan to determine which ports are closed on the target machine. 
This scan type is accomplished by sending TCP segments with the FIN, PSH and URG flags set in the packet header. These segments are illegal according to RFC 793. The expected behavior is that any illegal TCP segment sent to an open port is discarded, whereas illegal segments sent to closed ports are handled with a RST in response.

This behavior allows an attacker to scan for closed ports by sending rule-breaking packets and detect closed ports via RST packets. The major advantage of this scan type is its ability to scan through stateless firewall or ACL filters. Such filters are configured to block access to ports usually by preventing SYN packets, thus stopping any attempt to 'build' a connection. XMAS packets tend to pass through such devices undetected. 

Additionally, because open ports are inferred via no responses being generated, Xmas scan cannot distinguish an open port from a filtered port.

# Executing the code
python xmas.py xmas.pcap
