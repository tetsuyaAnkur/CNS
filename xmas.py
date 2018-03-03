# Xmas scan
from collections import defaultdict
import sys
import dpkt
import socket

# Opening the pcap file passed as a command line argument
f = open(sys.argv[1])

# Passing the file to the Reader class for reading records from the file
pcap = dpkt.pcap.Reader(f)

# Dictionaries to store the number of packets sent and received by different hosts
src_ip_count = defaultdict(int)
dst_ip_count = defaultdict(int)

# This function converts an inet object to a string
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# Parsing the pcap file
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)

    if type(eth.data) == dpkt.ip.IP:
        ip = eth.data

        if type(ip.data) == dpkt.tcp.TCP:
            tcp = ip.data

            if tcp.flags==41:
                src_ip_count[inet_to_str(ip.src)]+=1
                
            elif tcp.flags==20:
                dst_ip_count[inet_to_str(ip.dst)]+=1

# printing the ip address of the attacker (person who is possibly doing a Xmas scan)
for ip in src_ip_count.keys():
    count1 = src_ip_count[ip]
    count2 = dst_ip_count[ip]
    count3 = count1/3
    if count1-count2<count3:
        print "Ip address of the attacker is",ip

f.close()
