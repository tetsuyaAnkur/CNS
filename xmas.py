import dpkt
import socket
from collections import defaultdict

f = open('xmas.pcap')
pcap = dpkt.pcap.Reader(f)
ip_count = defaultdict(int)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)

    if type(eth.data) == dpkt.ip.IP:
        ip = eth.data

        if type(ip.data) == dpkt.tcp.TCP:
            tcp = ip.data
            if tcp.flags==41:
                ip_count[inet_to_str(ip.src)]+=1
                #print inet_to_str(ip.dst)  

    """tcp = ip.data
    if type(tcp) == dpkt.tcp.TCP:
        if tcp.dport == 80 and len(tcp.data) > 0:
            http = dpkt.http.Request(tcp.data)
            print http.uri"""

    """if tcp.dport == 80 and len(tcp.data) > 0:
        http = dpkt.http.Request(tcp.data)
        print http.uri"""

for ip in ip_count.keys():
    print(ip)

f.close()
