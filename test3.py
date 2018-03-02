import dpkt
import socket

f = open('evidence.pcap')
pcap = dpkt.pcap.Reader(f)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    if type(eth.data) == dpkt.ip.IP:
        ip = eth.data
        print(1)
        if type(ip.data) == dpkt.icmp.ICMP:
                print inet_to_str(ip.src)
                print inet_to_str(ip.dst)
                icmp = ip.data
                print(icmp.type)
                print(icmp.code)
                print
    

    """tcp = ip.data
    if type(tcp) == dpkt.tcp.TCP:
        if tcp.dport == 80 and len(tcp.data) > 0:
            http = dpkt.http.Request(tcp.data)
            print http.uri"""

    """if tcp.dport == 80 and len(tcp.data) > 0:
        http = dpkt.http.Request(tcp.data)
        print http.uri"""

f.close()
