from rich import print
from rich.panel import Panel
from rich.text import Text
from ipaddress import ip_address
from os import name
import socket
from struct import unpack
from sys import exit, argv

def banner():
    banner = Text("The Network Sniffer", justify='center', style='green bold underline')
    print(Panel(banner))
    print()

class IP:
    def __init__(self, buff=None):
        header = unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
    
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # Human Readable IP Addresses
        self.src_address = ip_address(self.src)
        self.dst_address = ip_address(self.dst)

        # Map Protocol Contants with their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as err:
            print('%s No protocol for %s' % (err, self.protocol_num))
            self.protocol = str(self.protocol_num)

class ICMP:
    def __init__(self, buff):
        header = unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def sniff(host):
    if (name == 'nt'):
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    if (name == 'nt'):
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65535)[0]
            ip_header = IP(raw_buffer[0:20])
            
            # If it's ICMP, we want it!
            if (ip_header.protocol == "ICMP"):
                print('[b]Protocol[/]: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
                print(f'[b]Version[/]: {ip_header.ver}')
                print(f'[b]Header[/]: Length: {ip_header.ihl} TTL: {ip_header.ttl}')

                # Calculate where our ICMP packet starts
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]

                # Create our ICMP structure
                icmp_header = ICMP(buf)
                print('[b]ICMP[/]: Type: %s Code: %s\n' % (icmp_header.type, icmp_header.code))
                
    except KeyboardInterrupt:
        if (name == 'nt'):
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        exit()

if __name__ == '__main__':
    banner()
    if (len(argv) == 2):
        host = argv[1]
    else:
        host = '192.168.225.43'

    sniff(host)
