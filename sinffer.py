from os import name
import socket
from ctypes import *
import struct

host = '172.20.10.3'
protocol_map = {1 : "ICMP", 6 : "TCP", 17 : "UDP"}

class IP(Structure):
    _fields_ = [
        ("header_length", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("type_of_service", c_ubyte),
        ("total_length", c_ushort),
        ("identification", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("header_checksum", c_ushort),
        ("source_ip", c_ulong),
        ("destination_ip", c_ulong)
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # cast ip to human readable
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.source_ip))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.destination_ip))

        try:
            self.protocol = protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_short),
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer):
        pass

def main():
    if name == "nt": # if the os is windows
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol =  socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))

    # capture the ip header
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # if windows machine.
    # Enter the machine to promiscuous-mode
    # so it will listen to all traffic that goes throw the network card
    if name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        # read from the socket (sniff packets)
        raw_buffer = sniffer.recvfrom(65565)[0]

        # create IP header from the first 20 bytes
        ip_header = IP(raw_buffer[0:20])
        print("Protocol: " + ip_header.protocol + " + " + ip_header.src_address + " -> " + ip_header.dst_address)
        if ip_header.protocol == "ICMP":
            # calculate where the ip header ends and the icmp header starts
            offset = ip_header.header_length * 4
            buffer = raw_buffer[offset:offset+sizeof(ICMP)]
            if len(buffer) >= 4:
                icmp_header = ICMP(buffer)
                print("ICMP Type: " + str(icmp_header.type) + " Code: " + str(icmp_header.code))


    # turn off the promiscuous-mode

    if name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

main()