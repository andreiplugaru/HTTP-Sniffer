import ctypes
import os
import socket

import IPHeader
from Sniffer import Sniffer
from TcpPacketHeader import TcpPacketHeader

#
# def main():
#     # Get host
#     host = socket.gethostbyname_ex(socket.gethostname())[-1][-1]
#     print('IP: {}'.format(host))
#     conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
#     conn.bind((host, 0))
#     conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#     conn.ioctl(socket.SIO_RCVALL, 1)
#
#     while True:
#         raw_data, address = conn.recvfrom(65536)
#         print(f"address is {address} and data is {raw_data}")

print(TcpPacketHeader.Source_port)
print(TcpPacketHeader.Destination_port)
print(TcpPacketHeader.Sequence_number)

sniffer = Sniffer()
sniffer.sniff()
