import socket
import struct


def get_ip_as_string(ip):
    return socket.inet_ntoa(struct.pack("I", ip))