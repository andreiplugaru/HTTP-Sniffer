import ctypes
import os
import socket
import logging

class Sniffer:
    MAX_BUFFER_SIZE = 65536

    def __init__(self):
        if os.name == 'nt':
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() == 1
                if not is_admin:
                    logging.error("You need to run this script as an administrator")
                    exit(1)
                host = socket.gethostbyname_ex(socket.gethostname())[-1][-1]
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.conn.bind((host, 0))
                self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.conn.ioctl(socket.SIO_RCVALL, 1)
            except OSError as e:
                logging.error("Error when opening socket: " + e)
                exit(1)
        # implement for linux
        else:
            pass

    def sniff(self):
        while True:
            raw_data, address = self.conn.recvfrom(Sniffer.MAX_BUFFER_SIZE)
            print(raw_data)

