import ctypes
import os
import socket
import logging
import sys

from HttpMessage import HttpRequestMessage
from IPHeader import IPHeader
from Printer import show
from TcpPacketHeader import TcpPacketHeader


class Sniffer:
    MAX_BUFFER_SIZE = 65536
    IP_HEADER_LENGTH = 20
    TCP_HEADER_LENGTH = 20

    def __init__(self, file_output=sys.stdout):
        self.file_output = file_output
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
        # key is tuple of (dest_ip, dest_port)

        self.fragments = dict()

    def tcp_parser(self, data, destination_address):
        tcp_packet = TcpPacketHeader(data)
        data_start_pos = self.TCP_HEADER_LENGTH
        if tcp_packet.Source_port == 80 or tcp_packet.Destination_port == 80:
            if (destination_address, tcp_packet.Destination_port) in self.fragments:
                self.fragments[(destination_address, tcp_packet.Destination_port)] += data[data_start_pos:]
            #     if has_connection_closed(
            #             self.fragments[(destination_address, tcp_packet.Destination_port)]):
            #         if tcp_packet.FIN == 1:
            #             self.http_parser(self.fragments[(destination_address, tcp_packet.Destination_port)])
            #             del self.fragments[(destination_address, tcp_packet.Destination_port)]
            #     elif (get_content_length(
            #             self.fragments[(destination_address, tcp_packet.Destination_port)]) == len(
            #         self.fragments[(destination_address, tcp_packet.Destination_port)])
            #           or len(data[data_start_pos:]) == 0):
            #         print(f"Content-Length: {get_content_length(self.fragments[(destination_address, tcp_packet.Destination_port)])}")
            #         if self.http_parser(self.fragments[(destination_address, tcp_packet.Destination_port)]):
            #             print("HTTP packet: ", self.fragments[(destination_address, tcp_packet.Destination_port)], file=self.file_output)
            #
            #         del self.fragments[(destination_address, tcp_packet.Destination_port)]
            # else:
            #     if get_content_length(data[data_start_pos:]) != len(
            #             data[data_start_pos:]):
            #         self.fragments[(destination_address, tcp_packet.Destination_port)] = data[data_start_pos:]
            #     if get_content_length(self.fragments[(destination_address, tcp_packet.Destination_port)]) == len(
            #             self.fragments[(destination_address, tcp_packet.Destination_port)]):
            #         self.http_parser(data[data_start_pos:])
            #         del self.fragments[(destination_address, tcp_packet.Destination_port)]
            self.http_parser(data[data_start_pos:])

    def http_parser(self, http_data_bytes):
        try:
            http_data_string = http_data_bytes.decode("utf-8")
            if "GET" not in http_data_string and  "POST" not in http_data_string:
                return
            http_request = HttpRequestMessage(http_data_string)
            http_request.parse()
            if "/2023/images/style/spacer.gif" in http_request.__str__() or "2023/css/main.css" in http_request.__str__():
                return True
            show(http_request.get_as_list())
            print(http_request, file=self.file_output)
        except:
            logging.warning("Could not decode HTTP")

    def sniff(self, filters=None, event_stop=None, event_pause = None):
        """

        :param filters:
        :param event:
        :return:
        """
        while event_stop is None or not event_stop.is_set():
            if event_pause is not None and event_pause.is_set():
                continue

            raw_data = self.conn.recv(Sniffer.MAX_BUFFER_SIZE)
            ip_packet = IPHeader(raw_data[:self.IP_HEADER_LENGTH])
            if ip_packet.Protocol == 6:
                part_of = raw_data[self.IP_HEADER_LENGTH:]
                self.tcp_parser(part_of, ip_packet.Destination_address)


def get_content_length(data):
    try:
        data_s = data.decode("utf-8")
    except:
        return -1
    data_s = data.decode("utf-8")
    content_length = -1
    for line in data_s.split("\r\n"):
        if "Content-Length" in line:
            content_length = int(line.split(":")[1])
            print("Content-Length: ", content_length)
    return content_length


def has_connection_closed(data):
    try:
        data_s = data.decode("utf-8")
    except:
        return False

    if "clos" in data_s.lower():
        return True
    return False
