import ctypes
import os
import socket
import logging
import sys

from HttpMessage import HttpRequestMessage
from IPHeader import IPHeader
from Printer import show
from TcpPacketHeader import TcpPacketHeader
from utils import get_ip_as_string


class Sniffer:
    MAX_BUFFER_SIZE = 65536
    IP_HEADER_LENGTH = 20
    TCP_HEADER_LENGTH = 20

    def __init__(self):
        self.current_http_message = None
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

    def replace_fragment(self, destination_address, destination_port,  current_sequence_number):
        if current_sequence_number == self.next_sequence_number:
            return
        self.fragments[(destination_address, destination_port, self.next_sequence_number)] = self.fragments[
            (destination_address, destination_port, current_sequence_number)]
        del self.fragments[(destination_address, destination_port, current_sequence_number)]

    def handle_existing_request(self, destination_address, tcp_packet, data, data_start_pos):
        self.fragments[(destination_address, tcp_packet.Destination_port, tcp_packet.Sequence_number)] += data[
                                                                                                          data_start_pos:]
        self.replace_fragment(destination_address, tcp_packet.Destination_port, tcp_packet.Sequence_number)
        if has_connection_closed(
                self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)]):
            if tcp_packet.get_FIN():
                self.http_parser(
                    self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)])
                del self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)]
        elif (get_content_length(
                self.fragments[(destination_address, tcp_packet.Destination_port,
                                self.next_sequence_number)]) <= self.get_http_body_len(
            self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)])
        ):
            self.http_parser(
                self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)])
            del self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)]

    def handle_new_request(self, destination_address, tcp_packet, data, data_start_pos):
        self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)] = data[
                                                                                                        data_start_pos:]
        if get_content_length(self.fragments[(
        destination_address, tcp_packet.Destination_port, self.next_sequence_number)]) <= self.get_http_body_len(
                self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)]):
            self.http_parser(data[data_start_pos:])
            del self.fragments[(destination_address, tcp_packet.Destination_port, self.next_sequence_number)]

    def tcp_parser(self, data, destination_address):
        tcp_packet = TcpPacketHeader(data)
        data_start_pos = self.TCP_HEADER_LENGTH
        if tcp_packet.Source_port != 80 and tcp_packet.Destination_port != 80:
            return

        self.next_sequence_number = tcp_packet.Sequence_number + len(data[data_start_pos:])
        if (destination_address, tcp_packet.Destination_port, tcp_packet.Sequence_number) in self.fragments:
            self.handle_existing_request(destination_address, tcp_packet, data, data_start_pos)
        else:
           self.handle_new_request(destination_address, tcp_packet, data, data_start_pos)

    def apply_filters(self, data):
        grouped_filters = dict()
        for thing in self.filters:
            if type(thing) in grouped_filters:
                grouped_filters[type(thing)].append(thing)
            else:
                grouped_filters[type(thing)] = [thing]

        for _, current_filters in grouped_filters.items():
            flag = False
            for current_filter in current_filters:
                if current_filter.apply(data):
                    flag = True
            if not flag:
                return False
        return True
    def get_http_body_len(self, message):
        try:
            data_s = message[40:].decode(errors='replace')
        except:
            return -1
        data_s = message[40:].decode(errors='replace')
        lines = data_s.split("\r\n\r\n")
        if len(lines) < 2:
            return -1
        return len(lines[1])

    def check_if_is_request(self, data):
        first_word = data.split(" ")[0]
        if first_word in ["GET", "POST", "PUT", "DELETE"]:
            return True
        return False

    def http_parser(self, http_data_bytes):
        try:
            http_data_string = http_data_bytes.decode(errors='replace')
            if not self.check_if_is_request(http_data_string):
                return
            self.shared_resources.http_request_messages.append(http_data_string)
            self.current_http_message.parse(http_data_string)
            if not self.apply_filters(self.current_http_message):
                return
            show(self.current_http_message.get_as_list())
            self.current_http_message = None
        except:
            logging.warning(f"Could not decode HTTP packet: {http_data_bytes}")

    def sniff(self, shared_resources):
        """

        :param shared_resources:
        :param filters:
        :param event:
        :return:
        """
        self.shared_resources = shared_resources
        while self.shared_resources.stop_event is None or not self.shared_resources.stop_event.is_set():
            self.filters = shared_resources.filters
            if self.shared_resources.pause_event is not None and self.shared_resources.pause_event.is_set():
                continue

            raw_data = self.conn.recv(Sniffer.MAX_BUFFER_SIZE)
            ip_packet = IPHeader(raw_data[:self.IP_HEADER_LENGTH])
            self.current_http_message = HttpRequestMessage()
            self.current_http_message.source_ip = get_ip_as_string(ip_packet.Source_address)
            self.current_http_message.destination_ip = get_ip_as_string(ip_packet.Destination_address)
            if ip_packet.Protocol == 6:
                part_of = raw_data[self.IP_HEADER_LENGTH:]
                self.tcp_parser(part_of, ip_packet.Destination_address)


def get_content_length(data):
    try:
        data_s = data.decode("ISO-8859-1")
    except:
        return -1
    data_s = data.decode("ISO-8859-1")
    content_length = -1
    for line in data_s.split("\r\n"):
        if "Content-Length" in line:
            content_length = int(line.split(":")[1])
    return content_length


def has_connection_closed(data):
    try:
        data_s = data.decode("utf-8")
    except:
        return False

    if "clos" in data_s.lower():
        return True
    return False
