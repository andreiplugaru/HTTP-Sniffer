import os
import socket
import logging

from HttpMessage import HttpRequestMessage
from IPHeader import IPHeader
from Printer import show
from TcpPacketHeader import TcpPacketHeader
from utils import get_ip_as_string, get_value_for_raw_message, get_http_body_len, check_if_tcp_is_http


class Sniffer:
    MAX_BUFFER_SIZE = 65536
    IP_HEADER_LENGTH = 20
    TCP_HEADER_LENGTH = 20

    def __init__(self):
        """
        Constructor for Sniffer class. Opens a socket and binds it to the host's ip address.
        """
        self.current_http_message = None
        if os.name == 'nt':
            try:
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

    def replace_fragment(self, destination_address, destination_port, current_sequence_number):
        """
        This method is used to replace a fragment with the next one, using the sequence number.
        :param destination_address: the destination address of the packet
        :param destination_port: the destination port of the packet
        :param current_sequence_number: the current sequence number
        """
        if current_sequence_number == self.next_sequence_number:
            return
        self.fragments[(destination_address, destination_port, self.next_sequence_number)] = self.fragments[
            (destination_address, destination_port, current_sequence_number)]
        del self.fragments[(destination_address, destination_port, current_sequence_number)]

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

    def handle_existing_request(self, destination_address, tcp_packet, data, data_start_pos):
        current_fragment_id = (destination_address, tcp_packet.Destination_port, tcp_packet.Sequence_number)
        self.fragments[current_fragment_id] += data[data_start_pos:]
        self.replace_fragment(destination_address, tcp_packet.Destination_port, tcp_packet.Sequence_number)
        current_fragment_id = (destination_address, tcp_packet.Destination_port, self.next_sequence_number)
        if has_connection_closed(self.fragments[current_fragment_id]):
            if tcp_packet.get_FIN():
                self.http_parser(self.fragments[current_fragment_id])
                del self.fragments[current_fragment_id]

        elif (get_content_length(self.fragments[current_fragment_id])
              <= get_http_body_len(self.fragments[current_fragment_id])):
            self.http_parser(self.fragments[current_fragment_id])
            del self.fragments[current_fragment_id]

    def handle_new_request(self, destination_address, tcp_packet, data, data_start_pos):
        current_fragment_id = (destination_address, tcp_packet.Destination_port, tcp_packet.Sequence_number)
        self.fragments[current_fragment_id] = data[data_start_pos:]
        if get_content_length(self.fragments[current_fragment_id]) <= get_http_body_len(self.fragments[current_fragment_id]):
            self.http_parser(data[data_start_pos:])
            del self.fragments[current_fragment_id]

    def apply_filters(self, data):
        grouped_filters = dict()
        for thing in self.shared_resources.filters:
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

    def http_parser(self, http_data_bytes):
        try:
            http_data_string = http_data_bytes.decode(errors='replace')
            if not check_if_tcp_is_http(http_data_string):
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
        Method for sniffing packets. Firstly, it checks if the stop event or the pause event are set. If one of them
        is, it doesn't parse the packets. Otherwise, it creates and instance of :class:`IPHeader` for parsing the
        first 20 bytes of the packet. After this, it parses the next 20 bytes of the packet, which are the TCP
        header.
         :param shared_resources: an instance of :class:`SharedResources` which contains the filters and the stop event.
        """
        self.shared_resources = shared_resources
        while self.shared_resources.stop_event is None or not self.shared_resources.stop_event.is_set():
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
    length_str = get_value_for_raw_message(data, "Content-Length")
    if length_str == "":
        return 0
    return int(length_str)


def has_connection_closed(data):
    # print(get_value_for_raw_message(data, "Connection"))
    return get_value_for_raw_message(data, "Connection") == "Closed"
    # try:
    #     data_s = data.decode("utf-8")
    # except:
    #     return False
    #
    # if "clos" in data_s.lower():
    #     return True
    # return False
