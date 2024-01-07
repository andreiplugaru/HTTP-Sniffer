import ctypes
import logging
import socket
import struct
import sys

valid_http_methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}


def get_ip_as_string(ip):
    return socket.inet_ntoa(struct.pack("I", ip))


def check_if_admin():
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() == 1
    if not is_admin:
        logging.error("You need to run this script as an administrator")
        exit(1)


def setup_logging():
    logger = logging.getLogger('my_logger')
    logger.setLevel(logging.DEBUG)

    warning_handler = logging.FileHandler('output.log')
    warning_handler.setLevel(logging.WARNING)

    error_handler = logging.StreamHandler(sys.stdout)
    error_handler.setLevel(logging.ERROR)

    logger.addHandler(warning_handler)
    logger.addHandler(error_handler)


def get_value_for_raw_message(raw_message, key):
    """
    In the header of a http request message, the value for a key is the part after the key and the colon.
    The raw message is the message as a byte array, so it needs to be decoded first.
    :param raw_message: the raw message supposed to be http request message.
    :param key: the key for which we want to find the value.
    :return: the value for the given key.
    """
    try:
        data_s = raw_message.decode(errors='replace')
    except ValueError:
        return -1
    lines = data_s.split("\r\n")
    for line in lines:
        if key in line:
            return line.split(":")[1]
    return ""


def check_if_tcp_is_http(data):
    first_word = data.split(" ")[0]
    if first_word in valid_http_methods:
        return True
    return False


def get_http_body_len(raw_message):
    try:
        data_s = raw_message.decode(errors='replace')
    except ValueError:
        return -1
    lines = data_s.split("\r\n\r\n")
    if len(lines) < 2:
        return -1
    return len(lines[1])
