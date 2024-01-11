import ctypes
import logging
import re
import socket
import struct
import sys

valid_http_methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}


def get_ip_as_string(ip):
    """
    :param ip: ip address in network byte order
    :return: ip address as string
    """
    return socket.inet_ntoa(struct.pack("I", ip))


def check_if_admin():
    """
    Checks if the script is run as an administrator. As the script needs to be run as an administrator, if it is not, it exits.
    """
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() == 1
    if not is_admin:
        logging.error("You need to run this script as an administrator")
        exit(1)


def setup_logging():
    """
    Sets up the logging for the script. It creates a logger and adds two handlers to it: one for warnings and one for
    errors. The warning handler writes the warnings to a file, while the error handler writes the errors to the
    console. :return:
    """
    logger = logging.getLogger('my_logger')

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
        data_s = raw_message.decode("ISO-8859-1", errors='replace')
    except ValueError:
        return -1
    lines = data_s.split("\r\n")
    for line in lines:
        if key in line:
            return line.split(":")[1]
    return ""


def check_if_tcp_is_request(data):
    """
    Checks if the tcp packet is a http request message. It checks if the first word of the message is a valid http
    method.
    :param data: the raw data of a packet
    :return: true if the tcp packet is a http request message, false otherwise.
    """
    first_word = data.split(" ")[0]
    if first_word in valid_http_methods:
        return True
    return False


def get_http_body_len(raw_message):
    """
    :param raw_message: the raw message supposed to be http request message.
    :return: the length of the body of the http request message.
    """
    try:
        data_s = raw_message.decode("ISO-8859-1", errors='replace')
    except ValueError:
        return -1
    if data_s.find("\r\n\r\n") == -1:
        return -1
    return len(data_s[data_s.find("\r\n\r\n"):])


def decode_utf8_char_by_char(input_bytes):
    return input_bytes.decode('utf-8', errors='replace')


def sanitize_string(input_string):
    string_clean = re.sub(r"[^\x00-\x7F]+", "?", input_string)  # Remove non-ASCII characters
    string_clean = ''.join([c if c.isprintable() else '' for c in string_clean])

    return string_clean
