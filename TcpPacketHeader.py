import ctypes


class TcpPacketHeader(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("Source_port", ctypes.c_uint16),
        ("Destination_port", ctypes.c_uint16),
        ("Sequence_number", ctypes.c_int, 32),
        ("Acknowledgement_number", ctypes.c_int, 32),
        ("Data_offset", ctypes.c_int, 4),
        ("Reserved", ctypes.c_int, 6),
        ("Control_bits", ctypes.c_int, 5),
        ("FIN", ctypes.c_int, 1),
        ("Window", ctypes.c_int, 16),
        ("Checksum", ctypes.c_int, 16),
        ("Urgent_pointer", ctypes.c_int, 16),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass  ## data is already present in class