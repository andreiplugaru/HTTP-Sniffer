import ctypes


class IPHeader(ctypes.BigEndianStructure):

    _fields_ = [
        ("Version", ctypes.c_int, 4),
        ("Header_length", ctypes.c_int, 4),
        ("Type_of_service", ctypes.c_int, 8),
        ("Total_length", ctypes.c_int, 16),
        ("Identification", ctypes.c_int, 16),
        ("Flags", ctypes.c_int, 3),
        ("Fragment_offset", ctypes.c_int, 13),
        ("Time_to_live", ctypes.c_int, 8),
        ("Protocol", ctypes.c_int, 8),
        ("Header_checksum", ctypes.c_int, 16),
        ("Source_address", ctypes.c_int, 32),
        ("Destination_address", ctypes.c_int, 32)
    ]


    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass  ## data is already present in class
