import ctypes


class IPHeader(ctypes.Structure):
    _pack_ = 1

    _fields_ = [
        ("Version", ctypes.c_uint8, 4),
        ("Header_length", ctypes.c_uint8, 4),
        ("Type_of_service", ctypes.c_uint8),
        ("Total_length", ctypes.c_uint16),
        ("Identification", ctypes.c_uint16),
        ("Fragment_offset", ctypes.c_uint16),
        ("Time_to_live", ctypes.c_uint8),
        ("Protocol", ctypes.c_uint8),
        ("Header_checksum", ctypes.c_uint16),
        ("Source_address", ctypes.c_uint32),
        ("Destination_address", ctypes.c_uint32)
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass  ## data is already present in class
