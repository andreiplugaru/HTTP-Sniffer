import ctypes


class TcpPacketHeader(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("Source_port", ctypes.c_uint16),
        ("Destination_port", ctypes.c_uint16),
        ("Sequence_number", ctypes.c_uint32),
        ("Acknowledgement_number", ctypes.c_uint32),
        ("Data_offset_and_reserved", ctypes.c_uint8),  # Combine Data_offset and Reserved into a single 8-bit field
        ("Reserved_and_Control_bits", ctypes.c_uint8, 8),  # Combine Control_bits and reserved into a single 8-bit field
        ("Window", ctypes.c_uint16),
        ("Checksum", ctypes.c_uint16),
        ("Urgent_pointer", ctypes.c_uint16),
    ]
    def get_RST(self):
        return (self.Reserved_and_Control_bits & (1 << 2))

    def get_SYN(self):
        return (self.Reserved_and_Control_bits & (1 << 1))

    def get_FIN(self):
        return (self.Reserved_and_Control_bits & 1 << 0)
    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)

    def __init__(self, data):
        pass  ## data is already present in class