

class DestinationIpFilter:
    """
    Class for filtering by destination ip.
    """
    def __init__(self, destination_ip):
        self.destination_ip = destination_ip

    def apply(self, http_message):
        """
        :param http_message: instance of HttpRequestMessage. The message to be filtered.
        :return: true if the message's destination ip is the same as the filter's destination ip.
        """
        return http_message.destination_ip == self.destination_ip

    def __str__(self):
        return "Filter for destination ip = " + self.destination_ip
