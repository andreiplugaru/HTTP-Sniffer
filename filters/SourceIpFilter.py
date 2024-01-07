class SourceIpFilter:
    """
    Class for filtering by source ip.
    """
    def __init__(self, source_ip):
        self.source_ip = source_ip

    def apply(self, http_message):
        """
        :param http_message: instance of HttpRequestMessage. The message to be filtered.
        :return: true if the message's source ip is the same as the filter's source ip.
        """
        return http_message.source_ip == self.source_ip

    def __str__(self):
        return "Filter for source ip = " + self.source_ip
