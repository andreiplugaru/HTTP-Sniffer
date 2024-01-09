class HttpRequestMessage:
    """
    Class for representing a http request message. It contains all the information about the message.
    """
    def __init__(self):
        self.source_ip = None
        self.destination_ip = None
        self.method = None
        self.request_target = None
        self.http_version = None
        self.content_type = ""
        self.content_length = ""
        self.body = None
        self.host = None
        self.raw_message = None

    def parse(self, raw_message):
        """
        Method for transforming a raw http request message into an instance of HttpRequestMessage.
        :param raw_message: a raw http request message.
        """
        self.raw_message = raw_message
        lines = self.raw_message.split("\r\n")
        self.method = lines[0].split(" ")[0]
        self.request_target = lines[0].split(" ")[1]
        self.http_version = lines[0].split(" ")[2]
        self.host = self.get_host()
        self.content_type = self.get_content_type()
        self.content_length = self.get_content_length()
        self.body = self.get_body()

    def get_body(self):
        """
        The body of a http request message is the part after the first empty line.
        :return: the body of the http request message.
        """
        return self.raw_message[self.raw_message.find("\r\n\r\n") + 4:]

    def get_value_for_key(self, key):
        """
        In the header of a http request message, the value for a key is the part after the key and the colon.
        :param key: the key for which we want to find the value.
        :return: the value for the given key.
        """
        lines = self.raw_message.split("\r\n")
        for line in lines:
            if key in line:
                return line.split(":")[1]
        return ""

    def get_host(self):
        return self.get_value_for_key("Host")

    def get_content_type(self):
        return self.get_value_for_key("Content-Type")

    def get_content_length(self):
        return self.get_value_for_key("Content-Length")

    def __str__(self):
        return (f"method: {self.method}, request_target: {self.request_target}, "
                f"http_version: {self.http_version}, content_type: {self.content_type}, "
                f"content_length: {self.content_length}, body: {self.body}")

    def get_as_list(self):
        """
        :return: a list containing information about the http request message. This list is further used for printing.
        """
        return [self.method, self.host, self.source_ip, self.destination_ip, self.http_version, self.content_type,
                self.content_length,
                self.body[:500] + "...[use show_details to see the entire body]" if len(self.body) > 500 else self.body]
