class HttpRequestMessage:
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

    def parse(self, raw_message):
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
        return self.raw_message[self.raw_message.find("\r\n\r\n") + 1:]

    def get_host(self):
        lines = self.raw_message.split("\r\n")
        for line in lines:
            if "Host" in line:
                return line.split(":")[1]
        return ""

    def get_content_type(self):
        lines = self.raw_message.split("\r\n")
        for line in lines:
            if "Content-Type" in line:
                return line.split(":")[1]
        return ""

    def get_content_length(self):
        lines = self.raw_message.split("\r\n")
        for line in lines:
            if "Content-Length" in line:
                return int(line.split(":")[1])
        return ""

    def __str__(self):
        return f"method: {self.method}, request_target: {self.request_target}, http_version: {self.http_version}, content_type: {self.content_type}, content_length: {self.content_length}, body: {self.body}"

    def get_as_list(self):
        return [self.method, self.host, self.source_ip, self.destination_ip, self.http_version, self.content_type, self.content_length, self.body[:500] + "...[use show_details to see the entire body]" if len(self.body) > 500 else self.body]
