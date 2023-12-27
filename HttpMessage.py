class HttpRequestMessage:
    def __init__(self, raw_message):
        self.raw_message = raw_message
        self.method = None
        self.request_target = None
        self.http_version = None
        self.content_type = None
        self.content_length = None
        self.body = None
    def parse(self):
        lines = self.raw_message.split("\r\n")
        self.method = lines[0].split(" ")[0]
        self.request_target = lines[0].split(" ")[1]
        self.http_version = lines[0].split(" ")[2]
        self.host = self.get_host()
        self.content_type = self.get_content_type()
        self.content_length = self.get_content_length()
        content_length_index = 0
        for i, line in enumerate(lines):
            if "Content-Length" in line:
                content_length_index = i
                break
        self.body = self.get_body()

    def get_body(self):
        lines = self.raw_message.split("\r\n\r\n")
        return lines[1]

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
        return None

    def get_content_length(self):
        lines = self.raw_message.split("\r\n")
        for line in lines:
            if "Content-Length" in line:
                return int(line.split(":")[1])
        return None

    def __str__(self):
        return f"method: {self.method}, request_target: {self.request_target}, http_version: {self.http_version}, content_type: {self.content_type}, content_length: {self.content_length}, body: {self.body}"

    def get_as_list(self):
        return [self.method, self.host, self.request_target, self.http_version, self.content_type, self.content_length, self.body]
