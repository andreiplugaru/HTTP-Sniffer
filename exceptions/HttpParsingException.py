class HttpParsingException(Exception):
    def __init__(self,):
        super().__init__("Error while parsing HTTP packet")