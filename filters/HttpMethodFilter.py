from exceptions.InvalidCommandArgs import InvalidCommandArgs
from filters.Filter import Filter

class HttpMethodFilter(Filter):
    valid_http_methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
    def __init__(self, http_method):
        super().__init__()
        if http_method.upper() not in HttpMethodFilter.valid_http_methods:
            raise InvalidCommandArgs("request_method", str(HttpMethodFilter.valid_http_methods)[1:-1])
        self.http_method = http_method

    def apply(self, request):
        return request.method.upper() == self.http_method.upper()

    def __str__(self):
        return "Filter for http method = " + self.http_method
