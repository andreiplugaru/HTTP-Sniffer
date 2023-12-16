from filters.Filter import Filter

class HttpMethodFilter(Filter):
    def __init__(self, http_method):
        super().__init__()
        self.http_method = http_method

    def apply(self, request):
        return request.method == self.http_method

    def __str__(self):
        return "Filter for http method = " + self.http_method
