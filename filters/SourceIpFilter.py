from filters.Filter import Filter


class SourceIpFilter(Filter):
    def __init__(self, source_ip):
        super().__init__()
        self.source_ip = source_ip

    def apply(self, request):
        return request.source_ip == self.source_ip

    def __str__(self):
        return "Filter for source ip = " + self.source_ip
