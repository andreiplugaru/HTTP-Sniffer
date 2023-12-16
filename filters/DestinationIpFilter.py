from filters.Filter import Filter


class DestinationIpFilter(Filter):
    def __init__(self, destination_ip):
        super().__init__()
        self.destination_ip = destination_ip

    def apply(self, request):
        return request.destination_ip == self.destination_ip

    def __str__(self):
        return "Filter for source ip = " + self.destination_ip
