from multiprocessing import Event


class SharedResources:
    def __init__(self):
        self.sniffer_thread = None
        self.filters = list()
        self.stop_event = Event()
        self.pause_event = Event()
        self.http_request_messages = list()

    def set_thread(self, sniffer_thread):
        self.sniffer_thread = sniffer_thread

    def get_thread(self):
        return self.sniffer_thread
