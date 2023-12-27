from multiprocessing import Event


class SharedResources:
    def __init__(self):
        self.sniffer_thread = None
        self.filters = list()
        self.stop_event = Event()
        self.pause_event = Event()

    def set_thread(self, sniffer_thread):
        self.sniffer_thread = sniffer_thread

    def get_thread(self):
        return self.sniffer_thread

    def set_filters(self, filters):
        self.filters = filters

    def get_filters(self):
        return self.filters

    def set_event(self, event):
        self.event = event
