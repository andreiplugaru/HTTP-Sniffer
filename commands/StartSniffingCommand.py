import threading

import Sniffer


class SniffingThread(threading.Thread):
    def __init__(self, shared_resources):
        threading.Thread.__init__(self)
        self.filters = shared_resources.filters
        self.event_stop = shared_resources.stop_event
        self.event_pause = shared_resources.pause_event
        self.shared_resources = shared_resources

    def run(self):
        print("Sniffing started")
        sniffer = Sniffer.Sniffer()
        self.event_stop.clear()
        self.event_pause.clear()
        sniffer.sniff(self.shared_resources)
        print("Sniffing finished")


class StartSniffingCommand:
    def __init__(self, shared_resources):
        self.shared_resources = shared_resources

    def execute(self):
        """Start the sniffing thread."""
        self.shared_resources.set_thread(SniffingThread(self.shared_resources))
        self.shared_resources.get_thread().start()
