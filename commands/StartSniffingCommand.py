import threading

import Sniffer


class SniffingThread(threading.Thread):
    def __init__(self, filters, event_stop, event_pause):
        threading.Thread.__init__(self)
        self.filters = filters
        self.event_stop = event_stop
        self.event_pause = event_pause

    def run(self):
        print("Sniffing started")
        sniffer = Sniffer.Sniffer()
        self.event_stop.clear()
        self.event_pause.clear()
        sniffer.sniff(self.filters, self.event_stop, self.event_pause)
        print("Sniffing finished")


class StartSniffingCommand:
    def __init__(self, shared_resources):
        self.shared_resources = shared_resources

    def execute(self):
        """Start the sniffing thread."""
        self.shared_resources.set_thread(
            SniffingThread(self.shared_resources.get_filters(),
                           self.shared_resources.stop_event,
                           self.shared_resources.pause_event))
        self.shared_resources.get_thread().start()
