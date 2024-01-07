import threading

import Sniffer


class SniffingThread(threading.Thread):
    """
    This class is a thread that runs the sniffing process.
    """
    def __init__(self, shared_resources):
        """
        :param shared_resources: instance of SharedResources used to get the stop event and the pause event
        """
        threading.Thread.__init__(self)
        self.shared_resources = shared_resources

    def run(self):
        """Starts the sniffing process. The Stop event and Pause event are cleared."""
        print("Sniffing started")
        sniffer = Sniffer.Sniffer()
        self.shared_resources.stop_event.clear()
        self.shared_resources.pause_event.clear()
        sniffer.sniff(self.shared_resources)
        print("Sniffing finished")


class StartSniffingCommand:
    """
    This class represents the command to start the sniffing process.
    """
    def __init__(self, shared_resources):
        """
        :param shared_resources: instance of SharedResources used to set the thread
        """
        self.shared_resources = shared_resources

    def execute(self):
        """Start the sniffing thread."""
        self.shared_resources.set_thread(SniffingThread(self.shared_resources))
        self.shared_resources.get_thread().start()
