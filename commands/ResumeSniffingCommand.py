from exceptions.InvalidCommandRunPeriod import InvalidCommandRunPeriod


class ResumeSniffingCommand:
    def __init__(self, shared_resources):
        self.pause_event = shared_resources.pause_event
        self.shared_resources = shared_resources

    def execute(self):
        if self.shared_resources.stop_event.is_set() or not self.pause_event.is_set():
            raise InvalidCommandRunPeriod("sniffing is paused")
        self.pause_event.clear()
