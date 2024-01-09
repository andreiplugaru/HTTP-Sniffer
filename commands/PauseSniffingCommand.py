from exceptions.InvalidCommandRunPeriod import InvalidCommandRunPeriod


class PauseSniffingCommand:
    def __init__(self, shared_resources):
        """
        :param shared_resources: instance of SharedResources used to get the pause event
        """
        self.event = shared_resources.pause_event

    def execute(self):
        """Sets the pause event to pause the sniffing."""
        if self.event is None or self.event.is_set():
            raise InvalidCommandRunPeriod("sniffing is started")
        self.event.set()
