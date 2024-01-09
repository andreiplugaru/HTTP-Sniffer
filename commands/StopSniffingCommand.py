from exceptions.InvalidCommandRunPeriod import InvalidCommandRunPeriod


class StopSniffingCommand:
    """
    Command to stop sniffing.
    """

    def __init__(self, shared_resources):
        """
        :param shared_resources: instance of SharedResources used to set the stop event
        """
        self.shared_resources = shared_resources

    def execute(self):
        """Stops the sniffing process by setting the stop event."""
        if self.shared_resources.stop_event.is_set():
            raise InvalidCommandRunPeriod("sniffing is started")
        self.shared_resources.stop_event.set()
