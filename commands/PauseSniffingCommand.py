class PauseSniffingCommand:
    def __init__(self, shared_resources):
        """
        :param shared_resources: instance of SharedResources used to get the pause event
        """
        self.event = shared_resources.pause_event

    def execute(self):
        """Sets the pause event to pause the sniffing."""
        self.event.set()
