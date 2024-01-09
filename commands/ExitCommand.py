class ExitCommand:
    def __init__(self, shared_resources):
        """
        :param shared_resources: instance of SharedResources used to set the stop event
        """
        self.shared_resources = shared_resources

    def execute(self):
        self.shared_resources.stop_event.set()
        exit(0)
