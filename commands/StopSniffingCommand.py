class StopSniffingCommand:
    def __init__(self, shared_resources):
        self.shared_resources = shared_resources

    def execute(self):
        self.shared_resources.stop_event.set()