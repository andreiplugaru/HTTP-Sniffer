class PauseSniffingCommand:
    def __init__(self, shared_resources):
        self.event = shared_resources.pause_event

    def execute(self):
        self.event.set()