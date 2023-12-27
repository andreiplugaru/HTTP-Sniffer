class ResumeSniffingCommand:
    def __init__(self, shared_resources):
        self.pause_event = shared_resources.pause_event

    def execute(self):
        self.pause_event.clear()