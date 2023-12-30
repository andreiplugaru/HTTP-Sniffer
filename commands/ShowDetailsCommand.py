from exceptions.InvalidCommandArgs import InvalidCommandArgs


class ShowDetailsCommand:
    def __init__(self, shared_resources):
        self.shared_resources = shared_resources

    def execute(self, args):
        """Executes the command to show details of a request."""
        try:
            index = int(args[0])
        except ValueError:
            raise InvalidCommandArgs("show_details", "integer")
        if index >= len(self.shared_resources.http_request_messages):
            raise InvalidCommandArgs("show_details", "integers less than the number of requests")
        request = self.shared_resources.http_request_messages[index]
        print(f"Request {index} details:")
        print(request)
