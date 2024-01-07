from exceptions.InvalidCommandArgs import InvalidCommandArgs


class ShowDetailsCommand:
    """
    This class represents the command to show details of a request.
    """
    def __init__(self, shared_resources):
        """
        :param shared_resources: instance of SharedResources used to get the list of requests
        """
        self.shared_resources = shared_resources

    def execute(self, args):
        """
        Prints the details of the request with the given index.
        :param args: the index of the request
        """
        if args is None or len(args) != 1:
            raise InvalidCommandArgs("show_details", "integers less than the number of requests")
        try:
            index = int(args[0])
        except ValueError:
            raise InvalidCommandArgs("show_details", "integer")
        if index >= len(self.shared_resources.http_request_messages):
            raise InvalidCommandArgs("show_details", "integers less than the number of requests")
        request = self.shared_resources.http_request_messages[index]
        print(f"Request {index} details:")
        print(request)
