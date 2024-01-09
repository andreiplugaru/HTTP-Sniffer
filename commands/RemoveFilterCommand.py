from exceptions.InvalidCommandArgs import InvalidCommandArgs


class RemoveFilterCommand:
    def __init__(self, shared_resources):
        self.shared_resources = shared_resources

    def execute(self, args):
        if args is None or len(args) != 1:
            raise InvalidCommandArgs("show_details", "integers less than the number of filters")
        try:
            index = int(args[0]) - 1
        except ValueError:
            raise InvalidCommandArgs("show_details", "integer")

        if index >= len(self.shared_resources.filters):
            raise InvalidCommandArgs("show_details", "integers less than the number of filters")
        print(f"Filter at position {index} removed!")
        del self.shared_resources.filters[index]
