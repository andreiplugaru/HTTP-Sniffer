from exceptions.InvalidCommandType import InvalidCommandType
from filters.DestinationIpFilter import DestinationIpFilter
from filters.HttpMethodFilter import HttpMethodFilter


class AddFilterCommand:
    filter_types = {"request_method": HttpMethodFilter, "destination_ip": DestinationIpFilter,
                    "source_ip": DestinationIpFilter}

    def __init__(self, shared_resources):
        self.shared_resources = shared_resources

    def execute(self, args):
        """Executes the add filter command. Adds a filter to the list of filters."""
        args = args[0].split("=")
        if len(args) != 2:
            raise InvalidCommandType(list(AddFilterCommand.filter_types.keys()))
        filter_type = args[0]
        if filter_type not in self.filter_types:
            raise InvalidCommandType(list(AddFilterCommand.filter_types.keys()))
        self.shared_resources.filters.append(self.filter_types[filter_type](args[1]))
