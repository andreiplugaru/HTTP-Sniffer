class InvalidCommandType(Exception):
    def __init__(self, valid_command_types):
        super().__init__(f"The command type is invalid. Valid command types are: {str(valid_command_types)[1:-1]}.")