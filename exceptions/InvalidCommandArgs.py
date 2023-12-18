class InvalidCommandArgs(Exception):
    def __init__(self, command_type, valid_args):
        super().__init__(f"The command arguments are invalid for command {command_type}. The valid arguments are {str(valid_args)[1:-1]}.")