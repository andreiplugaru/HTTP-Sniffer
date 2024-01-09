class InvalidCommandRunPeriod(Exception):
    def __init__(self, valid_command_run_period):
        super().__init__(f"This command cannot be run now. It can only be run when {valid_command_run_period}.")