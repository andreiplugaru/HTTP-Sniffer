import logging
from SharedResources import SharedResources
from commands.AddFilterCommand import AddFilterCommand
from commands.HelpCommand import HelpCommand
from commands.ListFiltersCommand import ListFiltersCommand
from commands.PauseSniffingCommand import PauseSniffingCommand
from commands.ResumeSniffingCommand import ResumeSniffingCommand
from commands.ShowDetailsCommand import ShowDetailsCommand
from commands.StartSniffingCommand import StartSniffingCommand
from commands.StopSniffingCommand import StopSniffingCommand
from exceptions.InvalidCommandArgs import InvalidCommandArgs
from exceptions.InvalidCommandType import InvalidCommandType
from utils import check_if_admin

check_if_admin()
shared_resources = SharedResources()
available_commands = {
    "help": HelpCommand(),
    "add_filter": AddFilterCommand(shared_resources),
    "list_filters": ListFiltersCommand(shared_resources.filters),
    "start_sniffing": StartSniffingCommand(shared_resources),
    "stop_sniffing": StopSniffingCommand(shared_resources),
    "pause_sniffing": PauseSniffingCommand(shared_resources),
    "resume_sniffing": ResumeSniffingCommand(shared_resources),
    "show_details": ShowDetailsCommand(shared_resources),
}


def call_command(command, args):
    if command in ["add_filter", "remove_filter", "show_details"]:
        available_commands[command].execute(args)
    else:
        available_commands[command].execute()


def main():
    while True:
        command = input("Enter command: ")
        if command == "":
            available_commands["pause_sniffing"].execute()
            continue
        command_parts = command.split(" ")
        command_name = command_parts[0]
        if command_name in available_commands:
            args = command_parts[1:] if len(command_parts) > 1 else None
            try:
                call_command(command_name, args)
            except (InvalidCommandArgs, InvalidCommandType) as e:
                print(e)
            except Exception as e:
                logging.error(e)
                exit(1)
        else:
            print("Command name is not recognized. Try help for more information.")


if __name__ == '__main__':
    main()
