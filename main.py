import logging

from commands.AddFilterCommand import AddFilterCommand
from commands.HelpCommand import HelpCommand
from commands.ListFiltersCommand import ListFiltersCommand
from exceptions.InvalidCommandArgs import InvalidCommandArgs
from exceptions.InvalidCommandType import InvalidCommandType

# sniffer = Sniffer()
# sniffer.sniff()

filters = list()
available_commands = {
    "help": HelpCommand(),
    "add_filter": AddFilterCommand(filters),
    # "remove filter": gui.remove_filter,
    "list_filters": ListFiltersCommand(filters),
    # "start sniffing": gui.start_sniffing,
    # "stop sniffing": gui.stop_sniffing,
    # "describe http packet": gui.describe_http_packet
}
def call_command(command, args):
    if command in ["add_filter", "remove_filter"]:
        available_commands[command].execute(args)
    else:
        available_commands[command].execute()

while True:
    command = input("Enter command: ")
    command_parts = command.split(" ")
    command_name = command_parts[0]
    args = command_parts[1:]
    if command_name in available_commands:
        try:
            call_command(command_name, args)
        except (InvalidCommandArgs, InvalidCommandType) as e:
            print(e)
        except Exception as e:
            logging.error(e)
            exit(1)
    else:
        print("Command name is not recognized. Try help for more information.")