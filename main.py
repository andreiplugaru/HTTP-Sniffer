import logging
from ctypes import sizeof

#
from SharedResources import SharedResources
from TcpPacketHeader import TcpPacketHeader

from commands.AddFilterCommand import AddFilterCommand
from commands.HelpCommand import HelpCommand
from commands.ListFiltersCommand import ListFiltersCommand
from commands.PauseSniffingCommand import PauseSniffingCommand
from commands.ResumeSniffingCommand import ResumeSniffingCommand
from commands.StartSniffingCommand import StartSniffingCommand
from commands.StopSniffingCommand import StopSniffingCommand
from exceptions.InvalidCommandArgs import InvalidCommandArgs
from exceptions.InvalidCommandType import InvalidCommandType

# sniffer = Sniffer()
# sniffer.sniff()
logging.basicConfig(filename='output.log', encoding='utf-8', level=logging.WARNING)

filters = list()
shared_resources = SharedResources()
available_commands = {
    "help": HelpCommand(),
    "add_filter": AddFilterCommand(shared_resources),
    # "remove filter": gui.remove_filter,
    "list_filters": ListFiltersCommand(shared_resources.filters),
    "start_sniffing": StartSniffingCommand(shared_resources),
    "stop_sniffing": StopSniffingCommand(shared_resources),
    "pause_sniffing": PauseSniffingCommand(shared_resources),
    "resume_sniffing": ResumeSniffingCommand(shared_resources),
    # "describe http packet": gui.describe_http_packet
}
def call_command(command, args):
    if command in ["add_filter", "remove_filter"]:
        available_commands[command].execute(args)
    else:
        available_commands[command].execute()

while True:
    command = input("Enter command: ")
    if command == "":
        available_commands["pause_sniffing"].execute()
        continue
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

# print(sizeof(TcpPacketHeader))
# from ctypes import sizeof
#
# from IPHeader import IPHeader
#
# # print(sizeof(IPHeader))
# from tabulate import tabulate
# from colorama import init, Fore, Style
# import time
# import os
#
# # Initialize colorama to work with Windows terminals
# init()
#
# def clear_console():
#     if os.name == 'nt':  # For Windows
#         os.system('cls')
#     else:  # For Unix-like systems
#         os.system('clear')
#
# def display_table(data, headers):
#     clear_console()
#     table = tabulate(data, headers=headers, tablefmt="grid")
#     print(table)
#
# def main():
#
#     # Sample data
#     data = [
#         ["Alice", 28, "Engineer"],
#         ["Bob", 35, "Teacher"],
#         ["Charlie", 22, "Student"],
#     ]
#
#     # Display the initial table
#     display_table(data, headers)
#     time.sleep(1)
#
#     # Simulate adding rows dynamically
#     for i in range(1, 6):
#         new_row = ["Person{}".format(i), 25 + i, "Job{}".format(i)]
#         data.append(new_row)
#
#         # Display the updated table after adding a row
#         print("\nAdding Row {}:".format(i))
#         display_table(data, headers)
#         time.sleep(1)
#
# if __name__ == "__main__":
#     main()
