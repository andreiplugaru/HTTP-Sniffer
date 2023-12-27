import os

from tabulate import tabulate


def clear_console():
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Unix-like systems
        os.system('clear')


headers = ["Method", "Host", "Request target", "Http version", "Content type", "Content length", "Body"]
data = []


def display_table(data, headers):
    clear_console()
    table = tabulate(data, headers=headers, tablefmt="grid", maxcolwidths=[20,40, 50, 10, None, None, 20])
    print(table)


def show(new_row):
    data.append(new_row)
    display_table(data, headers)
