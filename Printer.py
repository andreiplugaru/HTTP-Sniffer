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
    table = tabulate(data, headers=headers, tablefmt="grid", maxcolwidths=[10, 20, 40, 50, 10, None, None, 50], showindex=True)
    print(table)


def show(new_row):
    new_row[6] = new_row[6].encode("ISO-8859-1").decode("ascii")
    data.append(new_row)
    display_table(data, headers)
