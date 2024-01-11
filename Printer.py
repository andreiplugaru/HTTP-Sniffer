import os
import re

from tabulate import tabulate

from utils import sanitize_string


def clear_console():
    os.system('cls')


headers = ["Method", "Host", "Source IP address", "Destination IP address", "Http version", "Content type",
           "Content length", "Body"]
data = []


def display_table(data, headers):
    clear_console()
    table = tabulate(data, headers=headers, tablefmt="grid", maxcolwidths=[20, 40, 20, 20, 20, 20, 10, 50, 50],
                     showindex=True)
    print(table)


def show(new_row):
    new_row2 = [sanitize_string(x) for x in new_row]
    data.append(new_row2)
    display_table(data, headers)
