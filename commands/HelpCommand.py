class HelpCommand:
    @staticmethod
    def execute():
        """Prints the list of available commands."""
        print("Available commands:")
        print("  start_sniffing")
        print("  stop_sniffing")
        print("  help")
        print("  exit")
        print("  add_filter request_method=<request_method>|destination_ip=<ip_address>|source_ip"
              "=<ip_address>")
        print("  remove_filter <filter_index>")
        print("  list filters")
        print("  show_details <request_index>")
