class HelpCommand:
    @staticmethod
    def execute():
        """Prints the list of available commands."""
        print("Available commands:")
        print("  help")
        print("  exit")
        print("add_filter <filter_name> request_method=<request_method>|destination_ip=<ip_address>|source_ip"
              "=<ip_address>")
        print("  remove_filter <filter_name>")
        print("  list filters")
        print("  start sniffing")
        print("  stop sniffing")
        print("  describe http packet")
