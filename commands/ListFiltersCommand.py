class ListFiltersCommand:
    def __init__(self, filters):
        self.filters = filters

    def execute(self):
        """Prints the list of filters. If there are no filters, it prints a special message."""
        for i, filter in enumerate(self.filters):
            print(f"{i + 1}. {filter}")
        if len(self.filters) == 0:
            print("No filters added yet.")
