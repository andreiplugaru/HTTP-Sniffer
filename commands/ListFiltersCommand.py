class ListFiltersCommand:
    def __init__(self, filters):
        self.filters = filters

    def execute(self):
        """Executes the list filters command. Prints the list of filters."""
        for i, filter in enumerate(self.filters):
            print(f"{i + 1}. {filter}")
        if len(self.filters) == 0:
            print("No filters added yet.")
