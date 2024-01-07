import utils
from exceptions.InvalidCommandArgs import InvalidCommandArgs


class HttpMethodFilter:
    """
    Class for filtering by http method.
    """

    def __init__(self, http_method):
        """
        :param http_method: the http method to filter by. This must be a valid http method, otherwise an exception of
         type :class:`InvalidCommandArgs` is raised.
        """
        if http_method.upper() not in utils.valid_http_methods:
            raise InvalidCommandArgs("request_method", str(utils.valid_http_methods)[1:-1])
        self.http_method = http_method

    def apply(self, http_message):
        """
        :param http_message: instance of HttpRequestMessage. The message to be filtered.
        :return: true if the message's http method is the same as the filter's http method.
        """
        return http_message.method.upper() == self.http_method.upper()

    def __str__(self):
        return "Filter for http method = " + self.http_method
