class FireEyeError(Exception):

    """
    Generic exception class for ErrorResponse classes, defined in responses.py
    """

    def __init__(self, response):
        """Formatting of data in the ErrorResponse object for a meaningful exception

        :param response: an ErrorResponse object.
        """
        self.err_object = response.json()
        self.msg = "Expected status code {}, received status code {}\n" \
                   "Error Message: {}\n" \
                   "Headers: {}".format(self.err_object["expected"], self.err_object["status"],
                                        self.err_object["message"], self.err_object["headers"])
        Exception.__init__(self, self.msg)


class InsufficientCredentialsException(Exception):

    """
    Exception thrown when insufficient credentials are provided.
    """

    def __init__(self, *args):
        """Initialize instance of InsufficientCredentialsException class.

        :param args: list of credentials needed for proper authentication.

        """
        Exception.__init__(self, "Credentials required are: {0}".format(*args))


class UnknownHTTPMethodException(Exception):

    """
    To be raised when an HTTP method is used that is not a standard HTTP method.
    """

    def __init__(self, method):
        """Initializes an instance of the UnknownHTTPMethodException class.

        :param method: the method that is not standard
        """
        valid = ["GET", "POST", "HEAD", "DELETE", "PUT", "PATCH", "MOVE"]
        Exception.__init__(self, "Method {} is not a valid HTTP method\nAcceptable methods are".format(method, valid))


class InsufficientAuthenticationException(Exception):

    """
    To be raised when the AUTHENTICATION attribute of a class is not present
    """

    def __init__(self, message):
        """Initializes an instance of the InsufficientAuthenticationException class.

        :param message: error message to be raised
        """
        Exception.__init__(self, message)


class MissingPreparedFileException(Exception):

    """
    To be raised when submitting a file and the file has not been properly prepared
    """

    def __init__(self):
        """Initializes an instance of the MissingPreparedFileException class.

        """
        Exception.__init__(self, "Either file is not prepared or preparation failed")


class ExpectedResponseException(Exception):

    """
    To be raised when a Response object is expected but is not received.
    """

    def __init__(self, response):
        """Initializes an instance of the ExpectedResponseException class.

        """
        Exception.__init__(self, "Expected to get Response object, received {}".format(type(response)))
