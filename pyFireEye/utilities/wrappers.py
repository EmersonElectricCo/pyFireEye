import re
import json
import inspect
from functools import wraps
from requests import Response
from pyFireEye.utilities.responses import make_response, StreamResponse, ErrorResponse
from pyFireEye.utilities.params_helper import *
from pyFireEye.utilities.exceptions import *

try:
    getargspec = inspect.getfullargspec
except Exception:
    getargspec = inspect.getargspec

try:
    utype = unicode
    byte_type = str
except:
    byte_type = bytes

tag_pattern = re.compile("<\w[a-zA-Z0-9_]{0,31}>")


def _clean_params(request_params, **kwargs):
    """
    This function is used by the template request to make sure that params which do not
    follow a usable argument style are properly converted to the correct params
    before being passed into the params field for requests
    :param request_params: list of request params
    :param kwargs:
    :return:
    """
    replaced_keys = []

    for k, v in kwargs.items():
        if k in param_arg_map and param_arg_map.get(k) in request_params:
            kwargs[param_arg_map.get(k)] = v
            replaced_keys.append(k)

    for k in replaced_keys:
        del kwargs[k]


def _route_update(route, **kwargs):
    """
    Used by the template_request decorator to allow the route to be
    defined with replaceable parts, ex: /auth/<user>

    Pattern for tag detection: "<[a-zA-Z0-9\-_]{1,30}>"

    During function definition you must include the tagged value as an argument to
    the function. ex:
    @template_request(method="GET", route="/auth/<user>)
    def func(user, **kwargs):
        ...
    :param route: the route which will be checked for replacements
    :param kwargs: the arguments passed in
    :return: updated route
    """
    replace = re.findall(tag_pattern, route)
    for tag in replace:
        key = str(tag.split("<")[1].split(">")[0])
        if key not in kwargs:
            raise KeyError("Expected argument, " + key + ", but did not find it")
        route = re.sub(tag, str(kwargs[key]), route)

    return route


def _fill_default_args(func):
    """

    :param func:
    :return:
    """
    arg_dict = {}

    arg_data = getargspec(func)
    positional_args = arg_data[0]
    default_values = arg_data[3]
    if not default_values or not positional_args:
        return arg_dict

    start = len(positional_args) - len(default_values)

    for index in range(start, len(positional_args)):
        arg_dict[positional_args[index]] = default_values[index - start]

    return arg_dict


def _check_args(args, **kwargs):
    """
    Used internally by expect_response to check if an argument to
    the request exists and contains the correct data
    :param key: The argument to be checked, ex: params
    :param required: The required keys in the required argument's dictionary
    :param kwargs: The arguments passed in to be checked
    :return:
    """

    newdict = {}
    if not args:
        return newdict
    if not isinstance(args, list):
        raise TypeError("Expected required to be list")
    for parameter in args:
        if kwargs.get(parameter) is not None:
            newdict[parameter] = kwargs.get(parameter)
    return newdict


def template_request(method, route, request_params=None, json_body=None, request_headers=None, require_file=False,
                     require_auth=True):
    """
    allows simple generic building of requests methods for bindings, and validation of input parameters.
    It is assumed that the base url (http://example-site.com) will be constructed within the function or elsewhere.
    simple as this:
    @template_request(method="post", route="/test/route", json_body=["user", "data"], request_params=["filter"])
    def func(url, user, data, filter=None, **kwargs):
        url += route
        return requests.request(url=url, **kwargs)

    when func is called as such -
    response = func(url="url", user="username", data="im a message", filter="filter me")

    the request will be sent as
    requests.request(method=method, url=url, json={"user": "username", "data": "im a message"},
                     params={"filter": "filter me"})

    :param method: HTTP METHOD
    :param route: route to be appended to base route
    :param request_params: ["list", "of" "params"] - should match up to arguments for wrapped functions
        - will be mapped into params={} for request
    :param json_body: ["list", "of", "params"] - should match up to arguments for wrapped functions -
        - will be mapped into json={} for request
    :param request_headers: ["list", "of", "params"] - should match up to arguments for wrapped functions -
        - will be mapped into headers={} for request
    :param require_file: True if a file is required, False if not
    :param require_auth: The function's class's authenticator will be checked and the appropriate auth header details
        added to the headers. if the authenticator is not ready, an error will be thrown
    :return: function response
    """

    def decorate(func):
        @wraps(func)
        def wrap(self, *args, **kwargs):

            arg_data = getargspec(func)
            arg_vars = list(arg_data[0])
            if "self" in arg_vars:
                arg_vars.remove("self")
            for item in args:
                kwargs[arg_vars[args.index(item)]] = item

            defaults = _fill_default_args(func)

            for k, v in defaults.items():
                if k not in kwargs:
                    kwargs[k] = v

            methods = ["GET", "POST", "HEAD", "DELETE", "PUT", "PATCH", "MOVE"]
            if method.upper() not in methods:
                raise UnknownHTTPMethodException(method=method.upper())
            kwargs["route"] = _route_update(route=route, **kwargs)
            kwargs["method"] = method
            _clean_params(request_params, **kwargs)
            kwargs["params"] = _check_args(request_params, **kwargs)
            kwargs["json"] = _check_args(json_body, **kwargs)
            kwargs["headers"] = _check_args(request_headers, **kwargs)

            if require_auth:
                if self.AUTHENTICATION:
                    header_key, header_value = self.AUTHENTICATION.get_auth_header()
                    kwargs["headers"][header_key] = header_value
                else:
                    raise InsufficientAuthenticationException("No authentication attribute present in this class")

            if require_file:
                if kwargs['file_path'] is not None:
                    self.FILE = open(kwargs['file_path'], 'rb')
                    self.FILE_PREPARED = True
                elif kwargs['file_handle'] is not None:
                    self.FILE = kwargs['file_buffer']
                    self.FILE_PREPARED = True
                if self.FILE and self.FILE_PREPARED:
                    kwargs["files"] = {"file": self.FILE}
                    kwargs["json"] = {}
                    kwargs["data"] = {"options": json.dumps(_check_args(json_body, **kwargs))}
                    self.FILE = None
                    self.FILE_PREPARED = False
                else:
                    raise MissingPreparedFileException()
            return func(self, **kwargs)

        return wrap

    return decorate


def expected_response(expected_status_code=None, expected_format=None):
    """
    :return: decorated function
    """

    if not isinstance(expected_status_code, list):
        expected_status = [expected_status_code]
    else:
        expected_status = expected_status_code

    def decorate(func):
        @wraps(func)
        def wrap(*args, **kwargs):
            response = func(*args, **kwargs)
            if not isinstance(response, Response):
                raise ExpectedResponseException(response)

            return make_response(response, expected_format, expected_status)

        return wrap

    return decorate


def expect_stream_response(expected_status=None):
    """
    Allows the response object to be validated for status code and data returned.
    The decorated function is expected to return the response object from a requests.request() call
    and nothing more.

    after decoration, the function will return a GrowlerResponse Object
    GrowlerResponse
        response=<dictionary of json data from the response>,
        status=<status code>


    :param expected_status: Expected successful status code
    :return: decorated function
    """
    if not isinstance(expected_status, list):
        if expected_status:
            expected_status = [expected_status]

    def decorate(func):
        @wraps(func)
        def wrap(*args, **kwargs):
            response, output_file = func(*args, **kwargs)
            assert isinstance(response, Response), "Response must be type " + str(Response)
            status = response.status_code
            stream_response_data = {
                "data_length": 0,
                "data": None,
                "filename": None
            }

            if status not in expected_status:
                return make_response(response, expected_format=None, expected_status=expected_status)

            if output_file:
                try:
                    output = open(output_file, "wb")
                except:
                    return ErrorResponse("unable to open the requested output file: " + output_file,
                                         response.status_code, dict(response.headers), expected_status)

            else:
                output = byte_type()

            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    stream_response_data["data_length"] += len(chunk)
                    if output_file:
                        output.write(chunk)
                    else:
                        output += chunk
            if output_file:
                output.close()

            if output_file:
                stream_response_data["filename"] = output_file
            else:
                stream_response_data["data"] = output

            return StreamResponse(status=response.status_code, content=stream_response_data,
                                  headers=dict(response.headers))

        return wrap

    return decorate
