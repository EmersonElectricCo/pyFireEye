"""

"""
import requests
from pyFireEye.utilities.responses import *
from pyFireEye.utilities.wrappers import *
from pyFireEye.utilities.params_helper import *
from pyFireEye.utilities.exceptions import *
from pyFireEye.utilities.utility import *


class _FaaS:

    """

    """

    API_ROUTE = "https://api.services.fireeye.com"
    AUTHENTICATION = None

    def __init__(self, verify=False):

        self.verify = verify

    def _base_request(self, method, route, **kwargs):

        url = self.API_ROUTE + route

        # Prepare kwargs by removing fields that have no data
        kwargs = {k: v for k, v in kwargs.items() if v}

        response = requests.request(method=method, url=url, verify=self.verify, **kwargs)
        return response


class Authentication(_FaaS):

    """

    """

    AUTH_HEADER = "Authorization"
    token = ""

    def __init__(self, verify=False, token_auth=False, api_key="", api_secret=""):

        _FaaS.__init__(self, verify=verify)
        self.token_auth = token_auth
        self.api_key = api_key
        self.api_secret = api_secret

    def get_auth_header(self):

        if self.token_auth:
            return self.AUTH_HEADER, "Bearer {}".format(self.token)
        else:
            encoded = b64encode_wrap(self.api_key + ":" + self.api_secret)
            return self.AUTH_HEADER, """Basic {}""".format(encoded)

    def authenticate(self, api_key="", api_secret="", token_auth=None):

        if isinstance(token_auth, bool):
            self.token_auth = token_auth
        if api_key and api_secret:
            self.api_key = api_key
            self.api_secret = api_secret
        else:
            raise InsufficientCredentialsException("api_key", "api_secret")

        self.AUTHENTICATION = self

        response = self.auth(self.api_key, self.api_secret)
        if isinstance(response, ErrorResponse):
            raise FireEyeError(response)

        self.token = response.json()["content"]["access_token"]
        self.token_auth = True

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="POST", route="/token")
    def auth(self, api_key, api_secret, **kwargs):

        kwargs["data"] = {"grant_type": "client_credentials"}
        kwargs["headers"].update({"Content-Type": "application/x-www-form-urlencoded", "Cache-Control": "no-cache"})
        return self._base_request(**kwargs)


class Investigations(_FaaS):

    """

    """

    def __init__(self, verify=False, authenticator=None, api_key="", api_secret=""):

        _FaaS.__init__(self, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif api_key and api_secret:
            self.AUTHENTICATION = Authentication(verify=verify, api_key=api_key, api_secret=api_secret)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/investigations")
    def get_all_investigations(self, **kwargs):

        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/investigations/<investigationId>")
    def get_investigation_by_id(self, investigationId, **kwargs):
        """Get complete view of an investigation with a specific ID.

        :param investigationId: <string> The ID of the specific investigation.
        :param kwargs:
        :return: <JsonResponse> JsonResponse object containing headers, content, etc.
        """
        return self._base_request(**kwargs)
