import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from pyFireEye.utilities.responses import *
from pyFireEye.utilities.wrappers import *
from pyFireEye.utilities.params_helper import *
from pyFireEye.utilities.exceptions import *
from pyFireEye.utilities.utility import *


class _CMS:



    API_BASE_ROUTE = "/wsapis/v2.0.0"
    AUTHENTICATION = None

    def __init__(self, cms_host, cms_port=None, verify=False):

        self.verify = verify
        self.cms_host = cms_host
        self.cms_port = cms_port

    def _build_url(self):

        url = self.cms_host
        if self.cms_port:
            url += ":" + str(self.cms_port)
        return url + self.API_BASE_ROUTE

    def _base_request(self, method, route, **kwargs):

        url = self._build_url() + route
        response = requests.request(method=method, url=url, verify=self.verify, **kwargs)
        return response


class Authentication(_CMS):


    TOKEN_HEADER = "X-FeApi-Token"
    BASIC_HEADER = "Authorization"
    token = ""

    def __init__(self, cms_host, cms_port=None, verify=False, token_auth=False, username="", password=""):
        _CMS.__init__(self, cms_host, cms_port=cms_port, verify=verify)
        self.username = username
        self.password = password
        self.token_auth = token_auth

    def get_auth_header(self):

        if self.token_auth:
            return self.TOKEN_HEADER, self.token
        else:
            return self.BASIC_HEADER, "Basic " + '"' + b64encode_wrap(self.username + ":" + self.password) + '"'

    def authenticate(self, username="", password="", token_auth=None):

        if isinstance(token_auth, bool):
            self.token_auth = token_auth
        if username and password:
            self.username = username
            self.password = password

        if not self.username or not self.password:
            raise InsufficientCredentialsException("username", "password")

        response = self.auth(self.username, self.password)
        if isinstance(response, ErrorResponse):
            raise FireEyeError(response)

        self.token = response.headers[self.TOKEN_HEADER]
        self.AUTHENTICATION = self

    @expected_response(expected_status_code=200, expected_format=DEFAULT)
    @template_request(method="POST", route="/auth/login", require_auth=False)
    def auth(self, username, password, **kwargs):

        return self._base_request(auth=(username, password), **kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="POST", route="/auth/logout")
    def logout(self, **kwargs):

        return self._base_request(**kwargs)


class Alerts(_CMS):

    """

    """

    def __init__(self, cms_host, cms_port=None, verify=False, authenticator=None, username="", password=""):

        _CMS.__init__(self, cms_host=cms_host, cms_port=cms_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(cms_host=cms_host, cms_port=cms_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=[200, 206], expected_format=JSON)
    @template_request(method="GET", route="/alerts",
                      request_params=[ALERT_ID, DST_IP, SRC_IP, CALLBACK_DOMAIN, DURATION, END_TIME, FILE_NAME,
                                      FILE_TYPE, INFO_LEVEL, MALWARE_NAME,MALWARE_TYPE, MD5, RECIPIENT_EMAIL,
                                      SENDER_EMAIL, START_TIME, URL],
                      request_headers=["Accept"])
    def get_alerts(self, alert_id=None, dst_ip=None, src_ip=None, callback_domain=None, duration=None, end_time=None,
                   file_name=None, file_type=None, info_level=None,
                   malware_name=None, malware_type=None, md5=None, recipient_email=None, sender_email=None,
                   start_time=None, url=None, Accept="application/json", **kwargs):

        return self._base_request(**kwargs)

