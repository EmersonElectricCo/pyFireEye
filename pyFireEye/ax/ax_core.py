"""

"""
import requests
from pyFireEye.utilities.responses import *
from pyFireEye.utilities.wrappers import *
from pyFireEye.utilities.params_helper import *
from pyFireEye.utilities.exceptions import *
from pyFireEye.utilities.utility import *


class _AX:
    """

    """

    API_BASE_ROUTE_LATEST = "/wsapis/v2.0.0"
    API_BASE_ROUTE_OLD = "/wsapis/v1.2.0"
    AUTHENTICATION = None
    OLD_ROUTES = ["/reports/report", "/artifacts/malwareobject"]

    def __init__(self, ax_host, ax_port=None, verify=False):
        """

        :param ax_host:
        :param ax_port:
        :param verify:
        """
        self.verify = verify
        self.ax_host = ax_host
        self.ax_port = ax_port

    def _build_url(self, latest=True):
        url = self.ax_host
        if self.ax_port:
            url += ":" + str(self.ax_port)
        return url + self.API_BASE_ROUTE_LATEST if latest else url + self.API_BASE_ROUTE_OLD

    def _base_request(self, method, route, **kwargs):
        url = self._build_url() + route if not any(sub in route for sub in self.OLD_ROUTES) \
            else self._build_url(latest=False) + route
        response = requests.request(method=method, url=url, verify=self.verify, **kwargs)
        return response

    def _stream_request(self, method, route, output_file=None, **kwargs):
        url = self._build_url() + route if not any(sub in route for sub in self.OLD_ROUTES) \
            else self._build_url(latest=False) + route
        response = requests.request(method=method, url=url, verify=self.verify, stream=True,
                                    **kwargs), output_file
        return response


class Authentication(_AX):
    TOKEN_HEADER = "X-FeApi-Token"
    BASIC_HEADER = "Authorization"
    token = ""

    def __init__(self, ax_host, ax_port=None, verify=False, token_auth=False, username="", password=""):
        _AX.__init__(self, ax_host, ax_port=ax_port, verify=verify)
        self.username = username
        self.password = password
        self.token_auth = token_auth

    def get_auth_header(self):
        """

        :return:
        """
        if self.token_auth:
            return self.TOKEN_HEADER, self.token
        else:
            return self.BASIC_HEADER, "Basic " + '"' + b64encode_wrap(self.username + ":" + self.password) + '"'

    def authenticate(self, username="", password="", token_auth=None):
        """
        perform authentication request with user and password. the relevant details are stored for reuse in
        subsequent requests
        :param username:
        :param password:
        :param token_auth: if true, future requests will use the returned token, otherwise creds will just be tested
        :return:
        """
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
        self.token_auth = True
        self.AUTHENTICATION = self

    @expected_response(expected_status_code=200, expected_format=DEFAULT)
    @template_request(method="POST", route="/auth/login", require_auth=False)
    def auth(self, username, password, **kwargs):
        """
        actual api authentication function
        :param username:
        :param password:
        :param kwargs:
        :return:
        """
        return self._base_request(auth=(username, password), **kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="POST", route="/auth/logout")
    def logout(self, **kwargs):
        """

        :param kwargs:
        :return:
        """
        return self._base_request(**kwargs)


class Alerts(_AX):
    """

    """

    def __init__(self, ax_host, ax_port=None, verify=False, authenticator=None, username="", password=""):
        """

        :param ax_host: <string> the hostname of the AX appliance.
        :param ax_port: <int> the port the AX appliance is listening on.
        :param verify: <boolean> True if SSL verification is to be enforced, False if not.
        :param authenticator: <Authentication> an Authentication object representing the authentication to the AX API.
        :param username: <string> the username to login to the AX API.
        :param password: <string> the password to login to the AX API.
        """
        _AX.__init__(self, ax_host=ax_host, ax_port=ax_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, username=username,
                                                 password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/alerts",
                      request_params=[ALERT_ID, DURATION, END_TIME, FILE_NAME, FILE_TYPE, INFO_LEVEL, MALWARE_NAME,
                                      MALWARE_TYPE, MD5, RECIPIENT_EMAIL, SENDER_EMAIL, START_TIME, URL],
                      )
    def get_alerts(self, alert_id=None, duration=None, end_time=None, file_name=None, file_type=None, info_level=None,
                   malware_name=None, malware_type=None, md5=None, recipient_email=None, sender_email=None,
                   start_time=None, url=None, **kwargs):

        kwargs["headers"]["Accept"] = "application/json"

        return self._base_request(**kwargs)


class Reports(_AX):
    """
    Class for handling requests to the /reports endpoint of the AX API.
    """

    def __init__(self, ax_host, ax_port=None, verify=False, authenticator=None, username="", password=""):
        """Initialize and authenticate an instance of the Reports class.

        :param ax_host: <string> the hostname of the AX appliance.
        :param ax_port: <int> the port the AX appliance is listening on.
        :param verify: <boolean> True if SSL verification is to be enforced, False if not.
        :param authenticator: <Authentication> an Authentication object representing the authentication to the AX API.
        :param username: <string> the username to login to the AX API.
        :param password: <string> the password to login to the AX API.
        """
        _AX.__init__(self, ax_host=ax_host, ax_port=ax_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, username=username,
                                                 password=password)

    @expect_stream_response(expected_status=200)
    @template_request(method="GET", route="/reports/report",
                      request_params=["report_type", "infection_id", "infection_type", "id", "type"])
    def get_report_by_id(self, report_type=None, infection_id=None, infection_type=None, id=None, type=None,
                         output_file=None, **kwargs):
        """Retrieve reports on selected alerts.

        :param report_type: <string> the type of report to be retrieved.
        :param infection_id: <string> used to specify a unique alert to describe in the report.
        :param infection_type: <string> used to specify a unique alert to describe in the report.
        :param id: <string> an alternative to the combination of infection_id and infection_type to specify the alert to
                            generate a report for.
        :param type: <string> the output report type e.g. pdf
        :return: <JsonResponse> JSON response data.
        """
        kwargs["headers"]["Accept"] = "application/json"

        return self._stream_request(output_file=output_file, **kwargs)


class Config(_AX):
    """
    Class to handle requests to the /config endpoint of the AX API.
    """

    def __init__(self, ax_host, ax_port=None, verify=False, authenticator=None, username="", password=""):
        """Initialize and authenticate an instance of the Config class.

        :param ax_host: <string> the hostname of the AX appliance.
        :param ax_port: <int> the port the AX appliance is listening on.
        :param verify: <boolean> True if SSL verification is to be enforced, False if not.
        :param authenticator: <Authentication> an Authentication object representing the authentication to the AX API.
        :param username: <string> the username to login to the AX API.
        :param password: <string> the password to login to the AX API.
        """
        _AX.__init__(self, ax_host=ax_host, ax_port=ax_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, username=username,
                                                 password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/config")
    def get_configuration_information(self, **kwargs):
        """Return a list of guest image profiles and applications that are available on the AX Series appliance that
        you use to run the Web Services API.

        :param kwargs:
        :return: <JsonResponse> JSON response data.
        """
        kwargs["headers"]["Accept"] = "application/json"

        return self._base_request(**kwargs)


class Submission(_AX):
    """

    """

    FILE = None
    FILE_PREPARED = False

    def __init__(self, ax_host, ax_port=None, verify=False, authenticator=None, username="", password=""):

        _AX.__init__(self, ax_host=ax_host, ax_port=ax_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, username=username,
                                                 password=password)

    def prepare_file(self, file_path):

        self.FILE = open(file_path, "rb")
        self.FILE_PREPARED = True

    @expected_response(expected_status_code=[200, 201], expected_format=JSON)
    @template_request(method="GET", route="/submissions/status/<submission_key>")
    def get_submission_status(self, submission_key, **kwargs):

        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/submissions/results/<submission_key>",
                      request_params=[INFO_LEVEL], )
    def get_submission_results(self, submission_key, info_level, **kwargs):

        kwargs["headers"]["Accept"] = "application/json"

        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="POST", route="/submissions/file",
                      json_body=[APPLICATION, TIMEOUT, PRIORITY, PROFILES, ANALYSISTYPE, FORCE, PREFETCH],
                      require_file=True)
    def submit_file_for_analysis(self, application, timeout, priority, profiles, analysistype, force, prefetch,
                                 file_path=None, file_handle=None,
                                 **kwargs):
        """Submit a File for analysis to an AX appliance.

        :param application: <int> Specifies the ID of the application to be used for the analysis. Setting the
                                  application value to 0 allows the AX Series appliance to choose the application for
                                  you.
        :param timeout: <int> Sets the analysis timeout (in seconds).
        :param priority: <int> Sets the analysis priority: 0 — Normal: adds analysis to the bottom of queue.
                               1 — Urgent: places the analysis at the top of the queue.
        :param profiles: <string> Selects the AX Series profile to use for analysis.
        :param force: <boolean> Specifies whether to perform an analysis on the file even if the file exactly matches an
                                analysis that has already been performed. In most cases, it is not necessary to
                                reanalyze the file. False — Do not analyze duplicate file. True — Force analysis
        :param analysistype: <int> Specifies the analysis mode. 1 — Live: analyze suspected files live within the AX
                                   Series Multi-Vector Virtual Execution (MVX) analysis engine. 2 — Sandbox: analyze
                                   suspected files in a closed, protected environment.
        :param prefetch: <int> Specifies whether to determine the file target based on an internal determination rather
                               than browsing to the target location. 0 — No 1 — Yes
        :param file_path: <str> Specifies the path to the file to submit
        :param file_handle: <file> Specifies an open file object (rb mode) the file to submit. This is ignored if file_path is given
        :param kwargs:
        :return: <JsonResponse> JSON response data.
        """

        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="POST", route="/submissions/url",
                      json_body=[APPLICATION, TIMEOUT, PRIORITY, PROFILES, FORCE, ANALYSISTYPE, PREFETCH, URLS])
    def submit_url_for_analysis(self, application, timeout, priority, profiles, force, analysistype, prefetch, urls,
                                **kwargs):
        """Submit a URL for analysis to an AX appliance.

        :param application: <int> Specifies the ID of the application to be used for the analysis. Setting the
                                  application value to 0 allows the AX Series appliance to choose the application for
                                  you.
        :param timeout: <int> Sets the analysis timeout (in seconds).
        :param priority: <int> Sets the analysis priority: 0 — Normal: adds analysis to the bottom of queue.
                               1 — Urgent: places the analysis at the top of the queue.
        :param profiles: <list> Selects the AX Series profile to use for analysis.
        :param force: <boolean> Specifies whether to perform an analysis on the URL even if the URL exactly matches an
                                analysis that has already been performed. In most cases, it is not necessary to
                                reanalyze the URLs. False — Do not analyze duplicate URLs. True — Force analysis
        :param analysistype: <int> Specifies the analysis mode. 1 — Live: analyze suspected URLs live within the AX
                                   Series Multi-Vector Virtual Execution (MVX) analysis engine. 2 — Sandbox: analyze
                                   suspected URLs in a closed, protected environment.
        :param prefetch: <int> Specifies whether to determine the file target based on an internal determination rather
                               than browsing to the target location. 0 — No 1 — Yes
        :param urls: <list> Specifies the URLs to submit for analysis. Separate the URLs with a comma.
        :param kwargs:
        :return: <JsonResponse> JSON response data.
        """
        return self._base_request(**kwargs)


class Artifacts(_AX):
    """
    Class for handling submissions to the /artifacts endpoint of the AX API.
    """

    def __init__(self, ax_host, ax_port=None, verify=False, authenticator=None, username="", password=""):
        """Initialize and authenticate an instance of the Artifacts class.

        :param ax_host: <string> the hostname of the AX appliance.
        :param ax_port: <int> the port the AX appliance is listening on.
        :param verify: <boolean> True if SSL verification is to be enforced, False if not.
        :param authenticator: <Authentication> an Authentication object representing the authentication to the AX API.
        :param username: <string> the username to login to the AX API.
        :param password: <string> the password to login to the AX API.
        """
        _AX.__init__(self, ax_host=ax_host, ax_port=ax_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, username=username,
                                                 password=password)

    @expect_stream_response(expected_status=200)
    @template_request(method="GET", route="/artifacts/<alert_type>/<alert_id>")
    def list_artifacts_data_by_id(self, alert_type, alert_id, output_file=None, **kwargs):
        """Download malware artifacts data for the specified alert ID as a zip file.

        :param alert_type: <string> type of alert, for example, malwareobject.
        :param alert_id: <string, int> the ID of the alert.
        :param output_file: <string> the filename to write the stream to.
        :param kwargs:
        :return: <StreamResponse> StreamResponse object containing data about the streamed response.
        """
        return self._stream_request(output_file=output_file, **kwargs)

    @expect_stream_response(expected_status=200)
    @template_request(method="GET", route="/artifacts/<uuid>")
    def list_artifacts_by_uuid(self, uuid, output_file=None, **kwargs):
        """Download malware artifacts data for the specified UUID as a zip file.

        :param uuid: <string> universally unique ID of the alert.
        :param output_file: <string> the filename to write the stream to.
        :param kwargs:
        :return: <StreamResponse> StreamResponse object containing data about the streamed response.
        """
        return self._stream_request(output_file=output_file, **kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/artifacts/<alert_type>/<alert_id>/meta", )
    def list_artifacts_metadata_by_id(self, alert_type, alert_id, **kwargs):
        """Download malware artifacts metadata for the specified alert ID as a zip file.

        :param alert_type: <string> type of alert, for example, malwareobject.
        :param alert_id: <string, int> the ID of the alert.
        :param kwargs:
        :return: <JsonResponse> JSON response data.
        """
        kwargs["headers"]["Accept"] = "application/json"

        return self._base_request(**kwargs)

    @expect_stream_response(expected_status=200)  # TODO regualr response?
    @template_request(method="GET", route="/artifacts/<uuid>/meta")
    def list_artifacts_metadata_by_uuid(self, uuid, output_file=None, **kwargs):
        """Download malware artifacts metadata for the specified UUID as a zip file.

        :param uuid: <string> universally unique ID of the alert.
        :param output_file: <string> the filename to write the stream to.
        :param kwargs:
        :return: <StreamResponse> StreamResponse object containing data about the streamed response.
        """
        return self._stream_request(output_file=output_file, **kwargs)


class ATI(_AX):
    """
    Class to handle requests to the /ati endpoint of the AX API.
    """

    def __init__(self, ax_host, ax_port=None, verify=False, authenticator=None, username="", password=""):
        """Initialize and authenticate an instance of the ATI class.

        :param ax_host: <string> the hostname of the AX appliance.
        :param ax_port: <int> the port the AX appliance is listening on.
        :param verify: <boolean> True if SSL verification is to be enforced, False if not.
        :param authenticator: <Authentication> an Authentication object representing the authentication to the AX API.
        :param username: <string> the username to login to the AX API.
        :param password: <string> the password to login to the AX API.
        """
        _AX.__init__(self, ax_host=ax_host, ax_port=ax_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, username=username,
                                                 password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/ati/<alert_type>/start_time=<from_date>", )
    def get_recently_updated_alerts(self, alert_type, from_date,
                                    **kwargs):
        """Retrieve the IDs of alerts that have been updated with ATI information since a given time.

        :param alert_type: <string> the type of the alert to query against.
        :param from_date: <string> in datetime format (yyyy-MM-ddTHH:mm:ss.SSSXXX or yyyy-MM-ddTHH:mm:ssXXX), the
                                   earliest time to search from.
        :param kwargs:
        :return: <JsonResponse> JSON response data.
        """

        kwargs["headers"]["Accept"] = "application/json"

        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/ati/<alert_type>/<alert_id>/info")
    def get_ati_details(self, alert_type, alert_id, **kwargs):
        """Retrieve ATI details for a specified results.

        :param alert_type: <string> the type of the alert to query against.
        :param alert_id: <string> Specify a unique alert using the internal database ID of the alert record.
        :param kwargs:
        :return: <JsonResponse> JSON response data.
        """
        return self._base_request(**kwargs)


class CustomIOC(_AX):
    """
    Class to handle requests to the /customioc endpoint of the AX API.
    """

    FILE = None
    FILE_PREPARED = False

    def __init__(self, ax_host, ax_port=None, verify=False, authenticator=None, username="", password=""):
        """Initialize and authenticate an instance of the CustomIOC class.

        :param ax_host: <string> the hostname of the AX appliance.
        :param ax_port: <int> the port the AX appliance is listening on.
        :param verify: <boolean> True if SSL verification is to be enforced, False if not.
        :param authenticator: <Authentication> an Authentication object representing the authentication to the AX API.
        :param username: <string> the username to login to the AX API.
        :param password: <string> the password to login to the AX API.
        """
        _AX.__init__(self, ax_host=ax_host, ax_port=ax_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, username=username,
                                                 password=password)

    def prepare_file(self, file_path):
        self.FILE = open(file_path, "rb")
        self.FILE_PREPARED = True

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="POST", route="/customioc/yara/add/<yara_type>", request_params=["target_type"],
                      require_file=True)
    def add_yara_rule(self, yara_type, target_type=None,file_path=None, file_handle=None, **kwargs):
        """Submit a YARA rule file

        :param yara_type: <string> the file type of the YARA rule file being submitted.
        :param target_type: <string> the contentType that the new YARA rule should be applied to.
        :param file_path: <strint> the path to the YARA file to upload
        :param file_handle: <file> file handle of open yara file to upload
        :param kwargs:
        :return: <JsonResponse> JSON response data.
        """
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="POST", route="/customioc/yara/remove/<yara_type>/<yara_file>",
                      request_params=["target_type"])
    def delete_yara_rule(self, yara_type, yara_file, target_type=None, **kwargs):
        """Delete a YARA rule file.

        :param yara_type: <string> the file type of the YARA rule file being submitted.
        :param yara_file: <string> Name of the YARA rule file to delete.
        :param target_type: <string> the contentType that the new YARA rule should be applied to.
        :param kwargs:
        :return: <JsonResponse> JSON response data.
        """
        return self._base_request(**kwargs)
