"""

"""
import requests
from pyFireEye.utilities.responses import ErrorResponse
from pyFireEye.utilities.wrappers import template_request, expected_response
from pyFireEye.utilities.responses import ZIP, JSON, XML, DEFAULT, REDLINE
from pyFireEye.utilities.params_helper import *
from pyFireEye.utilities.exceptions import *
from pyFireEye.utilities.utility import *


class _HX:
    
    """
    Base class for hx endpoints to derive from. will not work by itself unless you construct authenticator
    and set it manually, but you should never need to use it directly
    """

    API_BASE_ROUTE = "/hx/api/v3"
    AUTHENTICATION = None

    def __init__(self, hx_host, hx_port=None, verify=False):
        self.verify = verify
        self.hx_host = hx_host
        self.hx_port = hx_port

    def _build_url(self):
        """
        simple method to combine the base_url, base_port, and base_route
        :return: created url string
        """
        url = self.hx_host
        if self.hx_port:
            url += ":" + str(self.hx_port)
        return url + self.API_BASE_ROUTE

    def _base_request(self, method, route, **kwargs):
        """
        wrapper on the requests.request method that enables simple class extensibility
        using the decorators from binding wrappers. In the simplest case, make a new decorated method and
        pass through **kwargs directly into the base request.

        like so:
        @template_request(method="GET", route="/test", required_headers=["header1"])
        def test(**kwargs):
            return self._base_request(**kwargs)

        :param method: http method (GET, POST, etc...)
        :param route: the unique api route, this will get appended to url built by _build_url
        :param kwargs: the "dict" of arguments typically passed to request calls
        :return: requests.Reponse object after the request is made
        """
        url = self._build_url() + route
        response = requests.request(method=method, url=url, verify=self.verify, **kwargs)
        return response

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/version")
    def version(self, **kwargs):
        return self._base_request(**kwargs)


class Authentication(_HX):
    """
    build in login/logout tokens
    """

    TOKEN_HEADER = "X-FeApi-Token"
    BASIC_HEADER = "Authorization"
    token = ""

    def __init__(self, hx_host, hx_port=None, verify=False, token_auth=False, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        self.username = username
        self.password = password
        self.token_auth = token_auth

    def get_auth_header(self):
        """
        return header tuple to be easily inserted into an existing header dict
        :return: header_key, header_value
        """
        if self.token_auth:
            return self.TOKEN_HEADER, self.token
        else:
            return self.BASIC_HEADER, "Basic " + '"' + b64encode_wrap(self.username + ":" + self.password) + '"'

    def authenticate(self, username="", password="", token_auth=None):
        """
        user username and password to login. If not using token auth, this will simply be a test to see if
        provided username and password work. If username and password and are not provided, the class will look
        to ones provided during init. If they are not there, throw an exception
        :param username: username
        :param password: password
        :param token_auth: True/False, if you want to use token authentication
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
        self.AUTHENTICATION = self

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="GET", route="/token", require_auth=False)
    def auth(self, username, password, **kwargs):
        """
        api method for authentication endpoint
        :param username: username for authentication
        :param password: password for authentication
        :param kwargs: passthrough from template request
        :return: request response
        """
        return self._base_request(auth=(username, password), **kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/token")
    def logout(self, **kwargs):
        """
        logout an existing token if using token auth
        :param kwargs: passthrough from template request
        :return: response if token auth, None otherwise
        """
        return self._base_request(**kwargs)


class Hosts(_HX):
    """
    hosts
    """

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/hosts",
                      request_params=[HAS_ACTIVE_THREATS, HAS_ALERTS, HAS_EXECUTION_ALERTS, HAS_EXPLOIT_ALERTS, 
                                      HAS_EXPLOIT_BLOCKS, HAS_MALWARE_ALERTS, HAS_MALWARE_CLEANED, 
                                      HAS_MALWARE_QUARANTINED, HAS_PRESENCE_ALERTS, HAS_SHARE_MODE, HOSTS_SET_ID, LIMIT, 
                                      OFFSET, SEARCH, SORT, FILTER_FIELD])
    def get_list_of_hosts(self, has_active_threats=None, has_alerts=None, has_execution_alerts=None,
                          has_exploit_alerts=None, has_exploit_blocks=None, has_malware_alerts=None,
                          has_malware_cleaned=None, has_malware_quarantined=None, has_presence_alerts=None,
                          has_share_mode=None, hosts_set_id=None, limit=None, offset=None, search=None, sort=None,
                          filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/hosts/<agent_id>")
    def get_host_by_id(self, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/hosts/<agent_id>")
    def delete_host_by_id(self, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/hosts/<agent_id>/configuration/actual.json")
    def get_configuration_for_agent(self, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/hosts/<agent_id>/files",
                      request_params=[SEARCH, OFFSET, LIMIT, FILTER_FIELD])
    def get_list_file_acquisitions_for_host(self, agent_id, search=None, offset=None, limit=None,
                                            filter_field=None,**kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/hosts/<agent_id>/files",
                      json_body=["req_path", "req_filename", "req_comment", "external_id", "req_use_api"])
    def new_file_acquisition_for_host(self, agent_id, req_path, req_filename, req_comment=None, external_id=None,
                                      req_use_api=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/hosts/<agent_id>/live",
                      request_params=[OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_data_acquisitions_for_host(self, agent_id, offset=None, limit=None, sort=None, 
                                            filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/hosts/<agent_id>/live",
                      json_body=["name", "script"])
    def new_data_acquisition_for_host(self, agent_id, script, name=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/hosts/<agent_id>/sysinfo")
    def get_agent_sysinfo(self, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET",
                      route="/hosts/<agent_id>/triages",
                      request_params=[SEARCH, OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_of_triage_acquisitions_for_host(self, agent_id=None, search=None, offset=None, limit=None,
                                                 sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/hosts/<agent_id>/triages",
                      json_body=["req_timestamp", "external_id"])
    def new_triage_acquisition_for_host(self, agent_id, req_timestamp=None, external_id=None, **kwargs):
        return self._base_request(**kwargs)


class HostSets(_HX):
    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="POST", route="/host_sets/static",
                      json_body=["name"])
    def new_static_hostset(self, name, addhosts=[], removehosts=[], **kwargs):
        changes = [{
            "command": "change",
            "add": addhosts,
            "remove": removehosts
        }]
        kwargs["json"]["changes"] = changes
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="POST", route="/host_sets/dynamic",
                      json_body=["name", "query"])
    def new_dynamic_hostset(self, name, query, **kwargs):
        # TODO make the query more user friendly
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="PUT", route="/host_sets/static/<hostset_id>", json_body=["name"])
    def update_static_hostset(self, hostset_id, name, addhosts=[], removehosts=[], **kwargs):
        changes = [{
            "command": "change",
            "add": addhosts,
            "remove": removehosts
        }]
        kwargs["json"]["changes"] = changes
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="PUT", route="/host_sets/dynamic/<hostset_id>",
                      json_body=["name", "query"])
    def update_dynamic_hostset(self, hostset_id, name, query, **kwargs):
        # TODO make the query more user friendly
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/host_sets",
                      request_params=[SEARCH, OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_hostsets(self, search=None, offset=None, limit=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/host_sets/<hostset_id>")
    def get_hostset_by_id(self, hostset_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/host_sets/<id>")
    def delete_hostset_by_id(self, id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/host_sets/<hostset_id>/hosts",
                      request_params=[HAS_ACTIVE_THREATS, HAS_EXPLOIT_ALERTS, HAS_EXPLOIT_BLOCKS, HAS_MALWARE_ALERTS,
                                      HAS_MALWARE_CLEANED, HAS_MALWARE_QUARANTINED, HAS_PRESENCE_ALERTS, LIMIT, OFFSET,
                                      SEARCH, SORT, FILTER_FIELD])
    def get_list_hosts_in_hostset(self, hostset_id, has_active_threats=None, has_exploit_alerts=None,
                                  has_exploit_blocks=None, has_malware_alerts=None, has_malware_cleaned=None,
                                  has_malware_quarantined=None, has_presence_alerts=None, limit=None, offset=None,
                                  sort=None, search=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)


class EnterpriseSearch(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/searches", json_body=["query"])
    def new_enterprise_search(self, query, hosts=[], host_set_id=None, **kwargs):
        # TODO make the query more user friendly
        if hosts:
            hostlist = [{"_id": host} for host in hosts]
            kwargs["json"]["hosts"] = hostlist
        if host_set_id:
            kwargs["json"]["host_set"] = {HOSTS_SET_ID: host_set_id}

        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/searches",
                      request_params=[OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_of_searches_all_hosts(self, offset=None, limit=None, sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/searches/counts")
    def get_searches_information(self, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/searches/<id>")
    def get_search_status_by_id(self, id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/searches/<id>")
    def delete_search_by_id(self, id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=202, expected_format=JSON)
    @template_request(method="POST", route="/searches/<id>/actions/stop")
    def stop_running_search(self, id, **kwargs):
        return self._base_request(**kwargs)
    
    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/searches/<id>/hosts", 
                      request_params=[OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_hosts_states_for_search(self, id, offset=None, limit=None, sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/searches/<id>/skipped_hosts", 
                      request_params=[HAS_ACTIVE_THREATS, HAS_EXPLOIT_ALERTS, HAS_EXPLOIT_BLOCKS, HAS_MALWARE_ALERTS, 
                                      HOSTS_SET_ID, LIMIT, OFFSET, SORT, FILTER_FIELD])
    def get_list_hosts_skipped_for_search(self, id, has_active_threats=None, has_exploit_alerts=None,
                                          has_exploit_blocks=None, has_malware_alerts=None, host_set_id=None,
                                          limit=None, offset=None, sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/searches/<search_id>/hosts/<agent_id>")
    def get_search_results_for_host(self, search_id, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/searches/<id>/results", request_params=[OFFSET, LIMIT])
    def get_search_results(self, id, offset=None, limit=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/searchs/<id>/results/<row_id>/hosts",
                      request_params=[HAS_ACTIVE_THREATS, HAS_EXPLOIT_ALERTS, HAS_EXPLOIT_BLOCKS, HAS_MALWARE_ALERTS, 
                                      HAS_SHARE_MODE, HOSTS_SET_ID, LIMIT, OFFSET, SORT, FILTER_FIELD])
    def get_host_results_for_grid_row_search(self, id, row_id, has_active_threats=None, has_exploit_alerts=None,
                                             has_exploit_blocks=None, has_malware_alerts=None, has_share_mode=None,
                                             host_set_id=None, limit=None, offset=None, sort=None, filter_field=None,
                                             **kwargs):
        return self._base_request(**kwargs)


class Indicators(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/indicators",
                      request_params=[OFFSET, LIMIT, CATEGORY_SHARE_MODE, SORT, FILTER_FIELD])
    def get_list_indicators_all_categories(self, offset=None, limit=None, category_share_mode=None,
                                           sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/indicators/<category>",
                      request_params=[SEARCH, OFFSET, LIMIT, CATEGORY_SHARE_MODE, SORT, FILTER_FIELD])
    def get_list_of_indicators_in_category(self, category, search, offset, limit, category_share_mode,
                                           sort, filter_field, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/indicators/<category>/<indicator>")
    def get_indicator_by_name(self, category, indicator, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/indicators/<category>",
                      json_body=["display_name", "create_text", "description", "signature", "meta", "platforms"])
    def new_indicator(self, category, display_name=None, create_text=None, description=None, signature=None,
                      meta=None, platforms=None, **kwargs):
        return self._base_request(**kwargs)

    # TODO new indicator with predefined name - this will be the uri_name as defined in the indicator json document
    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="PUT", route="/indicators/<category>/<indicator>",
                      json_body=["display_name", "create_text", "description", "signature", "meta", "platforms", "active_since"])
    def new_named_indicator(self, category, indicator, display_name=None, create_text=None, description=None,
                            signature=None, meta=None, platforms=[], active_since=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/indicators/<category>/<indicator>/conditions/<type>")
    def new_indicator_condition_with_type(self, category, indicator, type, tests, enabled=True, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="PATCH", route="/indicators/<category>/<indicator>",
                      json_body=["display_name", "create_text", "description", "signature", "meta", "platforms", "active_since"])
    def update_indicator(self, category, indicator, display_name=None, create_text=None, description=None,
                         signature=None, meta=None, platforms=None, active_since=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="MOVE", route="/indicators/<category>/<indicator>", request_headers=["destination"])
    def move_indicator(self, category, indicator, destination, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/indicators/<category>/<indicator>")
    def delete_indicator(self, category, indicator, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="PUT", route="/indicators/<category>/<indicator>/conditions")
    def bulk_replace_indicator_conditions(self, category, indicator, conditions, **kwargs):
        """

        :param category: newline separated string of conditions
        :param indicator:
        :param conditions: 
        :param kwargs:
        :return:
        """
        return self._base_request(data=conditions, **kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="PATCH", route="/indicators/<category>/<indicator>/conditions")
    def bulk_append_indicator_conditions(self, category, indicator, conditions, **kwargs):
        """

        :param category: newline separated string of conditions
        :param indicator:
        :param conditions: 
        :param kwargs:
        :return:
        """
        return self._base_request(data=conditions, **kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/indicators/<category>/<indicator>/conditions",
                      request_params=[SEARCH, LIMIT, OFFSET, ENABLED, HAS_ALERTS])
    def get_list_conditions_for_indicator(self, category, indicator, search=None, offset=None,
                                          limit=None, enabled=None, has_alerts=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/indicators/<category>/<indicator>/conditions/<type>",
                      request_params=[SEARCH, LIMIT, OFFSET, ENABLED, HAS_ALERTS])
    def get_list_conditions_for_indicator_by_type(self, category, indicator, type, search=None, offset=None,
                                                  limit=None, enabled=None,has_alerts=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/indicators/<category>/<indicator>/source_alerts",
                      request_params=[SORT, LIMIT, OFFSET, FILTER_FIELD])
    def get_list_source_alerts_for_indicator(self, category, indicator, sort=None, limit=None,
                                             offset=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="GET", route="/indicators/<category>/<indicator>/source_alerts",
                      json_body=["source_url", "ip_addresses"])
    def new_source_alert(self, category, indicator, source_url, ip_addresses, **kwargs):
        return self._base_request(**kwargs)


class Conditions(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="POST", route="/conditions", json_body=["tests", "enabled"])
    def new_condition(self, tests, enabled=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="PATCH", route="/condititions/<condition_id>")
    def enable_condition_by_id(self, condition_id, **kwargs):
        return self._base_request(json={"enabled": True}, **kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/conditions/<condition_id>")
    def get_condition_by_id(self, condition_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/conditions", 
                      request_params=[SEARCH, OFFSET, LIMIT, ENABLED, HAS_ALERTS, HAS_SHARE_MODE])
    def get_list_conditions_all_hosts(self, search=None, offset=None, limit=None, enabled=None,
                                      has_alerts=None, has_share_mode=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/conditions/<condition_id>/indicators", 
                      request_params=[OFFSET, LIMIT, CATEGORY_SHARE_MODE, SORT])
    def get_indicators_using_condition(self, condition_id, offset=None, limit=None,
                                       category_share_mode=None, sort=None, **kwargs):
        return self._base_request(**kwargs)


class IndicatorCategories(_HX):
    
    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/indicator_categories",
                      request_params=[OFFSET, LIMIT, SHARE_MODE, SORT, FILTER_FIELD])
    def get_list_indicator_categories(self, offset=None, limit=None, share_mode=None, 
                                      sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/indicator_categories/<category>", request_params=[SHARE_MODE])
    def get_indicator_category(self, category, share_mode, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="PUT", route="/indicator_categories/<category_name>",
                      json_body=["display_name", "retention_policy", "ui_edit_policy", 
                                 "ui_signature_enabled", "ui_source_alerts_enabled"])
    def new_indicator_category(self, category_name, display_name=None, retention_policy=None, ui_edit_policy=None,
                               ui_signature_enabled=None, ui_source_alerts_enabled=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="PATCH", route="/indicator_categories/<category_name>",
                      json_body=["display_name", "retention_policy", "ui_edit_policy",
                                 "ui_signature_enabled", "ui_source_alerts_enabled"])
    def update_indicator_category(self, category_name, display_name=None, retention_policy=None, ui_edit_policy=None,
                               ui_signature_enabled=None, ui_source_alerts_enabled=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="MOVE", route="/indicator_categories/<category_name>", request_headers=["destination"])
    def move_indicator_category(self, category_name, destination, **kwargs):
        self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="DELETE", route="/indicator_categories/<category>")
    def delete_indicator_category(self, category, **kwargs):
        return self._base_request(**kwargs)


class Alerts(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)
    
    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/alerts/<alert_id>")
    def get_alert_by_id(self, alert_id, **kwargs):
        return self._base_request(**kwargs)
        
    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/alerts",
                      request_params=[OFFSET, LIMIT, HAS_SHARE_MODE, SORT, FILTER_FIELD, FILTER_QUERY])
    def get_list_alerts_all_hosts(self, offset=None, limit=None, has_share_mode=None, sort=None, filter_field=None, filterQuery=None, **kwargs):
        return self._base_request(**kwargs)
        
    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/alerts/<alert_id>")
    def suppress_alert(self, alert_id, **kwargs):
        return self._base_request(**kwargs)


class SourceAlerts(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/source_alerts/<source_alert_id>")
    def get_source_alert_by_id(self, source_alert_id, **kwargs):
       return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/source_alerts/", 
                      request_params=[PRIMARY_INDICATOR_ID, OFFSET, LIMIT, SORT])
    def get_list_source_alerts_all_hosts(self, primary_indicator_id=None, offset=None, limit=None, sort=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/source_alerts/<source_alert_id>/alerted_hosts", 
                      request_params=[HAS_ACTIVE_THREATS, HAS_EXPLOIT_ALERTS, HAS_EXPLOIT_BLOCKS, 
                                      HAS_MALWARE_ALERTS, LIMIT, OFFSET, SEARCH, SORT, FILTER_FIELD])
    def get_list_alerted_hosts_for_source_alert(self, source_alert_id, has_active_threates=None,
                                                has_exploit_alerts=None, has_exploit_blocks=None,
                                                has_malware_alerts=None, limit=None, offset=None, search=None,
                                                sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/source_alerts/<source_alert_id>/alerts", 
                      request_params=[OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_lists_of_alerts_for_source_alert(self, source_alert_id, offset=None, limit=None, sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="PATCH", route="/source_alerts/<source_alert_id>", json_body=["source_url"])
    def update_source_alert(self, source_alert_id, source_url, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/source_alerts/<source_alert_id>")
    def suppress_source_alert(self, source_alert_id, **kwargs):
        return self._base_request(**kwargs)


class Acquisition(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)
    
    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/files", request_params=[SEARCH, OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_file_acquisitions_all_hosts(self, search=None, offset=None, limit=None,
                                             sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/files/<acq_id>")
    def get_file_acquisition_info(self, acq_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=ZIP)
    @template_request(method="GET", route="/acqs/files/<acq_id>.zip")
    def get_file_acquisitition_package(self, acq_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/acqs/files/<acq_id>")
    def delete_file_acquisition(self, acq_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/triages", request_params=[SEARCH, OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_triage_acquisitions_all_hosts(self, search=None, offset=None, limit=None,
                                               sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/triages/<triage_id>")
    def get_triage_acquisition_info(self, triage_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=REDLINE)
    @template_request(method="GET", route="/acqs/triages/<triage_id>.mans")
    def get_triage_collection(self, triage_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/acqs/triages/<triage_id>")
    def delete_triage_acquisition(self, triage_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/acqs/bulk", json_body=["script", "hosts", "host_set"])
    def new_bulk_acquisition(self, script, hosts=None, host_set=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/bulk", request_params=[SEARCH, OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_bulk_acquisitions_all_hosts(self, search=None, offset=None, limit=None,
                                             sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/bulk/<bulk_id>")
    def get_bulk_acquisition_info(self, bulk_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=202, expected_format=JSON)
    @template_request(method="POST", route="/acqs/bulk/<bulk_id>/actions/<action>")
    def change_bulk_acquisition_state(self, bulk_id, action, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=202, expected_format=JSON)
    @template_request(method="POST", route="/acqs/bulk/<bulk_id>/hosts/<agent_id>/actions/refresh")
    def refresh_host_data_in_bulk_acquisition(self, bulk_id, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/acqs/bulk/<bulk_id>")
    def delete_bulk_acquisition(self, bulk_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=ZIP)
    @template_request(method="GET", route="/acqs/bulk/<bulk_id>/hosts/<agent_id>.zip")
    def get_bulk_acquisition_packaged_for_host(self, bulk_id, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/acqs/bulk/<bulk_id/hosts/<agent_id>.zip")
    def delete_host_bulk_acquisition_package_by_host(self, bulk_id, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/bulk/<bulk_id>/hosts", 
                      request_params=[OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_hosts_in_bulk_acquisition(self, bulk_id, offset=None, limit=None, sort=None,
                                           filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/bulk/<bulk_id>/skipped_hosts",
                      request_params=[HAS_ACTIVE_THREATS, HAS_EXPLOIT_ALERTS, HAS_EXPLOIT_BLOCKS, HAS_MALWARE_ALERTS, 
                                      HOSTS_SET_ID, LIMIT, OFFSET, SORT, FILTER_FIELD])
    def get_hosts_skipped_in_bulk_acquisition(self, bulk_id, has_active_threats=None, has_exploit_alerts=None,
                                              has_exploit_blocks=None, has_malware_alerts=None, host_set_id=None,
                                              limit=None, offset=None, sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/bulk/<bulk_id>/hosts/<agent_id>")
    def get_bulk_acquisition_status_for_host(self, bulk_id, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=[200, 201], expected_format=JSON)
    @template_request(method="PUT", route="/acqs/bulk/<bulk_id>/hosts/<agent_id>")
    def add_host_to_bulk_acquisition(self, bulk_id, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/acqs/bulk/<bulk_id>/hosts/<agent_id>")
    def delete_host_from_bulk_acquisition(self, bulk_id, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/live", request_params=[SEARCH, OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_data_acquisitions_all_hosts(self, search=None, offset=None, limit=None,
                                             sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/acqs/live/<data_id>")
    def get_data_acquisition_info(self, data_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=REDLINE)
    @template_request(method="GET", route="/acqs/live/<data_id>.mans")
    def get_data_collection(self, data_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/acqs/live/<data_id>")
    def delete_data_acquisition(self, data_id, **kwargs):
        return self._base_request(**kwargs)


class Quarantine(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/hosts/<agent_id>/quarantines",
                      request_params=[OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_quarantined_files_for_host(self, agent_id=None, offset=None, limit=None, 
                                            sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/quarantines/", 
                      request_params=[OFFSET, LIMIT, SORT, FILTER_FIELD])
    def get_list_quarantined_files(self, offset=None, limit=None, sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/quarantines/<quarantine_id>/files")
    def new_quarantine_file_acquisition(self, quarantine_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=202, expected_format=JSON)
    @template_request(method="DELETE", route="/quarantines/<quarantine_id>/action/delete")
    def delete_quarantined_file(self, quarantine_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=202, expected_format=JSON)
    @template_request(method="POST", route="/quarantines/<quarantine_id>/action/restore")
    def restore_quarantined_file(self, quarantine_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/quarantines/files/<quarantine_id>")
    def get_quarantine_file_information(self, quarantine_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=ZIP)
    @template_request(method="GET", route="/quarantines/<quarantine_id>.zip")
    def get_quarantined_file(self, quarantine_id, **kwargs):
        return self._base_request(**kwargs)


class Scripts(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/scripts", request_params=[SEARCH, LIMIT, SORT, FILTER_FIELD])
    def get_list_scripts_all_hosts(self, search=None, limit=None, sort=None, filter_field=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/scripts/<script_id>")
    def get_script_info_by_id(self, script_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=XML)
    @template_request(method="GET", route="/scripts/<script_id>.xml")
    def get_script_content_py_id(self, script_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=ZIP)
    @template_request(method="GET", route="/scripts.zip")
    def get_script_content_all_hosts(self, **kwargs):
        return self._base_request(**kwargs)


class Containment(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=202, expected_format=JSON)
    @template_request(method="POST", route="/hosts/<agent_id>/containment")
    def new_containment_for_host(self, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/hosts/<agent_id>/containment")
    def get_host_containment_state(self, agent_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/containment_states", request_params=[OFFSET, LIMIT, STATE_UPDATE_TIME])
    def get_containment_state_all_hosts(self, offset=None, limit=None, state_update_time=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="PATCH", route="/hosts/<agent_id>/containment")
    def approve_containment_for_host(self, agent_id, **kwargs):
        return self._base_request(json={"state": "contain"}, **kwargs)

    @expected_response(expected_status_code=204, expected_format=JSON)
    @template_request(method="DELETE", route="/hosts/<agent_id>/containment")
    def cancel_containment_for_host(self, agent_id, **kwargs):
        return self._base_request(**kwargs)


class CustomChannels(_HX):

    def __init__(self, hx_host, hx_port=None, verify=False, authenticator=None, username="", password=""):
        _HX.__init__(self, hx_host, hx_port=hx_port, verify=verify)
        if isinstance(authenticator, Authentication):
            self.AUTHENTICATION = authenticator
        elif username and password:
            self.AUTHENTICATION = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, username=username, password=password)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/host_policies/channels", 
                      request_params=[OFFSET, LIMIT, SEARCH, SORT])
    def get_list_configuration_channels(self, offset=None, limit=None, search=None, sort=None, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="POST", route="/host_policies/channels",
                      json_body=["name", "description", "priority", "configuration"])
    def new_configuration_channel(self, name, host_sets, description=None, priority=None, configuration=None, **kwargs):
        host_sets = [{'_id': int(host_set_id)} for host_set_id in host_sets]
        kwargs["json"]["host_sets"] = host_sets
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/host_policies/channels/<channel_id>")
    def get_configuration_channel_by_id(self, channel_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=201, expected_format=JSON)
    @template_request(method="PATCH", route="/host_policies/channels/<channel_id>",
                      json_body=["name", "description", "priority", "configuration"])
    def update_configuration_channel(self, channel_id, name=None, host_sets=None,
                                     description=None, priority=None, configuration=None, **kwargs):
        if host_sets:
            host_sets = [{'_id': int(host_set_id)} for host_set_id in host_sets]
            kwargs["json"]["host_sets"] = host_sets
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=204, expected_format=DEFAULT)
    @template_request(method="DELETE", route="/host_policies/channels/<channel_id>")
    def delete_configuration_channel(self, channel_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/host_policies/channels/<channel_id>.json")
    def get_configuraton_for_channel(self, channel_id, **kwargs):
        return self._base_request(**kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/host_policies/channels/<channel_id>.json")
    def update_configuration_for_channel(self, channel_id, configuration, **kwargs):
        return self._base_request(json=configuration, **kwargs)

    @expected_response(expected_status_code=200, expected_format=JSON)
    @template_request(method="GET", route="/host_policies/channels/<channel_id>/hosts",
                      request_params=[HAS_ACTIVE_THREATS, HAS_EXPLOIT_ALERTS, HAS_EXPLOIT_BLOCKS, HAS_MALWARE_ALERTS,
                                      HAS_SHARE_MODE, HOSTS_SET_ID, LIMIT, OFFSET, SEARCH, SORT, FILTER_FIELD])
    def get_list_hosts_for_channel(self, channel_id, has_active_threats=None, has_exploit_alerts=None,
                                   has_exploit_blocks=None, has_malware_alerts=None, has_share_ode=None,
                                   host_set_id=None, limit=None, offset=None, search=None, sort=None,
                                   filter_field=None,**kwargs):
        return self._base_request(**kwargs)
