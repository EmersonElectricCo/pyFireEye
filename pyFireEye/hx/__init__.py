from .hx_core import \
    Authentication, \
    CustomChannels, \
    Alerts, \
    SourceAlerts, \
    Containment, \
    Conditions, \
    Acquisition, \
    Hosts, \
    HostSets, \
    EnterpriseSearch, \
    Indicators, \
    IndicatorCategories, \
    Quarantine, \
    Scripts, \
    ProcessTracker, \
    MessageBus


class HX:

    def __init__(self, hx_host, hx_port=None, verify=False, token_auth=False, username="", password="", token=""):
        """
        Class containing all hx endpoints with unified authenticator
        :param hx_host: hx server endpoint - https://hx.appliance.com ...
        :param hx_port: hx listening port
        :param verify: turn certificate verification on or off, default off
        :param token_auth: whether to use token/basic authentication
        :param username: username for authentication, if not set here, will need to call authenticate method later
        :param password: password for authentication, if not set here, will need to call authenticate method later
        """
        if not verify:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self._authenticator = Authentication(hx_host=hx_host, hx_port=hx_port, verify=verify, token_auth=token_auth, username=username, password=password, token=token)
        if username and password and not token:
            self._authenticator.authenticate(username=username, password=password, token_auth=token_auth)
        self.hosts = Hosts(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.host_sets = HostSets(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.search = EnterpriseSearch(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.indicators = Indicators(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.indicator_categories = IndicatorCategories(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.conditions = Conditions(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.alerts = Alerts(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.source_alerts = SourceAlerts(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.acquisitions = Acquisition(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.quarantine = Quarantine(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.scripts = Scripts(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.containment = Containment(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.custom_channels = CustomChannels(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.process_tracker = ProcessTracker(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)
        self.message_bus = MessageBus(hx_host=hx_host, hx_port=hx_port, verify=verify, authenticator=self._authenticator)

    def reauth(self):
        if self._authenticator.token_auth:
            self._authenticator.authenticate(token_auth=True)

    def authenticate(self, username, password, token_auth=None):
        self._authenticator.authenticate(username=username, password=password, token_auth=token_auth)

    def logout(self):
        if self._authenticator.token:
            token_auth = self._authenticator.token_auth
            self._authenticator.token_auth = True
            self._authenticator.logout()
            self._authenticator.token_auth = token_auth
