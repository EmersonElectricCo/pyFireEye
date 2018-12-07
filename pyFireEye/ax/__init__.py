from .ax_core import *


class AX:

    """

    """

    def __init__(self, ax_host, ax_port=None, verify=False, token_auth=False, username="", password=""):

        if not verify:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self._authenticator = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, token_auth=token_auth, username=username, password=password)
        if username and password:
            self._authenticator.authenticate(username=username, password=password)
        self.alerts = Alerts(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.submissions = Submission(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.reports = Reports(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.config = Config(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.artifacts = Artifacts(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.ati = ATI(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.custom_ioc = CustomIOC(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)

    def reauth(self):
        return self._authenticator.authenticate()

    def authenticate(self, username, password, token_auth=None):
        """ """
        return self._authenticator.authenticate(username=username, password=password, token_auth=token_auth)

    def logout(self):
        """ """
        return self._authenticator.logout()
