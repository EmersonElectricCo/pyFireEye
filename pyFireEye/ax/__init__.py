from .ax_core import *


class AX:

    """

    """

    def __init__(self, ax_host, ax_port=None, verify=False, token_auth=False, username="", password="", token=""):

        if not verify:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self._authenticator = Authentication(ax_host=ax_host, ax_port=ax_port, verify=verify, token_auth=token_auth, username=username, password=password, token=token)
        if username and password and not token:
            self._authenticator.authenticate(username=username, password=password, token_auth=token_auth)
        self.alerts = Alerts(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.submissions = Submission(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.reports = Reports(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.config = Config(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.artifacts = Artifacts(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.ati = ATI(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)
        self.custom_ioc = CustomIOC(ax_host=ax_host, ax_port=ax_port, verify=verify, authenticator=self._authenticator)

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
