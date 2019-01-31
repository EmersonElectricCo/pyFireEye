from .cms_core import Authentication, Alerts


class CMS:

    """

    """

    def __init__(self, cms_host, cms_port=None, verify=False, token_auth=False, username="", password="", token=""):

        if not verify:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self._authenticator = Authentication(cms_host=cms_host, cms_port=cms_port, verify=verify, token_auth=token_auth, username=username, password=password, token=token)
        if username and password and not token:
            self._authenticator.authenticate(username=username, password=password, token_auth=token_auth)
        self.alerts = Alerts(cms_host=cms_host, cms_port=cms_port, verify=verify, authenticator=self._authenticator)

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
