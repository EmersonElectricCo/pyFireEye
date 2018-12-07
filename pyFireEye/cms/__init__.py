from .cms_core import Authentication, Alerts


class CMS:

    """

    """

    def __init__(self, cms_host, cms_port=None, verify=False, token_auth=False, username="", password=""):

        if not verify:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self._authenticator = Authentication(cms_host=cms_host, cms_port=cms_port, verify=verify, token_auth=token_auth, username=username, password=password)
        if username and password:
            self._authenticator.authenticate(username=username, password=password)
        self.alerts = Alerts(cms_host=cms_host, cms_port=cms_port, verify=verify, authenticator=self._authenticator)

    def reauth(self):
        return self._authenticator.authenticate()

    def authenticate(self, username, password, token_auth=None):
        """ """
        return self._authenticator.authenticate(username=username, password=password, token_auth=token_auth)

    def logout(self):
        """ """
        return self._authenticator.logout()
