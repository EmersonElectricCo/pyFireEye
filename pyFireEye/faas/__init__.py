"""

"""
from .faas_core import Authentication, Investigations


class FaaS:

    """

    """

    def __init__(self, verify=False, api_key="", api_secret="", token=""):

        if not verify:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self._authenticator = Authentication(verify=verify, api_key=api_key, api_secret=api_secret, token=token)
        if api_secret and api_key and not token:
            self._authenticator.authenticate(api_key=api_key, api_secret=api_secret)
        self.investigations = Investigations(verify=verify, authenticator=self._authenticator)

    def authenticate(self, api_key, api_secret):

        return self._authenticator.authenticate(api_key=api_key, api_secret=api_secret)
