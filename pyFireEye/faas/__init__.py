"""

"""
from .faas_core import Authentication, Investigations


class FaaS:

    """

    """

    def __init__(self, verify=False, token_auth=False, api_key="", api_secret=""):

        if not verify:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self._authenticator = Authentication(verify=verify, token_auth=token_auth, api_key=api_key, api_secret=api_secret)
        if api_secret and api_key:
            self._authenticator.authenticate(api_key=api_key, api_secret=api_secret)
        self.investigations = Investigations(verify=verify, authenticator=self._authenticator)

        def authenticate(self, api_key, api_secret, token_auth=False):

            return self._authenticator.authenticate(api_key=api_key, api_secret=api_secret, token_auth=token_auth)
