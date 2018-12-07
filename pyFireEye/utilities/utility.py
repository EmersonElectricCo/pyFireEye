"""

"""
from base64 import b64encode


def b64encode_wrap(string):

    try:
        t = unicode
        bytes_type = str
    except:
        bytes_type = bytes

    if not isinstance(string, bytes_type):
        string = string.encode("utf-8")

    return b64encode(string).decode("utf-8")
