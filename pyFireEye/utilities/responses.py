try:
    from StringIO import StringIO as MemIO
except ImportError:
    from io import BytesIO as MemIO

try:
    test = unicode
    byte_type = str
except:
    byte_type = bytes
import zipfile
import json


DEFAULT = "DEFAULT"
JSON = "JSON"
ZIP = "ZIP"
XML = "XML"
REDLINE = "REDLINE"


class FEResponse:
    status = 0
    headers = {}
    message = ""
    content = ""

    def __init__(self, message, status, headers, content=None):

        self.message = message
        self.status = status
        self.content = content
        self.headers = headers

    def __str__(self):

        return json.dumps(self.json())

    def json(self):

        return {
            "status": self.status,
            "headers": self.headers,
            "message": self.message,
            "content": self.content
        }


def make_response(response, expected_format, expected_status):

    if response.status_code not in expected_status:
        return _error_response(response, expected_status)
    try:
        if expected_format == JSON:
            return _json_response(response)
        if expected_format == ZIP:
            return _zip_response(response)
        if expected_format == XML:
            return _xml_response(response)
        if expected_format == REDLINE:
            return _redline_response(response)
        if expected_format == DEFAULT:
            return _default_response(response)
    except Exception as err:
        return _error_response(response, expected_status)


def _json_response(response):

    status = response.status_code
    content = response.json()
    message = content.get("message") if isinstance(content, dict) else None
    headers = dict(response.headers)
    if message:
        del content["message"]
    data = content.get("data") if isinstance(content, dict) else None
    if data:
        del content["data"]
    entries = data.get("entries") if data else None
    if entries:
        del data["entries"]

    return JsonResponse(message=message, status=status, headers=headers, content=content, data=data, entries=entries)


def _zip_response(response):

    status = response.status_code
    headers = dict(response.headers)
    content = response.content

    return ZipResponse(status=status, content=content, headers=headers)


def _xml_response(response):

    status = response.status_code
    content = response.content
    headers = dict(response.headers)
    return XMLResponse(message="", status=status, content=content, headers=headers)


def _error_response(response, expected_status):
    message = response.content
    headers = dict(response.headers)
    status = response.status_code

    return ErrorResponse(message=message, status=status, headers=headers, expected_status=expected_status)


def _redline_response(response):
    status = response.status_code
    content = response.content
    headers = dict(response.headers)

    return RedlineResponse(status=status, content=content, headers=headers)


def _default_response(response):

    status = response.status_code
    message = response.content
    headers = dict(response.headers)

    return FEResponse(status=status, message=message, headers=headers)


class ErrorResponse(FEResponse):

    def __init__(self, message, status, headers, expected_status):
        self.message = message
        self.status = status
        self.headers = headers
        self.expected_status = expected_status

    def __str__(self):
        return json.dumps(self.json())

    def json(self):
        return {
                "message": self.message,
                "status": self.status,
                "headers": self.headers,
                "expected": self.expected_status
            }


class JsonResponse(FEResponse):

    def __init__(self, message, status, headers, content={}, data={}, entries=[]):
        self.message = message
        self.status = status
        self.headers = headers
        self.content = content
        self.data = data
        self.entries = entries

    def __str__(self):
        return json.dumps(self.json())

    def json(self):
        return {
                "message": self.message,
                "status": self.status,
                "headers": self.headers,
                "content": self.content,
                "data": self.data,
                "entries": self.entries

            }


class ZipResponse(FEResponse):
    default_password = "unzip-me"

    def __init__(self, status, content, headers):
        self.content = content
        self.status = status
        self.headers = headers
        self.password = self.default_password.encode("utf-8") if not isinstance(self.default_password, byte_type) else self.default_password

    def unzip(self, password=None, path=None):
        if not password:
            password = self.password

        if not isinstance(password, byte_type):
            password = password.encode("utf-8")

        if not isinstance(self.content, byte_type):
            content = self.content.encode("utf-8")
        else:
            content = self.content
        if not path.endswith('/'):
            path += "/"
        fp = MemIO(content)

        zipfile.ZipFile(fp, allowZip64=True).extractall(path=path, pwd=password)

    def zip_save(self, filename=None, path=""):
        if not filename:
            import uuid
            filename = str(uuid.uuid4()).replace("-", "") + ".zip"
        if not path.endswith('/'):
            path += "/"
        with open(path + filename, "wb") as f:
            f.write(self.content)

        return path + filename

    def __str__(self):
        return json.dumps(self.json())

    def json(self):
        return {
                "status": self.status,
                "headers": self.headers,
                "content": self.content,
                "zip_pass": self.password
            }


class RedlineResponse(FEResponse):
    """
    This class will get responses which are .mans files
    """

    def __init__(self, status, content, headers):
        if not isinstance(content, byte_type):
            content = content.encode("utf-8")
        self.content = content
        self.status = status
        self.headers = headers
        self.filename = None

    def _check_ext(self):
        ext = ".mans"
        if self.filename[-4:] != ext:
            self.filename += ext

    def output_raw_results(self, filename, path=None):
        """
        write results to .mans file
        :param path: path to place file
        :param filename: alternative filename, if the .mans extension is not there, it will be added
        :return:
        """
        if not path.endswith('/'):
            path += "/"
        if path:
            path_base = path
        else:
            path_base = ""

        if filename:
            self.filename = filename
            self._check_ext()
        else:
            import uuid
            self.filename = str(uuid.uuid4()).replace("-", "") + ".mans"

        with open(path_base + self.filename, "wb") as f:
            f.write(self.content)

    def unzip_file(self, path=None):
        if not path.endswith('/'):
            path += "/"
        if not isinstance(self.content, byte_type):
            self.content = self.content.encode("utf-8")

        fp = MemIO(self.content)

        zipfile.ZipFile(fp, allowZip64=True).extractall(path=path)

    def json(self):

        return {
            "status": self.status,
            "headers": self.headers,
            "content": self.content

        }


class XMLResponse(FEResponse):
    pass


class StreamResponse(FEResponse):
    """
    Class to handle responses from the FireEye API that are files/streams.
    """

    def __init__(self, status, content, headers, **kwargs):
        """Initialize an instance of the StreamResponse class.

        :param status: <int> the status code of the request.
        :param content: dictionary containing
            {
                "data_length": <int>,
                "data": None if outputfile was provided, else byte string containing data,
                "filename": name of output file if provided, else None
            }
        :param headers: <dict> returned headers.
        """
        self.content = content
        self.status = status
        self.headers = headers

    def json(self):
        """Produce JSON representation of the StreamResponse class.

        :return: <dict> JSON object.
        """
        return {
            "content": self.content,
            "status": self.status,
            "headers": self.headers,
        }
