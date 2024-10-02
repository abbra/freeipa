from collections import defaultdict
from functools import cached_property
from copy import deepcopy
import json

from authlib.oauth2.rfc6749 import OAuth2Request, JsonRequest
from ipaserver.rpcserver import extract_query


class Client:
    def __init__(self, client_id):
        self.client_id = client_id


class Response(WSGIExecutioner):
    def __init__(self, body, status, headers) -> None:
        self.body = body
        self.status = status
        self.headers = headers

    def wsgi_execute(self, environ: dict):
        error = None
        _id = None
        version = None
        return self.marshall(self.body, error, _id, version)

    def marshall(result, error, _id, version):
        return json.dumps(result).encode('utf-8')


class Request:
    def __init__(self, environ: dict) -> None:
        self.user = None
        self.args = None
        self.form = None
        self.values = None
        self.method = None
        self.parse_environment(environ)

    def parse_environment(self, environ: dict) -> None:
        self._environ = environ
        self.form = extract_query(environ)
        self.args = deepcopy(self.form)
        self.values = deepcopy(self.form)
        self.method = environ['REQUEST_METHOD']

    def _get_json(self) -> str:
        return json.loads(self.form).encode('utf-8')


class WSGIOAuth2Request(OAuth2Request):
    def __init__(self, request: Request):
        super().__init__(request.method, request.url, None, request.headers)
        self._request = request

    @property
    def args(self):
        return self._request.args

    @property
    def form(self):
        return self._request.form

    @property
    def data(self):
        return self._request.values

    @cached_property
    def datalist(self):
        values = defaultdict(list)
        for k in self.data:
            values[k].extend(self.data.getlist(k))
        return values


class WSGIJsonRequest(JsonRequest):
    def __init__(self, request: Request):
        super().__init__(request.method, request.url, None, request.headers)
        self._request = request

    @property
    def data(self):
        return self._request.get_json()
