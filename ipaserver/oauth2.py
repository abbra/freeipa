from urllib.parse import urlparse
from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from ipapython.kerberos import Principal
from ipalib import api, errors
from ipaplatform.paths import paths
import requests

import logging
logger = logging.getLogger(__name__)
from oauthlib import set_debug

class ExternalIdPValidator(RequestValidator):

    def __init__(self, api):
        self.api = api
        self.clients = {}

    # Pre- and post-authorization.

    def validate_client_id(self, client_id, request, *args, **kwargs):
        set_debug(True)
        logger.info('validate_client_id: %s, request: %s, args: %s, kwargs: %s', client_id, str(request), str(args), str(kwargs))
        set_debug(False)
        krb_id = Principal(client_id)
        if krb_id.realm and krb_id.realm != self.api.env.realm:
            return False
        if not(krb_id.is_service or krb_id.is_host):
            return False
        try:
            cookies = {}
            cookies['ipa_session'] = request.client_secret
            payload_template = '{"id": 0, "method": "whoami/1", "params": [[], {"version": "%s"}]}'
            payload = payload_template % self.api.env.api_version
            target = 'https://{0}/ipa'.format(self.api.env.host)
            whoami = None
            with requests.Session() as s:
                s.headers.update({'Referer': target, 'Content-Type': 'application/json'})
                r = s.post(target + '/session/json', data=payload,
                           cookies=cookies,
                           verify=paths.IPA_CA_CRT)
                r.raise_for_status()
                whoami = r.json()
            logger.info('WSGI oauth_idp: internal request result: %s', str(r.text))
            if 'result' in whoami:
                logger.info('WSGI oauth_idp: whoami: %s', str(whoami))
                krb_id_verified = Principal(whoami['principal'])
                if (krb_id == krb_id_verified and
                    whoami['result']['object'] in ('host', 'service')):

                    self.clients[client_id] = whoami
                    return True
                else:
                    return False
        except Exception as e:
            return False
        return False

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        krb_id = Principal(client_id)
        uri = urlparse(redirect_uri)
        if client_id in self.clients:
            if krb_id.hostname == self.clients[client_id]['result']['arguments'][0]:
                return True
        if krb_id.hostname != uri.netloc:
            return False
        return True

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        krb_id = Principal(client_id)
        # Assume Cockpit
        if krb_id.is_host:
            return f"https://{krb_id.hostname}:9090/login"
        return None

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        if 'openid' not in scopes:
            return False
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        return "openid"

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        if response_type != "code":
            return False
        return True

    # Post-authorization

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        pass

    # Token request

    def client_authentication_required(self, request, *args, **kwargs):
        # Check if the client provided authentication information that needs to
        # be validated, e.g. HTTP Basic auth
        pass

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        pass

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # The client_id must match an existing public (non-confidential) client
        pass

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes
        # and user to request.scopes and request.user.
        pass

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        pass

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        pass

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        pass

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        pass

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        pass

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        pass


validator = ExternalIdPValidator(api)
server = WebApplicationServer(validator)
