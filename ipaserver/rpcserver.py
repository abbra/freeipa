# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008-2016  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
RPC server.

Also see the `ipalib.rpc` and `ipaserver.rbcbase` modules.
"""

from __future__ import absolute_import

import logging
from xml.sax.saxutils import escape
import os
from io import BytesIO
from urllib.parse import parse_qs
from xmlrpc.client import Fault

import ldap.controls
from pyasn1.type import univ, namedtype
from pyasn1.codec.ber import encoder
import six

from ipalib.capabilities import VERSION_WITHOUT_CAPABILITIES
from ipalib.install.kinit import kinit_armor, kinit_password
from ipalib.errors import (
    CCacheError,
    InvalidSessionPassword,
    NotFound,
    ACIError,
    ExecutionError,
    PasswordExpired,
    KrbPrincipalExpired,
    KrbPrincipalWrongFAST,
    UserLocked,
    ZeroArgumentError,
    RequirementError,
    MaxArgumentError,
    DatabaseError,
)
from ipalib.request import context, destroy_context
from ipalib.rpc import xml_dumps, xml_loads
from ipapython.dn import DN
from ipaserver.plugins.ldap2 import ldap2
from ipalib.backend import Backend
from ipalib.krb_utils import (
    get_credentials_if_valid)
from ipapython import kerberos
from ipapython import ipautil
from ipaplatform.paths import paths

if six.PY3:
    unicode = str

from ipaserver.rpcbase import (
    params_2_args_options,
    read_input,
    KerberosWSGIExecutioner,
    KerberosSession,
    jsonserver,
    HTTP_Status,
    HTTP_STATUS_SUCCESS,
    _success_template,
)

logger = logging.getLogger(__name__)


class xmlserver(KerberosWSGIExecutioner):
    """
    Execution backend plugin for XML-RPC server.

    Also see the `ipalib.rpc.xmlclient` plugin.
    """

    content_type = 'text/xml'
    key = '/xml'

    def listMethods(self, *params):
        """list methods for XML-RPC introspection"""
        if params:
            raise ZeroArgumentError(name='system.listMethods')
        return (tuple(unicode(cmd.name) for cmd in self.api.Command) +
                tuple(unicode(name) for name in self._system_commands))

    def _get_method_name(self, name, *params):
        """Get a method name for XML-RPC introspection commands"""
        if not params:
            raise RequirementError(name='method name')
        elif len(params) > 1:
            raise MaxArgumentError(name=name, count=1)
        [method_name] = params
        return method_name

    def methodSignature(self, *params):
        """get method signature for XML-RPC introspection"""
        method_name = self._get_method_name('system.methodSignature', *params)
        if method_name in self._system_commands:
            # TODO
            # for now let's not go out of our way to document standard XML-RPC
            return u'undef'
        else:
            self._get_command(method_name)

            # All IPA commands return a dict (struct),
            # and take a params, options - list and dict (array, struct)
            return [[u'struct', u'array', u'struct']]

    def methodHelp(self, *params):
        """get method docstring for XML-RPC introspection"""
        method_name = self._get_method_name('system.methodHelp', *params)
        if method_name in self._system_commands:
            return u''
        else:
            command = self._get_command(method_name)
            return unicode(command.doc or '')

    _system_commands = {
        'system.listMethods': listMethods,
        'system.methodSignature': methodSignature,
        'system.methodHelp': methodHelp,
    }

    def unmarshal(self, data):
        (params, name) = xml_loads(data)
        if name in self._system_commands:
            # For XML-RPC introspection, return params directly
            return (name, params, {}, None)
        (args, options) = params_2_args_options(params)
        if 'version' not in options:
            # Keep backwards compatibility with client containing
            # bug https://fedorahosted.org/freeipa/ticket/3294:
            # If `version` is not given in XML-RPC, assume an old version
            options['version'] = VERSION_WITHOUT_CAPABILITIES
        return (name, args, options, None)

    def marshal(self, result, error, _id=None,
                version=VERSION_WITHOUT_CAPABILITIES):
        if error:
            logger.debug('response: %s: %s',
                         error.__class__.__name__, str(error))
            response = Fault(error.errno, error.strerror)
        else:
            if isinstance(result, dict):
                logger.debug('response: entries returned %d',
                             result.get('count', 1))
            response = (result,)
        dump = xml_dumps(response, version, methodresponse=True)
        return dump.encode('utf-8')


class jsonserver_i18n_messages(jsonserver):
    """
    JSON RPC server for i18n messages only.
    """

    key = '/i18n_messages'

    def not_allowed(self, start_response):
        status = '405 Method Not Allowed'
        headers = [('Allow', 'POST')]
        response = b''

        logger.debug('jsonserver_i18n_messages: %s', status)
        start_response(status, headers)
        return [response]

    def forbidden(self, start_response):
        status = '403 Forbidden'
        headers = []
        response = b'Invalid RPC command'

        logger.debug('jsonserver_i18n_messages: %s', status)
        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        logger.debug('WSGI jsonserver_i18n_messages.__call__:')
        if environ['REQUEST_METHOD'] != 'POST':
            return self.not_allowed(start_response)

        data = read_input(environ)
        unmarshal_data = super(jsonserver_i18n_messages, self
                               ).unmarshal(data)
        name = unmarshal_data[0] if unmarshal_data else ''
        if name != 'i18n_messages':
            return self.forbidden(start_response)

        environ['wsgi.input'] = BytesIO(data.encode('utf-8'))
        response = super(jsonserver_i18n_messages, self
                         ).__call__(environ, start_response)
        return response


class jsonserver_session(jsonserver, KerberosSession):
    """
    JSON RPC server protected with session auth.
    """

    key = '/session/json'

    def __init__(self, api):
        super(jsonserver_session, self).__init__(api)

    def _on_finalize(self):
        super(jsonserver_session, self)._on_finalize()

    def __call__(self, environ, start_response):
        '''
        '''

        logger.debug('WSGI jsonserver_session.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        # Redirect to login if no Kerberos credentials
        ccache_name = self.get_environ_creds(environ)
        if ccache_name is None:
            return self.need_login(start_response)

        # Store the ccache name in the per-thread context
        setattr(context, 'ccache_name', ccache_name)

        # This may fail if a ticket from wrong realm was handled via browser
        try:
            self.create_context(ccache=ccache_name)
        except ACIError as e:
            return self.unauthorized(environ, start_response, str(e), 'denied')
        except DatabaseError as e:
            # account is disable but user has a valid ticket
            msg = str(e)
            if "account inactivated" in msg.lower():
                return self.unauthorized(
                    environ, start_response, str(e), "account disabled"
                )
            else:
                return self.service_unavailable(environ, start_response, msg)

        except CCacheError:
            return self.need_login(start_response)

        try:
            response = super(jsonserver_session,
                             self).__call__(environ, start_response)
        finally:
            destroy_context()

        return response


class jsonserver_kerb(jsonserver, KerberosWSGIExecutioner):
    """
    JSON RPC server protected with kerberos auth.
    """

    key = '/json'


class KerberosLogin(Backend, KerberosSession):
    key = None

    def _on_finalize(self):
        super(KerberosLogin, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        logger.debug('WSGI KerberosLogin.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        # Redirect to login if no Kerberos credentials
        user_ccache_name = self.get_environ_creds(environ)
        if user_ccache_name is None:
            return self.need_login(start_response)

        return self.finalize_kerberos_acquisition(
            "login_kerberos", user_ccache_name, environ, start_response
        )


class login_kerberos(KerberosLogin):
    key = '/session/login_kerberos'


class login_x509(KerberosLogin):
    key = '/session/login_x509'

    def __call__(self, environ, start_response):
        logger.debug('WSGI login_x509.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        if 'KRB5CCNAME' not in environ:
            return self.unauthorized(
                environ, start_response, 'KRB5CCNAME not set',
                'Authentication failed')

        return super(login_x509, self).__call__(environ, start_response)


class login_password(Backend, KerberosSession):

    content_type = 'text/plain'
    key = '/session/login_password'

    def _on_finalize(self):
        super(login_password, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        def attempt_kinit(user_principal, password,
                          ipa_ccache_name, use_armor=True):
            try:
                # try to remove in case an old file was there
                os.unlink(ipa_ccache_name)
            except OSError:
                pass
            try:
                self.kinit(user_principal, password,
                           ipa_ccache_name, use_armor=use_armor)
            except PasswordExpired as e:
                return self.unauthorized(environ, start_response,
                                         str(e), 'password-expired')
            except InvalidSessionPassword as e:
                return self.unauthorized(environ, start_response,
                                         str(e), 'invalid-password')
            except KrbPrincipalExpired as e:
                return self.unauthorized(environ,
                                         start_response,
                                         str(e),
                                         'krbprincipal-expired')
            except UserLocked as e:
                return self.unauthorized(environ,
                                         start_response,
                                         str(e),
                                         'user-locked')
            return None

        logger.debug('WSGI login_password.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        # Get the user and password parameters from the request
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(
                environ,
                start_response,
                "Content-Type must be application/x-www-form-urlencoded",
            )

        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(
                environ, start_response, "HTTP request method must be POST"
            )

        try:
            query_dict = parse_qs(query_string)
        except Exception:
            return self.bad_request(
                environ, start_response, "cannot parse query data"
            )

        user = query_dict.get('user', None)
        if user is not None:
            if len(user) == 1:
                user = user[0]
            else:
                return self.bad_request(
                    environ, start_response, "more than one user parameter"
                )
        else:
            return self.bad_request(
                environ, start_response, "no user specified"
            )

        # allows login in the form user@SERVER_REALM or user@server_realm
        # we kinit as enterprise principal so we can assume that unknown realms
        # are UPN
        try:
            user_principal = kerberos.Principal(user)
        except Exception:
            # the principal is malformed in some way (e.g. user@REALM1@REALM2)
            # netbios names (NetBIOS1\user) are also not accepted (yet)
            return self.unauthorized(environ, start_response, '', 'denied')

        password = query_dict.get('password', None)
        if password is not None:
            if len(password) == 1:
                password = password[0]
            else:
                return self.bad_request(
                    environ, start_response, "more than one password parameter"
                )
        else:
            return self.bad_request(
                environ, start_response, "no password specified"
            )

        # Get the ccache we'll use and attempt to get credentials
        # in it with user,password
        ipa_ccache_name = os.path.join(paths.IPA_CCACHES,
                                       'kinit_{}'.format(os.getpid()))
        try:
            result = attempt_kinit(user_principal, password,
                                   ipa_ccache_name, use_armor=True)
        except KrbPrincipalWrongFAST:
            result = attempt_kinit(user_principal, password,
                                   ipa_ccache_name, use_armor=False)

        if result is not None:
            return result

        result = self.finalize_kerberos_acquisition('login_password',
                                                    ipa_ccache_name, environ,
                                                    start_response)
        try:
            # Try not to litter the filesystem with unused TGTs
            os.unlink(ipa_ccache_name)
        except OSError:
            pass
        return result

    def kinit(self, principal, password, ccache_name, use_armor=True):
        if use_armor:
            # get anonymous ccache as an armor for FAST to enable OTP auth
            armor_path = os.path.join(paths.IPA_CCACHES,
                                      "armor_{}".format(os.getpid()))

            logger.debug('Obtaining armor in ccache %s', armor_path)

            try:
                kinit_armor(
                    armor_path,
                    pkinit_anchors=[paths.KDC_CERT, paths.KDC_CA_BUNDLE_PEM],
                )
            except RuntimeError:
                logger.error("Failed to obtain armor cache")
                # We try to continue w/o armor, 2FA will be impacted
                armor_path = None
        else:
            armor_path = None

        try:
            kinit_password(
                unicode(principal),
                password,
                ccache_name,
                armor_ccache_name=armor_path,
                enterprise=True,
                canonicalize=True,
                lifetime=self.api.env.kinit_lifetime)

        except RuntimeError as e:
            if ('kinit: Cannot read password while '
                    'getting initial credentials') in str(e):
                raise PasswordExpired(principal=principal, message=unicode(e))
            elif ('kinit: Client\'s entry in database'
                  ' has expired while getting initial credentials') in str(e):
                raise KrbPrincipalExpired(principal=principal,
                                          message=unicode(e))
            elif ('kinit: Clients credentials have been revoked '
                  'while getting initial credentials') in str(e):
                raise UserLocked(principal=principal,
                                 message=unicode(e))
            elif ('kinit: Error constructing AP-REQ armor: '
                  'Matching credential not found') in str(e):
                raise KrbPrincipalWrongFAST(principal=principal)
            raise InvalidSessionPassword(principal=principal,
                                         message=unicode(e))
        finally:
            if armor_path:
                logger.debug('Cleanup the armor ccache')
                ipautil.run([paths.KDESTROY, '-A', '-c', armor_path],
                            env={'KRB5CCNAME': armor_path}, raiseonerr=False)


class change_password(Backend, HTTP_Status):

    content_type = 'text/plain'
    key = '/session/change_password'

    def _on_finalize(self):
        super(change_password, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        logger.info('WSGI change_password.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        # Get the user and password parameters from the request
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(
                environ,
                start_response,
                "Content-Type must be application/x-www-form-urlencoded",
            )

        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(
                environ, start_response, "HTTP request method must be POST"
            )

        try:
            query_dict = parse_qs(query_string)
        except Exception:
            return self.bad_request(
                environ, start_response, "cannot parse query data"
            )

        data = {}
        for field in ('user', 'old_password', 'new_password', 'otp'):
            value = query_dict.get(field, None)
            if value is not None:
                if len(value) == 1:
                    data[field] = value[0]
                else:
                    return self.bad_request(
                        environ, start_response,
                        "more than one %s parameter" % field
                    )
            elif field != 'otp':  # otp is optional
                return self.bad_request(
                    environ, start_response, "no %s specified" % field
                )

        # start building the response
        logger.info("WSGI change_password: start password change of user '%s'",
                    data['user'])
        status = HTTP_STATUS_SUCCESS
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]
        title = 'Password change rejected'
        result = 'error'
        policy_error = None

        bind_dn = DN((self.api.Object.user.primary_key.name, data['user']),
                     self.api.env.container_user, self.api.env.basedn)

        try:
            pw = data['old_password']
            if data.get('otp'):
                pw = data['old_password'] + data['otp']
            conn = ldap2(self.api)
            conn.connect(bind_dn=bind_dn, bind_pw=pw)
        except (NotFound, ACIError):
            result = 'invalid-password'
            message = 'The old password or username is not correct.'
        except Exception as e:
            message = "Could not connect to LDAP server."
            logger.error("change_password: cannot authenticate '%s' to LDAP "
                         "server: %s",
                         data['user'], str(e))
        else:
            try:
                conn.modify_password(
                    bind_dn, data["new_password"], data["old_password"],
                    skip_bind=True
                )
            except ExecutionError as e:
                result = 'policy-error'
                policy_error = escape(str(e))
                message = "Password change was rejected: %s" % escape(str(e))
            except Exception as e:
                message = "Could not change the password"
                logger.error("change_password: cannot change password of "
                             "'%s': %s",
                             data['user'], str(e))
            else:
                result = 'ok'
                title = "Password change successful"
                message = "Password was changed."
            finally:
                if conn.isconnected():
                    conn.disconnect()

        logger.info('%s: %s', status, message)

        response_headers.append(('X-IPA-Pwchange-Result', result))
        if policy_error:
            response_headers.append(
                ("X-IPA-Pwchange-Policy-Error", policy_error)
            )

        start_response(status, response_headers)
        output = _success_template % dict(title=str(title),
                                          message=str(message))
        return [output.encode('utf-8')]


class sync_token(Backend, HTTP_Status):
    content_type = 'text/plain'
    key = '/session/sync_token'

    class OTPSyncRequest(univ.Sequence):
        OID = "2.16.840.1.113730.3.8.10.6"

        componentType = namedtype.NamedTypes(
            namedtype.NamedType('firstCode', univ.OctetString()),
            namedtype.NamedType('secondCode', univ.OctetString()),
            namedtype.OptionalNamedType('tokenDN', univ.OctetString())
        )

    def _on_finalize(self):
        super(sync_token, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        # Make sure this is a form request.
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(
                environ,
                start_response,
                "Content-Type must be application/x-www-form-urlencoded",
            )

        # Make sure this is a POST request.
        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(
                environ, start_response, "HTTP request method must be POST"
            )

        # Parse the query string to a dictionary.
        try:
            query_dict = parse_qs(query_string)
        except Exception:
            return self.bad_request(
                environ, start_response, "cannot parse query data"
            )
        data = {}
        kws = ("user", "password", "first_code", "second_code", "token")
        for field in kws:
            value = query_dict.get(field, None)
            if value is not None:
                if len(value) == 1:
                    data[field] = value[0]
                else:
                    return self.bad_request(
                        environ, start_response,
                        "more than one %s parameter" % field
                    )
            elif field != 'token':
                return self.bad_request(
                    environ, start_response, "no %s specified" % field
                )

        # Create the request control.
        sr = self.OTPSyncRequest()
        sr.setComponentByName('firstCode', data['first_code'])
        sr.setComponentByName('secondCode', data['second_code'])
        if 'token' in data:
            try:
                token_dn = DN(data['token'])
            except ValueError:
                token_dn = DN(
                    (self.api.Object.otptoken.primary_key.name, data["token"]),
                    self.api.env.container_otp,
                    self.api.env.basedn,
                )

            sr.setComponentByName('tokenDN', str(token_dn))
        rc = ldap.controls.RequestControl(sr.OID, True, encoder.encode(sr))

        # Resolve the user DN
        bind_dn = DN((self.api.Object.user.primary_key.name, data['user']),
                     self.api.env.container_user, self.api.env.basedn)

        # Start building the response.
        status = HTTP_STATUS_SUCCESS
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]
        title = 'Token sync rejected'

        # Perform the synchronization.
        conn = ldap2(self.api)
        try:
            conn.connect(bind_dn=bind_dn,
                         bind_pw=data['password'],
                         serverctrls=[rc,])
            result = 'ok'
            title = "Token sync successful"
            message = "Token was synchronized."
        except (NotFound, ACIError):
            result = 'invalid-credentials'
            message = 'The username, password or token codes are not correct.'
        except Exception as e:
            result = 'error'
            message = "Could not connect to LDAP server."
            logger.error("token_sync: cannot authenticate '%s' to LDAP "
                         "server: %s",
                         data['user'], str(e))
        finally:
            if conn.isconnected():
                conn.disconnect()

        # Report status and return.
        response_headers.append(('X-IPA-TokenSync-Result', result))
        start_response(status, response_headers)
        output = _success_template % dict(title=str(title),
                                          message=str(message))
        return [output.encode('utf-8')]


class xmlserver_session(xmlserver, KerberosSession):
    """
    XML RPC server protected with session auth.
    """

    key = '/session/xml'

    def __init__(self, api):
        super(xmlserver_session, self).__init__(api)

    def _on_finalize(self):
        super(xmlserver_session, self)._on_finalize()

    def need_login(self, start_response):
        status = '401 Unauthorized'
        headers = []
        response = b''

        logger.debug('xmlserver_session: %s need login', status)

        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        '''
        '''

        logger.debug('WSGI xmlserver_session.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        ccache_name = environ.get('KRB5CCNAME')

        # Redirect to /ipa/xml if no Kerberos credentials
        if ccache_name is None:
            logger.debug('xmlserver_session.__call_: no ccache, need TGT')
            return self.need_login(start_response)

        # Redirect to /ipa/xml if Kerberos credentials are expired
        creds = get_credentials_if_valid(ccache_name=ccache_name)
        if not creds:
            logger.debug('xmlserver_session.__call_: ccache expired, deleting '
                         'session, need login')
            # The request is finished with the ccache, destroy it.
            return self.need_login(start_response)

        # Store the session data in the per-thread context
        setattr(context, 'ccache_name', ccache_name)

        try:
            response = super(xmlserver_session, self).__call__(
                environ, start_response
            )
        finally:
            destroy_context()

        return response


class oauth_idp(Backend, HTTP_Status):

    content_type = 'text/plain'
    key = '/auth'
    callbacks = ['authorize', 'token']

    def _on_finalize(self):
        super(oauth_idp, self)._on_finalize()
        for key in self.callbacks:
            self.api.Backend.wsgi_dispatch.mount(self, self.key + '/' + key)

    def __call__(self, environ, start_response):
        logger.info('WSGI oauth_idp.__call__:')
        logger.info('WSGI oauth_idp: env is %s', str(environ))

        name = environ['PATH_INFO'].split('/')[-1]
        if name not in self.callbacks:
            return self.bad_request(
                environ, start_response, "cannot handle request"
            )

        def prepare_request(environ):
            pass
        from ipaserver.oauth2 import ExternalIdPValidator
        from oauthlib.oauth2 import WebApplicationServer

        validator = ExternalIdPValidator(self.api)
        server = WebApplicationServer(validator)

        def authorize_callback(query_string):
            scopes, credentials = server.validate_authorization_request(
                uri=environ['SCRIPT_URI'],
                http_method=environ['REQUEST_METHOD'],
                body=query_string)
            logger.info(
                "WSGI oauth_idp: scopes = %s, credentials = %s",
                str(scopes),
                str(credentials)
            )

        def token_callback():
            server.validate_token_request()

        # Get the user and password parameters from the request
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(
                environ,
                start_response,
                "Content-Type must be application/x-www-form-urlencoded",
            )
        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(
                environ, start_response, "HTTP request method must be POST"
            )
        try:
            data = parse_qs(query_string)
        except Exception:
            return self.bad_request(
                environ, start_response, "cannot parse query data"
            )

        # start building the response
        logger.info("WSGI oauth_idp: data passed '%s'", str(data))

        status = HTTP_STATUS_SUCCESS
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        if name == 'authorize':
            scopes, creds = authorize_callback(query_string)
            response_headers.append(('OAuth-Response', str(creds)))

        logger.info('%s: %s', status, str(response_headers))

        start_response(status, response_headers)
