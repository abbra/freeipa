#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
import logging
from urllib.parse import urlparse

from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve)
from ipalib import api, errors, Password, Str, StrEnum, _, ngettext
from ipalib.plugable import Registry
from ipapython.dn import DN

logger = logging.getLogger(__name__)

__doc__ = _("""
External Identity Provider Servers
""") + _("""
Manage External Identity Provider Servers.
""") + _("""
IPA supports the use of an external Identity Provider for Oauth2.0 Device Flow
authentication.
""") + _("""
EXAMPLES:
""") + _("""
 Add a new external Identity Provider server:
   ipa idp-add MyIdP --client-id jhkQty13 \
      --auth-uri https://oauth2.idp.com/auth \
      --token-uri https://oauth2.idp.com/token --secret
""") + _("""
 Add a new external Identity Provider server using github predefined endpoints:
   ipa idp-add MyIdp --client-id jhkQty13 --provider github --secret
""") + _("""
 Find all external Identity Provider servers whose entries include the string
 "test.com":
   ipa idp-find test.com
""") + _("""
 Examine the configuration of an external Identity Provider server:
   ipa idp-show MyIdP
""") + _("""
 Change the secret:
   ipa idp-mod MyIdP --secret
""") + _("""
 Delete an external Identity Provider server:
   ipa idp-del MyIdP
""")

register = Registry()


def validate_uri(ugettext, uri):
    try:
        parsed = urlparse(uri, 'https')
    except Exception:
        return _('Invalid URI: not an https scheme')

    if not parsed.netloc:
        return _('Invalid URI: missing netloc')

    return None


@register()
class idp(LDAPObject):
    """
    Identity Provider object.
    """
    container_dn = api.env.container_idp
    object_name = _('Identity Provider server')
    object_name_plural = _('Identity Provider servers')
    object_class = ['ipaidp']
    default_attributes = [
        'cn', 'ipaidpauthendpoint', 'ipaidpuserinfoendpoint',
        'ipaidpkeysendpoint', 'ipaidptokenendpoint', 'ipaidpissuerurl',
        'ipaidpclientid', 'ipaidpscope', 'ipaidpsub',
    ]
    search_attributes = [
        'cn', 'ipaidpauthendpoint', 'ipaidptokenendpoint',
        'ipaidpuserinfoendpoint', 'ipaidpkeysendpoint', 'ipaidpscope',
        'ipaidpsub']
    allow_rename = True
    label = _('Identity Provider servers')
    label_singular = _('Identity Provider server')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Identity Provider server name'),
            primary_key=True,
            ),
        Str('ipaidpauthendpoint?',
            validate_uri,
            cli_name='auth_uri',
            label=_('Authorization URI'),
            doc=_('Device authorization endpoint'),
            ),
        Str('ipaidptokenendpoint?',
            validate_uri,
            cli_name='token_uri',
            label=_('Token URI'),
            doc=_('Token endpoint'),
            ),
        Str('ipaidpuserinfoendpoint?',
            validate_uri,
            cli_name='userinfo_uri',
            label=_('User info URI'),
            doc=_('User information endpoint'),
            ),
        Str('ipaidpkeysendpoint?',
            validate_uri,
            cli_name='keys_uri',
            label=_('JWKS URI'),
            doc=_('JWKS endpoint'),
            ),
        Str('ipaidpissuerurl?',
            cli_name='issuer_url',
            label=_('OIDC URL'),
            doc=_(
                'The Identity Provider OIDC URL'),
            ),
        Str('ipaidpclientid',
            cli_name='client_id',
            label=_('Client identifier'),
            doc=_(
                'The client identifier issued by the IdP during registration'),
            ),
        Password('ipaidpclientsecret?',
                 cli_name='secret',
                 label=_('Secret'),
                 doc=_('The client secret'),
                 confirm=True,
                 flags={'no_display'},
                 ),
        Str('ipaidpscope?',
            cli_name='scope',
            label=_('Scope'),
            doc=_('Scope of the access request'),
            ),
        Str('ipaidpsub?',
            cli_name='subject',
            label=_('Subject'),
            doc=_('Attribute holding user identity in User info'),
            ),
    )

    permission_filter_objectclasses = ['ipaidp']
    managed_permissions = {
        'System: Add External IdP server': {
            'ipapermright': {'add'},
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermtargetfilter': {
                '(objectclass=ipaidp)'},
            'default_privileges': {'External IdP server Administrators'}
        },
        'System: Read External IdP server': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'ipaidpauthendpoint',
                'ipaidpuserinfoendpoint', 'ipaidptokenendpoint',
                'ipaidpkeysendpoint', 'ipaidpissuerurl', 'ipaidpclientid',
                'ipaidpscope', 'ipaidpsub',
            },
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermtargetfilter': {
                '(objectclass=ipaidp)'},
            'default_privileges': {'External IdP server Administrators'}
        },
        'System: Modify External IdP server': {
            'ipapermright': {'write'},
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'ipaidpauthendpoint',
                'ipaidpuserinfoendpoint', 'ipaidptokenendpoint',
                'ipaidpkeysendpoint', 'ipaidpissuerurl', 'ipaidpclientid',
                'ipaidpscope', 'ipaidpclientsecret', 'ipaidpsub',
            },
            'default_privileges': {'External IdP server Administrators'}
        },
        'System: Delete External IdP server': {
            'ipapermright': {'delete'},
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermtargetfilter': {
                '(objectclass=ipaidp)'},
            'default_privileges': {'External IdP server Administrators'}
        },
        'System: Read External IdP server client secret': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'ipaidpauthendpoint',
                'ipaidpuserinfoendpoint', 'ipaidptokenendpoint',
                'ipaidpissuerurl', 'ipaidpkeysendpoint', 'ipaidpclientid',
                'ipaidpscope', 'ipaidpclientsecret', 'ipaidpsub',
            },
            'ipapermtargetfilter': {
                '(objectclass=ipaidp)'},
        }
    }


@register()
class idp_add(LDAPCreate):
    __doc__ = _('Add a new Identity Provider server.')
    msg_summary = _('Added Identity Provider server "%(value)s"')

    # List of pre-populated idp endpoints
    # key = provider,
    # value = dictionary of overidden attributes
    idp_providers = {
        'google': {
            'ipaidpauthendpoint':
                'https://oauth2.googleapis.com/device/code',
            'ipaidptokenendpoint':
                'https://oauth2.googleapis.com/token',
            'ipaidpuserinfoendpoint':
                'https://openidconnect.googleapis.com/v1/userinfo',
            'ipaidpkeysendpoint':
                'https://www.googleapis.com/oauth2/v3/certs'},
        'github': {
            'ipaidpauthendpoint':
                'https://github.com/login/device/code',
            'ipaidptokenendpoint':
                'https://github.com/login/oauth/access_token',
            'ipaidpuserinfoendpoint':
                'https://api.github.com/user',
            'ipaidpsub': 'login'},
        'microsoft-common': {
            'ipaidpauthendpoint':
                'https://login.microsoftonline.com/common/oauth2/v2.0/'
                'devicecode',
            'ipaidptokenendpoint':
                'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'ipaidpuserinfoendpoint':
                'https://graph.microsoft.com/oidc/userinfo',
            'ipaidpkeysendpoint':
                'https://login.microsoftonline.com/common/discovery/v2.0/keys'
        },
        'microsoft-consumer': {
            'ipaidpauthendpoint':
                'https://login.microsoftonline.com/consumer/oauth2/v2.0/'
                'devicecode',
            'ipaidptokenendpoint':
                'https://login.microsoftonline.com/consumer/oauth2/v2.0/token',
            'ipaidpuserinfoendpoint':
                'https://graph.microsoft.com/oidc/userinfo',
            'ipaidpkeysendpoint':
                'https://login.microsoftonline.com/common/discovery/v2.0/keys'
        },
        'microsoft-organizations': {
            'ipaidpauthendpoint':
                'https://login.microsoftonline.com/organizations/oauth2/v2.0/'
                'devicecode',
            'ipaidptokenendpoint':
                'https://login.microsoftonline.com/organizations/oauth2/v2.0/'
                'token',
            'ipaidpuserinfoendpoint':
                'https://graph.microsoft.com/oidc/userinfo',
            'ipaidpkeysendpoint':
                'https://login.microsoftonline.com/common/discovery/v2.0/keys'
        },
    }

    takes_options = LDAPCreate.takes_options + (
        StrEnum(
            'ipaidpprovider?',
            cli_name='provider',
            label=_(''),
            flags={'virtual_attribute', 'no_create', 'no_update', 'nosearch'},
            values=tuple(idp_providers),
        ),
    )

    def _convert_provider_to_endpoints(self, entry_attrs, provider=None):
        """
        Converts provider options to auth-uri and token-uri
        """
        if provider:
            if provider not in self.idp_providers:
                raise errors.ValidationError(
                    name='provider',
                    error=_('unknown provider')
                )
            entry_attrs.update(self.idp_providers[provider])

    def get_options(self):
        # Some URIs are not mandatory as they can be built from the value of
        # provider.
        for option in super(idp_add, self).get_options():
            if option.name in ('ipaidpauthendpoint', 'ipaidptokenendpoint',
                               'ipaidpuserinfoendpoint', 'ipaidpkeysendpoint'):
                yield option.clone(required=False, alwaysask=False)
            else:
                yield option

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        # The valid calls are
        # ipa idp-add --provider provider IDP
        # ipa idp-add --auth-uri auth --token-uri token IDP
        auth = options.get('ipaidpauthendpoint')
        token = options.get('ipaidptokenendpoint')
        userinfo = options.get('ipaidpuserinfoendpoint')
        jwks = options.get('ipaidpkeysendpoint')
        provider = options.get('ipaidpprovider')

        # If the provider is supplied, reject individual endpoints
        if any([auth, token, userinfo, jwks]):
            if provider:
                raise errors.MutuallyExclusiveError(
                    reason=_('cannot specify both individual endpoints '
                             'and IdP provider'))

        # If there is no --provider, --auth-uri and --token-uri are required
        if not provider and not auth:
            raise errors.RequirementError(name='auth-uri or provider')
        if not provider and not token:
            raise errors.RequirementError(name='token-uri or provider')
        if not provider and not userinfo:
            raise errors.RequirementError(name='userinfo-uri or provider')

        # if the command is called with --provider we need to add
        # ipaidpauthendpoint and ipaidptokenendpoint to the attrs list
        # in order to display the resulting value in the command output
        for endpoint in ['ipaidpauthendpoint', 'ipaidptokenendpoint',
                         'ipaidpuserinfoendpoint', 'ipaidpkeysendpoint']:
            if endpoint not in attrs_list:
                attrs_list.append(endpoint)

        self._convert_provider_to_endpoints(entry_attrs, provider=provider)
        return dn


@register()
class idp_del(LDAPDelete):
    __doc__ = _('Delete an Identity Provider server.')
    msg_summary = _('Deleted Identity Provider server "%(value)s"')


@register()
class idp_mod(LDAPUpdate):
    __doc__ = _('Modify an Identity Provider server.')
    msg_summary = _('Modified Identity Provider server "%(value)s"')


@register()
class idp_find(LDAPSearch):
    __doc__ = _('Search for Identity Provider servers.')
    msg_summary = ngettext(
        '%(count)d Identity Provider server matched',
        '%(count)d Identity Provider servers matched', 0
    )

    def get_options(self):
        # do not propose --client-id or --secret in ipa idp-find
        for option in super(idp_find, self).get_options():
            if option.name in ('ipaidpclientsecret', 'ipaidpclientid'):
                option = option.clone(flags={'no_option'})

            yield option


@register()
class idp_show(LDAPRetrieve):
    __doc__ = _('Display information about an Identity Provider '
                'server.')
