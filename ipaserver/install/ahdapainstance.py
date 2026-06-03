# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.

from __future__ import absolute_import

import contextlib
import logging
import os
import pwd

from ipalib import api
from ipalib.kinit import kinit_password
from ipaplatform import services
from ipaplatform.paths import paths
from ipaserver.install.service import SimpleServiceInstance
from ipaserver.install import sysupgrade
from ipapython import ipautil
from ipapython import ipaldap

logger = logging.getLogger(__name__)

AHDAPA_USER = 'ahdapa'
HBAC_RULE_NAME = 'IPA Web UI access'


def idp_client_id(fqdn):
    """Per-host OAuth2 client_id for this replica's Web UI.

    Each replica's Web UI lives at its own hostname and thus needs its
    own redirect_uris; ahdapa's client store is gossip-synced cluster-
    wide, so a single shared client_id would have each replica's
    install/upgrade overwrite the redirect_uris the others depend on.
    """
    return 'ipa-webui-{}'.format(fqdn)


def _get_ahdapa_user():
    try:
        return pwd.getpwnam(AHDAPA_USER)
    except KeyError:
        raise RuntimeError(
            "System user '{}' does not exist. "
            "Ensure the ahdapa package is installed.".format(
                AHDAPA_USER))


class AhdapaInstance(SimpleServiceInstance):
    def __init__(self, fstore=None):
        super(AhdapaInstance, self).__init__("ahdapa")
        self.fstore = fstore
        self.fqdn = None
        self.realm = None
        self.domain = None
        self.admin_principal = None
        self.admin_password = None

    def configure_instance(self, realm, host_name, domain,
                           ldap_suffix=None,
                           admin_principal=None, admin_password=None):
        self.fqdn = host_name
        self.realm = realm
        self.domain = domain
        self.admin_principal = admin_principal
        self.admin_password = admin_password

        self.step("creating ahdapa container",
                  self._create_container)
        self.step("enabling S4U2Self delegation on HTTP service",
                  self._enable_delegation)
        self.step("granting ahdapa service role membership",
                  self._grant_role_membership)
        self.step("configuring ahdapa",
                  self._configure_ahdapa)
        self.step("configuring gssproxy for ahdapa",
                  self._configure_gssproxy)
        self.step("configuring httpd proxy for ahdapa",
                  self._configure_httpd_proxy)

        super(AhdapaInstance, self).create_instance(
            gensvc_name='IDP',
            fqdn=self.fqdn,
            ldap_suffix=ldap_suffix or ipautil.realm_to_suffix(self.realm),
            realm=self.realm
        )
        # httpd already has ipa-idp-proxy.conf on disk (written by
        # _configure_httpd_proxy above), but won't proxy /idp until
        # reloaded; wait for ahdapa's socket first so httpd doesn't
        # proxy to it before it's actually listening.
        ipautil.wait_for_open_socket(paths.AHDAPA_SOCKET, timeout=60)
        services.knownservices.httpd.reload_or_restart()
        self.print_msg("Configuring ahdapa OIDC scope and HBAC rule")
        self._configure_hbac()
        sysupgrade.set_upgrade_state('ahdapa', 'installed', True)

    def _create_container(self):
        self._ldap_update(['78-ahdapa.update'])

    def _enable_delegation(self):
        service = 'HTTP/{}@{}'.format(self.fqdn, self.realm)
        result = api.Command.service_show(service, all=True)
        if not result['result'].get('ipakrboktoauthasdelegate', False):
            api.Command.service_mod(
                service, ipakrboktoauthasdelegate=True)
            logger.debug('Enabled ok_to_auth_as_delegate on %s', service)

    def _grant_role_membership(self):
        service = 'HTTP/{}@{}'.format(self.fqdn, self.realm)
        api.Command.role_add_member('Ahdapa Services', service=[service])

    def _write_secure(self, path, content, ahdapa_pw):
        fd = os.open(path,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchown(fd, ahdapa_pw.pw_uid, ahdapa_pw.pw_gid)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

    def _configure_ahdapa(self):
        ahdapa_pw = _get_ahdapa_user()
        ldapi_socket = ipaldap.realm_to_ldapi_uri(self.realm)

        sub_dict = dict(
            REALM=self.realm,
            FQDN=self.fqdn,
            DOMAIN=self.domain,
            AHDAPA_CONF_DIR=paths.AHDAPA_CONF_DIR,
            AHDAPA_SOCKET=paths.AHDAPA_SOCKET,
            AHDAPA_STATE_DIR=paths.AHDAPA_STATE_DIR,
            AHDAPA_CCACHE=paths.AHDAPA_CCACHE,
            LDAPI_SOCKET=ldapi_socket,
            HTTP_KEYTAB=paths.HTTP_KEYTAB,
            IDP_CLIENT_ID=idp_client_id(self.fqdn),
        )

        os.makedirs(paths.AHDAPA_CONF_DIR, mode=0o755, exist_ok=True)

        if self.fstore:
            self.fstore.backup_file(paths.AHDAPA_CONF)
            self.fstore.backup_file(paths.AHDAPA_CLIENTS_CONF)

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ahdapa.toml.template")
        conf = ipautil.template_file(template, sub_dict)
        self._write_secure(paths.AHDAPA_CONF, conf, ahdapa_pw)

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ahdapa-clients.toml.template")
        clients = ipautil.template_file(template, sub_dict)
        self._write_secure(paths.AHDAPA_CLIENTS_CONF, clients, ahdapa_pw)

        os.chown(paths.AHDAPA_CONF_DIR, ahdapa_pw.pw_uid,
                 ahdapa_pw.pw_gid)

    def _configure_gssproxy(self):
        ahdapa_pw = _get_ahdapa_user()

        sub_dict = dict(
            HTTP_KEYTAB=paths.HTTP_KEYTAB,
            AHDAPA_USER=str(ahdapa_pw.pw_uid),
        )

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ahdapa-gssproxy.conf.template")
        conf = ipautil.template_file(template, sub_dict)

        if self.fstore:
            self.fstore.backup_file(paths.AHDAPA_GSSPROXY_CONF)

        with open(paths.AHDAPA_GSSPROXY_CONF, 'w') as f:
            f.write(conf)
            ipautil.flush_sync(f)
        os.chmod(paths.AHDAPA_GSSPROXY_CONF, 0o644)

        services.knownservices.gssproxy.restart()

    def _configure_httpd_proxy(self):
        sub_dict = dict(
            AHDAPA_SOCKET=paths.AHDAPA_SOCKET,
        )

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ipa-idp-proxy.conf.template")
        conf = ipautil.template_file(template, sub_dict)

        if self.fstore:
            self.fstore.backup_file(paths.HTTPD_IPA_IDP_PROXY_CONF)

        with open(paths.HTTPD_IPA_IDP_PROXY_CONF, 'w') as f:
            f.write(conf)
            ipautil.flush_sync(f)
        os.chmod(paths.HTTPD_IPA_IDP_PROXY_CONF, 0o644)

    def _ahdapactl(self, *args):
        base_url = 'https://{}/idp'.format(self.fqdn)
        cmd = [
            paths.AHDAPACTL,
            '--url', base_url,
            '--ca-cert', paths.IPA_CA_CRT,
            '--kerberos',
        ] + list(args)
        return ipautil.run(cmd, capture_output=True)

    def _configure_hbac(self):
        # ahdapactl --kerberos only ever consumes the ambient credential
        # cache (KRB5CCNAME) -- it never touches a keytab itself. During
        # install/replica-install nothing has kinited yet at this point,
        # so if we have the admin password, acquire a transient ticket in
        # a private ccache. On upgrade (no admin_password available), fall
        # back to whatever ambient ccache is already in place.
        need_kinit = (self.admin_password is not None
                      and self.admin_principal is not None)
        ctx = ipautil.private_ccache() if need_kinit else \
            contextlib.nullcontext()

        with ctx as ccache:
            if need_kinit:
                kinit_password(self.admin_principal, self.admin_password,
                               ccache_name=ccache)

            # Create krb5:ccache scope if it does not already exist
            # (may have been replicated from another node via gossip)
            result = self._ahdapactl('scopes', 'list')
            if 'krb5:ccache' not in result.output:
                logger.debug('Creating krb5:ccache scope')
                self._ahdapactl(
                    'scopes', 'update', 'krb5:ccache',
                    '--description', 'Kerberos credential exchange')
            else:
                logger.debug('krb5:ccache scope already exists')

            # Create the HBAC rule for the Web UI client, or -- since it is
            # one shared, gossip-synced rule across the whole cluster --
            # add this replica's own client_id to it if another replica
            # already created it first.
            client_id = idp_client_id(self.fqdn)
            result = self._ahdapactl('hbac', 'list')
            rule_line = next(
                (line for line in result.output.splitlines()
                 if HBAC_RULE_NAME in line), None)
            if rule_line is None:
                logger.debug('Creating HBAC rule %r', HBAC_RULE_NAME)
                self._ahdapactl(
                    'hbac', 'create',
                    '--name', HBAC_RULE_NAME,
                    '--description',
                    'Allow all users to obtain Kerberos credentials '
                    'via the FreeIPA Web UI',
                    '--user-groups', 'ipausers',
                    '--clients', client_id,
                    '--scopes', 'openid,profile,krb5:ccache')
            else:
                rule_id = rule_line.split()[0]
                logger.debug(
                    'HBAC rule %r already exists; ensuring client %r '
                    'is present', HBAC_RULE_NAME, client_id)
                self._ahdapactl(
                    'hbac', 'update', rule_id,
                    '--add-clients', client_id)

    def uninstall(self):
        super(AhdapaInstance, self).uninstall()

        for filepath in (paths.HTTPD_IPA_IDP_PROXY_CONF,
                         paths.AHDAPA_GSSPROXY_CONF,
                         paths.AHDAPA_CLIENTS_CONF,
                         paths.AHDAPA_CONF):
            if self.fstore and self.fstore.has_file(filepath):
                self.fstore.restore_file(filepath)
            else:
                ipautil.remove_file(filepath)

        sysupgrade.set_upgrade_state('ahdapa', 'installed', False)

    def upgrade_instance(self):
        installed = sysupgrade.get_upgrade_state("ahdapa", "installed")
        if not installed:
            return

        self.fqdn = api.env.host
        self.realm = api.env.realm
        self.domain = api.env.domain

        if not os.path.isfile(paths.AHDAPA_CONF):
            logger.warning(
                "ahdapa config is missing, forcing reinstallation")
            installed = False

        if not installed:
            logger.info("ahdapa service is being configured")
            self.configure_instance(
                realm=self.realm,
                host_name=self.fqdn,
                domain=self.domain,
            )
        else:
            self._configure_ahdapa()
            self._configure_gssproxy()
            self._configure_httpd_proxy()
            logger.info("Restarting ahdapa")
            self.restart()
