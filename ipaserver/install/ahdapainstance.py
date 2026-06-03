# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.

from __future__ import absolute_import

import logging
import os
import pwd

from ipalib import api
from ipaplatform import services
from ipaplatform.paths import paths
from ipaserver.install.service import SimpleServiceInstance
from ipaserver.install import sysupgrade
from ipapython import ipautil
from ipapython import ipaldap

logger = logging.getLogger(__name__)

AHDAPA_USER = 'ahdapa'
IDP_CLIENT_ID = 'ipa-webui'


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

    def create_instance(self, realm, host_name, domain,
                        ldap_suffix=None):
        self.fqdn = host_name
        self.realm = realm
        self.domain = domain

        self.step("creating ahdapa container",
                  self._create_container)
        self.step("enabling S4U2Self delegation on HTTP service",
                  self._enable_delegation)
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
            IDP_CLIENT_ID=IDP_CLIENT_ID,
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

        # Create HBAC rule for the Web UI client if not present
        result = self._ahdapactl('hbac', 'list')
        if IDP_CLIENT_ID not in result.output:
            logger.debug('Creating HBAC rule for %s', IDP_CLIENT_ID)
            self._ahdapactl(
                'hbac', 'create',
                '--name', 'FreeIPA Web UI access',
                '--description',
                'Allow all users to obtain Kerberos credentials '
                'via the FreeIPA Web UI',
                '--user-groups', 'ipausers',
                '--clients', IDP_CLIENT_ID,
                '--scopes', 'openid,profile,krb5:ccache')
        else:
            logger.debug('HBAC rule for %s already exists', IDP_CLIENT_ID)

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
            self.create_instance(
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
