# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.

from __future__ import absolute_import

import logging
import os

from ipalib import api
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython import ipautil, ipaldap
from ipapython.dn import DN
from ipaserver.install import sysupgrade
from ipaserver.install.service import SimpleServiceInstance, add_principals_to_group

logger = logging.getLogger(__name__)

# kuipad runs as root: it writes the realm's key material under
# /var/lib/ipa/ku and reads only root-owned files there, and the daemon's
# unit (shipped by kuipa-server) declares User=root as well.
KUIPA_USER = 'root'



class KuipadInstance(SimpleServiceInstance):
    def __init__(self, fstore=None):
        super(KuipadInstance, self).__init__(
            "kuipad",
            service_desc="post-quantum enrollment daemon",
            fstore=fstore,
            service_prefix='ipa-ku',
            keytab=paths.KUIPA_KEYTAB,
            service_user=KUIPA_USER)
        self.fqdn = None
        self.realm = None
        self.domain = None

    def configure_instance(self, realm, host_name, domain, ldap_suffix=None):
        self.fqdn = host_name
        self.realm = realm
        self.domain = domain
        self.suffix = ldap_suffix or ipautil.realm_to_suffix(realm)

        self.step("creating kuipa containers", self._create_container)
        # _configure_kuipad must precede the keytab request: it is what
        # creates /var/lib/ipa/ku, and ipa-getkeytab exits 11 ('Failed to
        # add key to the keytab') when that directory is absent.
        self.step("configuring kuipad", self._configure_kuipad)
        self.step("setting up kuipad keytab", self.request_service_keytab)
        # the keys too, before the daemon is started below: 'serve' loads
        # them before binding the socket httpd proxies /ipa/ku to.
        self.step("generating kuipad realm keys", self._generate_keys)
        self.step("adding kuipad to the kuipa server group",
                  self._join_server_group)
        self.step("allowing kuipad to act as the joining principal",
                  self._enable_delegation)
        self.step("configuring httpd proxy for kuipad",
                  self._configure_httpd_proxy)

        super(KuipadInstance, self).create_instance(
            gensvc_name='KU',
            fqdn=self.fqdn,
            ldap_suffix=self.suffix,
            realm=self.realm
        )
        # httpd already has ipa-kuipa-proxy.conf on disk (written by
        # _configure_httpd_proxy above), but won't proxy /ipa/ku until it is
        # reloaded; wait for the daemon's socket first so httpd does not
        # proxy to a socket that is not listening yet.
        ipautil.wait_for_open_socket(paths.KUIPA_SOCKET, timeout=60)
        services.knownservices.httpd.reload_or_restart()
        sysupgrade.set_upgrade_state('kuipa', 'installed', True)

    def _create_container(self):
        self._ldap_update(['74-kuipa.update'])

    def _join_server_group(self):
        # 'kuipa servers' is created by 74-kuipa.update inside the accounts
        # groups container, with the same object classes as 'adtrust agents';
        # every ACI of that file binds as this group.  Here only the member
        # is written: ipa group-add-member accepts users and groups only, and
        # groupdn ACIs in 389-ds match on a real group entry only, so write
        # the value directly as adtrustinstance does for 'adtrust agents'.
        add_principals_to_group(
            api.Backend.ldap2,
            DN(('cn', 'kuipa servers'), api.env.container_group, self.suffix),
            'member', [self.get_principal_dn()])

    def _enable_delegation(self):
        """S4U2Self requires the flag on the daemon's own principal; the
        impersonation rule and its ldap/<server> target are in
        74-kuipa.update."""
        principal = self.principal
        result = api.Command.service_show(principal, all=True)
        if not result['result'].get('ipakrboktoauthasdelegate', False):
            api.Command.service_mod(principal, ipakrboktoauthasdelegate=True)
            logger.debug('Enabled ok_to_auth_as_delegate on %s', principal)

    def _configure_kuipad(self):
        """Create /var/lib/ipa/ku and write /etc/ipa/kuipad.json.

        kuipa-server ships neither a config nor a tmpfiles.d entry for the
        key directory, so the installer creates it: ipa-getkeytab writes the
        daemon's keytab into it and the daemon writes its realm keys there,
        under ProtectSystem=strict.  Root-owned, as created, is what kuipad
        needs -- its unit runs as root.
        """
        os.makedirs(paths.KUIPA_STATE_DIR, mode=0o750, exist_ok=True)

        sub_dict = dict(
            REALM=self.realm,
            DOMAIN=self.domain,
            BASEDN=str(self.suffix),
            FQDN=self.fqdn,
            LDAP_URI=ipaldap.realm_to_ldapi_uri(self.realm),
            KUIPA_KEYTAB=paths.KUIPA_KEYTAB,
            KUIPA_STATE_DIR=paths.KUIPA_STATE_DIR,
            IPA_CA_CRT=paths.IPA_CA_CRT,
            KDC_CA_BUNDLE_PEM=paths.KDC_CA_BUNDLE_PEM,
            IPA_CUSTODIA_HANDLER=paths.IPA_CUSTODIA_HANDLER,
        )

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "kuipad.json.template")
        conf = ipautil.template_file(template, sub_dict)

        if self.fstore:
            self.fstore.backup_file(paths.KUIPA_CONFIG)

        with open(paths.KUIPA_CONFIG, 'w') as f:
            f.write(conf)
            ipautil.flush_sync(f)
        # root-only: the file names the keytab and the key directory.
        os.chmod(paths.KUIPA_CONFIG, 0o600)

    def _generate_keys(self):
        """Create this server's anchor and realm keys in /var/lib/ipa/ku.

        kuipad 'serve' loads its keys before it binds the socket httpd
        proxies /ipa/ku to, so a server installed without them never serves
        it.  generate-keys refuses to overwrite existing keys, so only ask
        for them when they are missing -- a reinstalled server keeps its key
        material (see uninstall()).
        """
        if os.path.exists(os.path.join(paths.KUIPA_STATE_DIR, 'signing.jwk')):
            logger.info('kuipad keys already exist in %s',
                        paths.KUIPA_STATE_DIR)
            return

        result = ipautil.run([paths.KUIPAD, 'generate-keys'],
                             capture_output=True)
        logger.info('Created kuipad keys, anchor thumbprint %s',
                    result.output.strip())

    def _configure_httpd_proxy(self):
        sub_dict = dict(KUIPA_SOCKET=paths.KUIPA_SOCKET)

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ipa-kuipa-proxy.conf.template")
        conf = ipautil.template_file(template, sub_dict)

        if self.fstore:
            self.fstore.backup_file(paths.HTTPD_IPA_KUIPA_PROXY_CONF)

        with open(paths.HTTPD_IPA_KUIPA_PROXY_CONF, 'w') as f:
            f.write(conf)
            ipautil.flush_sync(f)
        os.chmod(paths.HTTPD_IPA_KUIPA_PROXY_CONF, 0o644)

    def uninstall(self):
        super(KuipadInstance, self).uninstall()

        for filepath in (paths.HTTPD_IPA_KUIPA_PROXY_CONF, paths.KUIPA_CONFIG):
            if self.fstore and self.fstore.has_file(filepath):
                self.fstore.restore_file(filepath)
            else:
                ipautil.remove_file(filepath)

        # /var/lib/ipa/ku keeps its key material: sealed realm keys outlive a
        # server uninstall, and nothing here backs that directory up.
        sysupgrade.set_upgrade_state('kuipa', 'installed', False)

    def upgrade_instance(self):
        installed = sysupgrade.get_upgrade_state("kuipa", "installed")
        if not installed:
            return

        self.fqdn = api.env.host
        self.realm = api.env.realm
        self.domain = api.env.domain

        if not os.path.isfile(paths.KUIPA_CONFIG):
            logger.warning("kuipad config is missing, forcing reinstallation")
            installed = False

        if not installed:
            logger.info("kuipad service is being configured")
            self.configure_instance(
                realm=self.realm,
                host_name=self.fqdn,
                domain=self.domain,
            )
        else:
            # The containers, the daemon group membership and the delegation
            # rule arrived with the IPAUpgrade run that precedes this.
            self._configure_kuipad()
            self._configure_httpd_proxy()
            logger.info("Restarting kuipad")
            self.restart()
            # Reload httpd so a rewritten ipa-kuipa-proxy.conf takes effect;
            # the daemon's restart alone does not pick up new proxy config.
            services.knownservices.httpd.reload_or_restart()


