# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.

from __future__ import absolute_import

import json
import logging
import os
import pwd
import shutil
import stat
import tempfile

from ipalib import api
from ipalib.kinit import kinit_keytab
from ipaplatform import services
from ipaplatform.base.constants import User
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipapython import ipautil, ipaldap
from ipapython.dn import DN
from ipaserver.install import sysupgrade
from ipaserver.install.service import SimpleServiceInstance, add_principals_to_group

logger = logging.getLogger(__name__)

KUIPA_USER = 'kuipad'


def _get_kuipa_user():
    try:
        return pwd.getpwnam(KUIPA_USER)
    except KeyError:
        raise RuntimeError(
            "System user '{}' does not exist. "
            "Ensure the kuipa-server package is installed.".format(KUIPA_USER))

def _migrate_state_directory(fd, user):
    info = os.fstat(fd)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("Unsafe legacy kuipad state directory")
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if info.st_uid != 0:
            raise RuntimeError("Unsafe legacy kuipad state entry")
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            try:
                _migrate_state_directory(child, user)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=fd)
            try:
                current = os.fstat(child)
                if (current.st_uid != 0 or not stat.S_ISREG(current.st_mode)
                        or current.st_nlink != 1):
                    raise RuntimeError("Unsafe legacy kuipad state entry")
                os.fchown(child, user.pw_uid, user.pw_gid)
            finally:
                os.close(child)
        else:
            raise RuntimeError("Unsafe legacy kuipad state entry")
    os.fchown(fd, user.pw_uid, user.pw_gid)


class KuipadInstance(SimpleServiceInstance):
    def __init__(self, fstore=None):
        super(KuipadInstance, self).__init__(
            "kuipad",
            service_desc="post-quantum enrollment daemon",
            fstore=fstore,
            service_prefix='ipa-ku',
            keytab=paths.KUIPA_KEYTAB,
            service_user=KUIPA_USER)
        self.keytab_user = User('root')
        self.fqdn = None
        self.realm = None
        self.domain = None

    def configure_instance(self, realm, host_name, domain, ldap_suffix=None):
        self.fqdn = host_name
        self.realm = realm
        self.domain = domain
        self.suffix = ldap_suffix or ipautil.realm_to_suffix(realm)

        self.step("creating kuipa containers", self._create_container)
        # Migrate an old keytab before handing the state directory to kuipad.
        self.step("configuring kuipad", self._configure_kuipad)
        self.step("setting up kuipad keytab", self.request_service_keytab)
        self.step("configuring gssproxy for kuipad", self._configure_gssproxy)
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
        self._enroll_host()
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
        """Secure existing state and configure the unprivileged daemon."""
        user = _get_kuipa_user()
        os.makedirs(paths.KUIPA_STATE_DIR, mode=0o700, exist_ok=True)
        state = os.open(paths.KUIPA_STATE_DIR,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            state_info = os.fstat(state)
            owner = state_info.st_uid
            if owner not in (0, user.pw_uid):
                raise RuntimeError("Unsafe kuipad state directory owner")
            if owner == 0 and state_info.st_mode & 0o022:
                raise RuntimeError("Unsafe legacy kuipad state directory")
            if owner != 0 and os.path.lexists(paths.KUIPA_KEYTAB):
                try:
                    os.unlink('kuipa.keytab', dir_fd=state)
                except FileNotFoundError:
                    pass
            try:
                legacy = os.open('kuipa.keytab', os.O_RDONLY | os.O_NOFOLLOW
                                 | os.O_NONBLOCK, dir_fd=state)
            except FileNotFoundError:
                legacy = None
            if legacy is not None:
                try:
                    info = os.fstat(legacy)
                    if (owner != 0 or info.st_uid != 0
                            or not stat.S_ISREG(info.st_mode)
                            or info.st_nlink != 1):
                        raise RuntimeError("Unsafe legacy kuipad keytab")
                    if not os.path.exists(paths.KUIPA_KEYTAB):
                        with os.fdopen(os.dup(legacy), 'rb') as source:
                            with tempfile.NamedTemporaryFile(
                                    dir=os.path.dirname(paths.KUIPA_KEYTAB),
                                    delete=False) as target:
                                try:
                                    shutil.copyfileobj(source, target)
                                    ipautil.flush_sync(target)
                                    os.replace(target.name, paths.KUIPA_KEYTAB)
                                except BaseException:
                                    ipautil.remove_file(target.name)
                                    raise
                    os.unlink('kuipa.keytab', dir_fd=state)
                finally:
                    os.close(legacy)
            if owner == 0:
                _migrate_state_directory(state, user)
            os.fchmod(state, 0o700)
        finally:
            os.close(state)

        try:
            keytab = os.open(paths.KUIPA_KEYTAB, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            pass
        else:
            try:
                if not stat.S_ISREG(os.fstat(keytab).st_mode):
                    raise RuntimeError("Unsafe kuipad keytab")
                os.fchown(keytab, 0, 0)
                os.fchmod(keytab, 0o600)
            finally:
                os.close(keytab)
            tasks.restore_context(paths.KUIPA_KEYTAB)

        sub_dict = dict(
            REALM=self.realm,
            DOMAIN=self.domain,
            BASEDN=str(self.suffix),
            FQDN=self.fqdn,
            LDAP_URI=ipaldap.realm_to_ldapi_uri(self.realm),
            KUIPA_KEYTAB=paths.KUIPA_KEYTAB,
            KUIPA_KEYS_SOCKET=paths.KUIPA_KEYS_SOCKET,
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
        os.chown(paths.KUIPA_CONFIG, 0, user.pw_gid)
        os.chmod(paths.KUIPA_CONFIG, 0o640)

    def request_service_keytab(self):
        if os.path.islink(paths.KUIPA_KEYTAB):
            os.unlink(paths.KUIPA_KEYTAB)
        super(KuipadInstance, self).request_service_keytab()
        fd = os.open(paths.KUIPA_KEYTAB, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        tasks.restore_context(paths.KUIPA_KEYTAB)

    def _configure_gssproxy(self):
        user = _get_kuipa_user()
        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "kuipad-gssproxy.conf.template")
        conf = ipautil.template_file(template, {
            'KUIPA_KEYTAB': paths.KUIPA_KEYTAB,
            'KUIPA_USER': user.pw_uid,
        })
        if self.fstore:
            self.fstore.backup_file(paths.KUIPA_GSSPROXY_CONF)
        with open(paths.KUIPA_GSSPROXY_CONF, 'w') as f:
            f.write(conf)
            ipautil.flush_sync(f)
        os.chmod(paths.KUIPA_GSSPROXY_CONF, 0o644)
        services.knownservices.gssproxy.restart()

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
                             capture_output=True, runas=KUIPA_USER)
        logger.info('Created kuipad keys, anchor thumbprint %s',
                    result.output.strip())

    def _enroll_host(self):
        if os.path.exists(paths.KUIPA_CLIENT_STATE):
            with open(paths.KUIPA_CLIENT_STATE) as f:
                state = json.load(f)
            if state.get('realm') != self.realm or state.get('fqdn') != self.fqdn:
                raise RuntimeError('Existing kuipa enrollment belongs to another host or realm')
            return

        service_principal = 'host/{}@{}'.format(self.fqdn, self.realm)
        enrollment = ipautil.run(
            [paths.KUIPAD, 'enrollment-string'], capture_output=True
        ).output.strip()
        with tempfile.TemporaryDirectory(prefix='ipa-kuipa-enroll-') as directory:
            ccache = 'FILE:' + os.path.join(directory, 'ccache')
            kinit_keytab(service_principal, paths.KRB5_KEYTAB, ccache)
            env = os.environ.copy()
            env['KRB5CCNAME'] = ccache
            for name in ('KRB5_CONFIG', 'KUIPA_ROOT', 'KUIPA_KDC'):
                env.pop(name, None)
            ipautil.run([
                paths.KUIPA, 'enroll', '--enrollment-file', '-', '--use-ccache',
                '--server', self.fqdn, '--hostname', self.fqdn, '--domain', self.domain,
            ], stdin=enrollment + '\n', env=env)

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

        for filepath in (paths.HTTPD_IPA_KUIPA_PROXY_CONF,
                         paths.KUIPA_GSSPROXY_CONF, paths.KUIPA_CONFIG):
            if self.fstore and self.fstore.has_file(filepath):
                self.fstore.restore_file(filepath)
            else:
                ipautil.remove_file(filepath)
        services.knownservices.gssproxy.restart()

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
        self.suffix = ipautil.realm_to_suffix(self.realm)

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
            self.stop()
            self._configure_kuipad()
            self._configure_gssproxy()
            self._configure_httpd_proxy()
            logger.info("Restarting kuipad")
            self.restart()
            # Reload httpd so a rewritten ipa-kuipa-proxy.conf takes effect;
            # the daemon's restart alone does not pick up new proxy config.
            services.knownservices.httpd.reload_or_restart()
            self._enroll_host()


