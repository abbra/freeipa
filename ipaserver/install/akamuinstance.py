# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.

from __future__ import absolute_import

import base64
import logging
import os
import pwd
import secrets
import tempfile

import ipalib.constants
from ipalib import api, x509
from ipalib.install import certmonger
from ipaplatform import services
from ipaplatform.constants import constants as platformconstants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipaserver.install import certs, sysupgrade
from ipaserver.install.service import SimpleServiceInstance
from ipapython import dogtag, ipautil
from ipapython.certdb import IPA_CA_TRUST_FLAGS, EMPTY_TRUST_FLAGS
from ipapython.dn import DN

logger = logging.getLogger(__name__)

AKAMU_USER = 'akamu'
AKAMU_RA_UID = 'akamu-ra'
AKAMU_RA_SUBJECT_CN = 'Akamu RA'
ROLE_NAME = 'Akamu Services'


def _get_akamu_user():
    try:
        return pwd.getpwnam(AKAMU_USER)
    except KeyError:
        raise RuntimeError(
            "System user '{}' does not exist. "
            "Ensure the akamu package is installed.".format(AKAMU_USER))


# ---------------------------------------------------------------------------
# RA-agent identity + certificate provisioning.
#
# These are scheduled as CAInstance steps (see cainstance.py's
# configure_instance()), not as part of AkamuInstance.configure_instance():
# they only need Dogtag/LDAP, which is already up at that point, unlike the
# rest of the Akamu service, which additionally needs HTTP_KEYTAB/httpd/
# gssproxy to exist first.
# ---------------------------------------------------------------------------

def _ensure_akamu_state_dir():
    # The akamu package's own tmpfiles.d normally creates this with the
    # right ownership well before install runs, but request_ra_certificate()
    # can run this early (as part of CAInstance.configure_instance(), before
    # AkamuInstance's own steps ever touch this directory), so don't rely
    # on that alone.
    akamu_pw = _get_akamu_user()
    os.makedirs(paths.AKAMU_STATE_DIR, mode=0o750, exist_ok=True)
    os.chown(paths.AKAMU_STATE_DIR, akamu_pw.pw_uid, akamu_pw.pw_gid)


def request_ra_certificate(ca):
    """Request the Akamu RA certificate from Dogtag.

    Mirrors CAInstance.__request_ra_certificate() almost verbatim,
    substituting the Akamu RA's own subject and output paths. Must run
    after Dogtag is started, and only on the first (non-clone) CA server.

    :param ca: the CAInstance performing a non-clone install/upgrade
    """
    _ensure_akamu_state_dir()
    try:
        chain = dogtag.get_ca_certchain(ca_host=ca.fqdn)
    except Exception as e:
        raise RuntimeError("Unable to retrieve CA chain: %s" % str(e))

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdb = certs.CertDB(ca.realm, nssdir=tmpdir)
        chain_file = os.path.join(tmpdir, "chain.pem")

        data = base64.b64decode(chain)
        ipautil.run(
            [paths.OPENSSL, "pkcs7", "-inform", "DER", "-print_certs",
             "-out", chain_file], stdin=data, capture_output=False)

        tmpdb.create_noise_file()
        tmpdb.create_passwd_file()
        tmpdb.create_certdbs()
        tmpdb.load_cacert(chain_file, IPA_CA_TRUST_FLAGS)

        tmpdb.import_pkcs12(
            paths.DOGTAG_ADMIN_P12, pkcs12_passwd=ca.dm_password)

        (keytype, keysize) = certs.get_key_type_and_strength(
            api.env.key_type_size)
        if keytype == "mldsa":
            keysize = f"ML-DSA-{keysize}"

        csrfile = os.path.join(tmpdb.secdir, "csr")
        cmd = [
            paths.CERTUTIL, "-d", tmpdb.secdir, "-R",
            "-s", str(DN(('CN', AKAMU_RA_SUBJECT_CN), ca.subject_base)),
            "-k", keytype,
            "-z", os.path.join(tmpdb.secdir, tmpdb.noise_fname),
            "-f", tmpdb.passwd_fname, "-o", csrfile, "-a"]
        if keytype.lower() == 'rsa':
            cmd.extend(["-g", keysize])
        else:
            cmd.extend(["-q", keysize])
        ipautil.run(cmd)

        tmpdb.pki_issue_ra_certificate(
            csrfile=csrfile, certfile=paths.AKAMU_RA_AGENT_PEM,
            dm_password=ca.dm_password)

        cert = x509.load_certificate_from_file(paths.AKAMU_RA_AGENT_PEM)
        tmpdb.add_cert(cert, AKAMU_RA_SUBJECT_CN, EMPTY_TRUST_FLAGS)
        pk12_pwdfile = ipautil.write_tmp_file(ca.dm_password)
        tmpdb.export_pkcs12(
            os.path.join(tmpdb.secdir, "akamu-ra.p12"),
            pk12_pwdfile.name, AKAMU_RA_SUBJECT_CN)
        certs.install_key_from_p12(
            os.path.join(tmpdb.secdir, "akamu-ra.p12"),
            ca.dm_password, paths.AKAMU_RA_AGENT_KEY)

    _create_akamu_ra_agent(ca, cert)
    _set_akamu_ra_cert_perms()
    # Deferred import: cainstance.py imports akamuinstance (for the
    # __request_akamu_ra_certificate/__import_akamu_ra_key steps) too, so
    # a module-level import here would be a real circular import.
    # pylint: disable-next=cyclic-import
    from ipaserver.install import cainstance
    cainstance.update_people_entry(cert)
    configure_agent_renewal()


def _create_akamu_ra_agent(ca, cert):
    """Create uid=akamu-ra under o=ipaca and join the two Dogtag agent
    groups that AgentCertAuth recognizes for mutual-TLS agent auth.

    Deliberately omits "Security Domain Administrators" -- ipara needs it
    for domain-level operations Akamu never performs.
    """
    conn = api.Backend.ldap2
    user_dn = DN(('uid', AKAMU_RA_UID), ('ou', 'People'), ca.basedn)
    entry = conn.make_entry(
        user_dn,
        objectClass=['top', 'person', 'organizationalPerson',
                     'inetOrgPerson', 'cmsuser'],
        uid=[AKAMU_RA_UID],
        sn=[AKAMU_RA_UID],
        cn=[AKAMU_RA_UID],
        usertype=["agentType"],
        userstate=["1"],
        userCertificate=[cert],
        description=['2;%s;%s;%s' % (
            cert.serial_number,
            DN(ca.ca_subject),
            DN(('CN', AKAMU_RA_SUBJECT_CN), ca.subject_base))])
    conn.add_entry(entry)

    for group_cn in ('Certificate Manager Agents',
                     'Registration Manager Agents'):
        group_dn = DN(('cn', group_cn), ('ou', 'groups'), ca.basedn)
        conn.add_entry_to_group(user_dn, group_dn, 'uniqueMember')


def _set_akamu_ra_cert_perms():
    # Unlike ipara's RA cert (read by IPA's own Python code, hence group
    # ipaapi), this cert/key is read exclusively by the akamu daemon
    # itself, so akamu must own it outright.
    akamu_pw = _get_akamu_user()
    for fname in (paths.AKAMU_RA_AGENT_PEM, paths.AKAMU_RA_AGENT_KEY):
        os.chown(fname, akamu_pw.pw_uid, akamu_pw.pw_gid)
        os.chmod(fname, 0o400)
        tasks.restore_context(fname)


def configure_agent_renewal():
    try:
        certmonger.start_tracking(
            certpath=(paths.AKAMU_RA_AGENT_PEM, paths.AKAMU_RA_AGENT_KEY),
            ca=ipalib.constants.RENEWAL_CA_NAME,
            profile=ipalib.constants.RA_AGENT_PROFILE,
            pre_command='renew_akamu_ra_cert_pre',
            post_command='renew_akamu_ra_cert',
            storage='FILE')
    except RuntimeError as e:
        logger.error(
            "certmonger failed to start tracking Akamu RA certificate: %s",
            e)


def import_ra_key(custodia):
    """Fetch the shared akamu-ra PEM cert+key via Custodia."""
    _ensure_akamu_state_dir()
    custodia.import_akamu_ra_key()
    _set_akamu_ra_cert_perms()
    configure_agent_renewal()


# ---------------------------------------------------------------------------
# The Akamu service instance: container LDIF, config.toml, gssproxy conf,
# httpd proxy conf, daemon start. Wired from server/install.py and
# server/replicainstall.py, not from CAInstance.configure_instance() --
# httpd/HTTP_KEYTAB don't exist yet at that point on a fresh master install.
# ---------------------------------------------------------------------------

class AkamuInstance(SimpleServiceInstance):
    def __init__(self, fstore=None):
        super(AkamuInstance, self).__init__("akamu")
        self.fstore = fstore
        self.fqdn = None
        self.realm = None
        self.domain = None

    def configure_instance(self, realm, host_name, domain, ldap_suffix=None):
        self.fqdn = host_name
        self.realm = realm
        self.domain = domain

        self.step("creating akamu container", self._create_container)
        self.step("granting akamu service role membership",
                  self._configure_grants)
        self.step("configuring akamu", self._configure_akamu)
        self.step("configuring gssproxy for akamu", self._configure_gssproxy)
        self.step("configuring httpd proxy for akamu",
                  self._configure_httpd_proxy)
        self.step("granting httpd access to the akamu socket",
                  self._configure_socket_group)

        super(AkamuInstance, self).create_instance(
            gensvc_name='AKAMU',
            fqdn=self.fqdn,
            ldap_suffix=ldap_suffix or ipautil.realm_to_suffix(self.realm),
            realm=self.realm
        )
        # httpd already has ipa-akamu-proxy.conf on disk (written by
        # _configure_httpd_proxy above), but won't proxy /akamu until
        # reloaded; wait for akamu's socket first so httpd doesn't proxy
        # to it before it's actually listening.
        ipautil.wait_for_open_socket(paths.AKAMU_SOCKET, timeout=60)
        services.knownservices.httpd.reload_or_restart()
        sysupgrade.set_upgrade_state('akamu', 'installed', True)

    def _create_container(self):
        self._ldap_update(['79-akamu.update'])

    def _configure_grants(self):
        service = 'HTTP/{}@{}'.format(self.fqdn, self.realm)
        api.Command.role_add_member(ROLE_NAME, service=[service])

    def _write_secure(self, path, content, akamu_pw):
        fd = os.open(path,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchown(fd, akamu_pw.pw_uid, akamu_pw.pw_gid)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

    def _get_eab_master_secret(self, akamu_pw):
        """Read back a previously-generated EAB master secret, or generate
        and persist a new one. Never rotate an existing secret -- every
        already-registered ACME account's Kerberos-derived EAB credential
        depends on it staying stable across reconfigure/upgrade runs."""
        if os.path.isfile(paths.AKAMU_EAB_MASTER_SECRET):
            with open(paths.AKAMU_EAB_MASTER_SECRET) as f:
                secret = f.read().strip()
            if secret:
                return secret
            logger.warning(
                "%s is empty; generating a new EAB master secret",
                paths.AKAMU_EAB_MASTER_SECRET)

        secret = secrets.token_hex(32)
        os.makedirs(paths.AKAMU_STATE_DIR, mode=0o750, exist_ok=True)
        self._write_secure(paths.AKAMU_EAB_MASTER_SECRET, secret, akamu_pw)
        os.chown(paths.AKAMU_STATE_DIR, akamu_pw.pw_uid, akamu_pw.pw_gid)
        return secret

    def _configure_akamu(self):
        akamu_pw = _get_akamu_user()
        eab_secret = self._get_eab_master_secret(akamu_pw)

        sub_dict = dict(
            REALM=self.realm,
            FQDN=self.fqdn,
            DOMAIN=self.domain,
            AKAMU_SOCKET=paths.AKAMU_SOCKET,
            AKAMU_STATE_DIR=paths.AKAMU_STATE_DIR,
            AKAMU_RA_AGENT_PEM=paths.AKAMU_RA_AGENT_PEM,
            AKAMU_RA_AGENT_KEY=paths.AKAMU_RA_AGENT_KEY,
            IPA_CA_CRT=paths.IPA_CA_CRT,
            EAB_MASTER_SECRET=eab_secret,
            AKAMU_WEBUI_DIR=paths.AKAMU_WEBUI_DIR,
        )

        os.makedirs(paths.AKAMU_CONF_DIR, mode=0o750, exist_ok=True)

        if self.fstore:
            self.fstore.backup_file(paths.AKAMU_CONF)

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "akamu.toml.template")
        conf = ipautil.template_file(template, sub_dict)
        self._write_secure(paths.AKAMU_CONF, conf, akamu_pw)

        os.chown(paths.AKAMU_CONF_DIR, akamu_pw.pw_uid, akamu_pw.pw_gid)

    def _configure_gssproxy(self):
        akamu_pw = _get_akamu_user()

        sub_dict = dict(
            HTTP_KEYTAB=paths.HTTP_KEYTAB,
            AKAMU_USER=str(akamu_pw.pw_uid),
        )

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "akamu-gssproxy.conf.template")
        conf = ipautil.template_file(template, sub_dict)

        if self.fstore:
            self.fstore.backup_file(paths.AKAMU_GSSPROXY_CONF)

        with open(paths.AKAMU_GSSPROXY_CONF, 'w') as f:
            f.write(conf)
            ipautil.flush_sync(f)
        os.chmod(paths.AKAMU_GSSPROXY_CONF, 0o644)

        services.knownservices.gssproxy.restart()

    def _configure_httpd_proxy(self):
        sub_dict = dict(
            AKAMU_SOCKET=paths.AKAMU_SOCKET,
        )

        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ipa-akamu-proxy.conf.template")
        conf = ipautil.template_file(template, sub_dict)

        if self.fstore:
            self.fstore.backup_file(paths.HTTPD_IPA_AKAMU_PROXY_CONF)

        with open(paths.HTTPD_IPA_AKAMU_PROXY_CONF, 'w') as f:
            f.write(conf)
            ipautil.flush_sync(f)
        os.chmod(paths.HTTPD_IPA_AKAMU_PROXY_CONF, 0o644)

    def _configure_socket_group(self):
        # Akamu's Unix socket is owned by akamu:akamu (SocketGroup=akamu in
        # its systemd unit); httpd needs group membership to connect to it
        # via mod_proxy. "usermod -a -G" is idempotent.
        ipautil.run([
            paths.USERMOD, '-a', '-G', AKAMU_USER,
            str(platformconstants.HTTPD_USER)])

    def uninstall(self):
        super(AkamuInstance, self).uninstall()

        try:
            certmonger.stop_tracking(certfile=paths.AKAMU_RA_AGENT_PEM)
        except RuntimeError as e:
            logger.error(
                "certmonger failed to stop tracking the Akamu RA "
                "certificate: %s", e)
        ipautil.remove_file(paths.AKAMU_RA_AGENT_PEM)
        ipautil.remove_file(paths.AKAMU_RA_AGENT_KEY)

        for filepath in (paths.HTTPD_IPA_AKAMU_PROXY_CONF,
                         paths.AKAMU_GSSPROXY_CONF,
                         paths.AKAMU_CONF):
            if self.fstore and self.fstore.has_file(filepath):
                self.fstore.restore_file(filepath)
            else:
                ipautil.remove_file(filepath)

        sysupgrade.set_upgrade_state('akamu', 'installed', False)

    def upgrade_instance(self, ca=None, custodia=None):
        """Bring Akamu onto a pre-existing CA-enabled server (UC5).

        :param ca: a configured CAInstance for this host, or None if this
            host doesn't have the CA role
        :param custodia: a CustodiaInstance constructed with a peer (the
            CA renewal master), used to fetch the RA cert when this host
            isn't the renewal master and doesn't have a local copy yet
        """
        if ca is None or not ca.is_configured():
            return  # not (or no longer) a CA host: nothing to do

        installed = sysupgrade.get_upgrade_state("akamu", "installed")
        if installed and not os.path.isfile(paths.AKAMU_CONF):
            logger.warning(
                "akamu config is missing, forcing reinstallation")
            installed = False

        self.fqdn = api.env.host
        self.realm = api.env.realm
        self.domain = api.env.domain

        if not installed:
            if not os.path.isfile(paths.AKAMU_RA_AGENT_PEM):
                if ca.is_renewal_master():
                    request_ra_certificate(ca)
                elif custodia is not None:
                    import_ra_key(custodia)
                else:
                    logger.warning(
                        "No Custodia peer available; deferring Akamu "
                        "deployment to the next upgrade run")
                    return

            self.configure_instance(self.realm, self.fqdn, self.domain)
        else:
            self._configure_akamu()
            self._configure_gssproxy()
            self._configure_httpd_proxy()
            logger.info("Restarting akamu")
            self.restart()
