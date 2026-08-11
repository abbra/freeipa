# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
from __future__ import absolute_import

import base64
import datetime
import hashlib
import json
import logging
import os
import secrets
import ssl

import requests

from ipalib import Bool, Bytes, Int, Str, StrEnum, _
from ipalib import errors
from ipalib import output
from ipalib import x509
from ipalib.install import certstore
from ipalib.plugable import Registry
from ipaplatform.paths import paths
from .virtual import VirtualCommand
from ipapython.cms_kem import (
    generate_kem_keypair,
    generate_signing_keypair,
    kem_private_key_from_bytes,
    kem_public_key_from_bytes,
    open_and_verify,
    seal,
    UnsealError,
)
from ipapython.dn import DN

__doc__ = _("""
Bootstrap IPA-IPA trust credentials via CMS(ML-KEM) envelope exchange.

See doc/designs/ipa_to_ipa_trust.md, section "Bootstrapping authentication
via OAuth2 and CMS(ML-KEM)" for the full protocol description.

Three commands implement the exchange:

* trust_bootstrap_init: run by the requesting side (A). Generates a
  one-time ML-KEM keypair and returns it -- nothing is persisted
  server-side, so a later trust_bootstrap_retrieve works regardless of
  which replica served this call.
* trust_bootstrap_prepare: run by the providing side (B), already
  authenticated to its own realm by whatever means it normally uses
  (including Ahdapa OAuth2 SSO). Given A's ML-KEM public key, seals B's
  realm/CA-chain/shared-secret to it, stores the sealed blob under a
  one-time retrieval token, and immediately configures B's own half of
  the trust locally.
* trust_bootstrap_retrieve: run by the requesting side (A). Fetches the
  sealed blob from B's anonymous token-gated endpoint, opens it with the
  ML-KEM private key from trust_bootstrap_init, imports B's CA chain, and
  configures A's own half of the trust locally.
""")

logger = logging.getLogger(__name__)

register = Registry()

_KEM_PARAMETER_SETS = (u'ML-KEM-768', u'ML-KEM-1024')
_SIGNATURE_ALGORITHMS = (u'RSA', u'EC', u'ML-DSA')
_TRUST_ADD_PASSTHROUGH = ('base_id', 'range_size', 'range_type')
_FETCH_TIMEOUT = 30


def _log_tofu_peer_certificate(hostname, port=443):
    """Fetch and log the fingerprint of a host's TLS certificate.

    This is called right before an intentionally verify=False HTTPS
    request to that same host, where verification is impossible by
    design (there is no CA chain for the peer yet -- that is exactly
    what this exchange bootstraps). It does not make the connection
    trustworthy; it only ensures the accepted certificate is recorded
    somewhere an administrator can audit or cross-check out of band,
    instead of being silently and untraceably accepted.
    """
    try:
        der = ssl.get_server_certificate((hostname, port)).encode('ascii')
    except (ssl.SSLError, OSError) as e:
        logger.warning(
            "trust-bootstrap-retrieve: could not fetch %s's TLS "
            "certificate for audit logging: %s", hostname, e)
        return
    fingerprint = hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(der.decode('ascii'))).hexdigest()
    logger.warning(
        "trust-bootstrap-retrieve: accepting %s's TLS certificate on "
        "first use (no CA chain established yet) with SHA-256 "
        "fingerprint %s -- the retrieval token's entropy/TTL/single-use "
        "is the actual security boundary for this request, not this "
        "certificate; cross-check the fingerprint out of band if in "
        "doubt.", hostname, fingerprint)


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _unb64(data):
    return base64.b64decode(data)


def _get_kdc_ca_chain():
    """The CA chain that actually backs *this* server's KDC PKINIT
    certificate.

    This is deliberately not certstore.get_ca_certs() (the general,
    deployment-wide IPA CA store): PKINIT configuration is per-server, not
    per-realm -- a master or replica can have its KDC certificate
    self-signed, IPA-CA-issued, or externally-issued (ipa-server-certinstall
    -k) independently of any other server in the same deployment, and the
    general CA store doesn't reflect any of that. paths.CACERT_PEM is the
    one artifact tied to *this* krb5kdc's actual pkinit_anchors
    configuration (ipaserver/install/krbinstance.py's
    _install_pkinit_ca_bundle/issue_selfsigned_pkinit_certs, install/share/
    kdc.conf.template) -- it is written on every master/replica during
    install, kept current by ipa-certupdate, and explicitly emptied when
    this server's KDC certificate is self-signed.
    """
    if not os.path.exists(paths.CACERT_PEM):
        raise errors.NotFound(
            reason=_(
                "this server's KDC has no PKINIT CA chain configured "
                "(paths.CACERT_PEM is missing) -- the remote deployment "
                "would have no way to validate this server's KDC "
                "certificate; run ipa-pkinit-manage enable or use a "
                "PKINIT-enabled server for trust-bootstrap-prepare"))
    ca_certs = x509.load_certificate_list_from_file(paths.CACERT_PEM)
    if not ca_certs:
        raise errors.NotFound(
            reason=_(
                "this server's KDC PKINIT CA chain (paths.CACERT_PEM) is "
                "empty -- its KDC certificate is likely self-signed; the "
                "remote deployment would have no way to validate it. Use "
                "a PKINIT-enabled server for trust-bootstrap-prepare"))
    return ca_certs


def _get_realm_ca_chain(ldap, basedn, realm):
    """The deployment-wide IPA CA chain (used for HTTPS/LDAP trust
    generally), as opposed to _get_kdc_ca_chain()'s per-server
    PKINIT-specific one -- the two are usually the same chain but are not
    guaranteed to be, see doc/designs/ipa_to_ipa_trust.md.
    """
    ca_certs = certstore.get_ca_certs(ldap, basedn, realm, False)
    return [cert for cert, _nick, trusted, _eku, _serial in ca_certs
            if trusted is not False]


@register()
class trust_bootstrap_init(VirtualCommand):
    __doc__ = _(
        'Generate a one-time ML-KEM keypair to bootstrap trust with another '
        'IPA deployment. Save the returned private key; it must be passed '
        'back to trust-bootstrap-retrieve once the other side has prepared '
        'a bootstrap package for it. The public key is meant to be handed, '
        'out of band, to an administrator of the other IPA deployment.'
    )

    operation = "trust bootstrap init"

    takes_options = (
        StrEnum(
            'kem_parameter_set?',
            cli_name='kem_parameter_set',
            label=_('ML-KEM parameter set'),
            values=_KEM_PARAMETER_SETS,
            default=u'ML-KEM-768',
            autofill=True,
        ),
    )

    def execute(self, *args, **options):
        self.check_access()

        parameter_set = options['kem_parameter_set']
        private_key, public_key = generate_kem_keypair(parameter_set)

        return dict(result=dict(
            kem_parameter_set=parameter_set,
            public_key=_b64(public_key.public_bytes_raw()),
            private_key=_b64(private_key.private_bytes_raw()),
        ))


@register()
class trust_bootstrap_prepare(VirtualCommand):
    __doc__ = _(
        'Prepare a sealed trust bootstrap package for another IPA '
        'deployment and configure this side\'s half of the trust. Run '
        'this after receiving an ML-KEM public key (from '
        'trust-bootstrap-init on the other side) out of band. Relay the '
        'returned token, and this server\'s hostname, back to the other '
        'side out of band so it can run trust-bootstrap-retrieve.'
    )

    operation = "trust bootstrap prepare"

    takes_args = (
        Str(
            'remote_domain',
            cli_name='remote_domain',
            label=_('Remote IPA domain'),
            doc=_('DNS domain name of the requesting IPA deployment'),
        ),
    )

    takes_options = (
        Bytes(
            'remote_kem_public_key',
            cli_name='remote_kem_public_key',
            label=_('Remote ML-KEM public key'),
            doc=_('ML-KEM public key produced by trust-bootstrap-init on '
                  'the requesting side'),
        ),
        StrEnum(
            'kem_parameter_set?',
            cli_name='kem_parameter_set',
            label=_('ML-KEM parameter set'),
            doc=_('Must match the parameter set the requester used'),
            values=_KEM_PARAMETER_SETS,
            default=u'ML-KEM-768',
            autofill=True,
        ),
        StrEnum(
            'signature_algorithm?',
            cli_name='signature_algorithm',
            label=_('Signing algorithm'),
            values=_SIGNATURE_ALGORITHMS,
            default=u'EC',
            autofill=True,
        ),
        Int(
            'ttl?',
            cli_name='ttl',
            label=_('Token time-to-live in seconds'),
            default=3600,
            autofill=True,
            minvalue=60,
        ),
        Bool(
            'bidirectional?',
            cli_name='two_way',
            label=_('Two-way trust'),
            default=False,
        ),
        Int('base_id?', cli_name='base_id',
            label=_('First Posix ID of the range reserved for the '
                    'trusted domain')),
        Int('range_size?', cli_name='range_size',
            label=_('Size of the ID range reserved for the trusted '
                    'domain')),
        StrEnum('range_type?', cli_name='range_type',
                label=_('Range type'),
                values=(u'ipa-ad-trust-posix',)),
    )

    def execute(self, *args, **options):
        self.check_access()

        remote_domain = args[0]
        parameter_set = options['kem_parameter_set']
        kem_pub = kem_public_key_from_bytes(
            parameter_set, options['remote_kem_public_key'])

        ldap = self.api.Backend.ldap2
        kdc_ca_ders = [
            cert.public_bytes(x509.Encoding.DER)
            for cert in _get_kdc_ca_chain()
        ]
        realm_ca_ders = [
            cert.public_bytes(x509.Encoding.DER)
            for cert in _get_realm_ca_chain(
                ldap, self.api.env.basedn, self.api.env.realm)
        ]

        trust_secret = secrets.token_urlsafe(32)

        payload_dict = dict(
            realm=self.api.env.realm,
            domain=self.api.env.domain,
            server=self.api.env.host,
            trust_secret=trust_secret,
            kdc_ca_certs=[_b64(der) for der in kdc_ca_ders],
        )
        # The KDC/PKINIT chain and the general realm-wide IPA CA chain are
        # the same in the common case (a KDC certificate issued by the
        # deployment's own IPA CA). Only send the realm-wide chain
        # separately when it actually differs -- otherwise the KDC chain
        # already covers both purposes once imported (see
        # trust_bootstrap_retrieve and doc/designs/ipa_to_ipa_trust.md).
        if realm_ca_ders and set(realm_ca_ders) != set(kdc_ca_ders):
            payload_dict['realm_ca_certs'] = [
                _b64(der) for der in realm_ca_ders]

        payload = json.dumps(payload_dict).encode('utf-8')

        signing_private_key, signing_cert = generate_signing_keypair(
            options['signature_algorithm'])
        sealed = seal(
            payload, kem_pub, signing_private_key, signing_cert,
            parameter_set)

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode('ascii')).hexdigest()
        expires = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=options['ttl'])
        )

        entry_dn = DN(
            ('cn', token_hash), ('cn', 'trust bootstrap'), ('cn', 'ipa'),
            ('cn', 'etc'), self.api.env.basedn)
        entry = ldap.make_entry(
            entry_dn,
            objectclass=['top', 'ipatrustbootstraprequest'],
            cn=[token_hash],
            ipatrustbootstrapciphertext=[sealed],
            ipatrustbootstrapexpires=[expires],
        )
        ldap.add_entry(entry)

        trust_add_kw = dict(
            trust_type=u'ipa',
            trust_secret=trust_secret,
            bidirectional=options.get('bidirectional', False),
        )
        for opt in _TRUST_ADD_PASSTHROUGH:
            if opt in options:
                trust_add_kw[opt] = options[opt]
        self.api.Command.trust_add(remote_domain, **trust_add_kw)

        return dict(result=dict(
            token=token,
            server=self.api.env.host,
        ))


@register()
class trust_bootstrap_retrieve(VirtualCommand):
    __doc__ = _(
        'Fetch a sealed trust bootstrap package prepared by another IPA '
        'deployment via trust-bootstrap-prepare, and configure this '
        'side\'s half of the trust.'
    )

    operation = "trust bootstrap retrieve"

    has_output = ('result', output.summary)

    takes_options = (
        Str(
            'server',
            cli_name='server',
            label=_('Remote server'),
            doc=_('Hostname of the IPA server that prepared the package'),
        ),
        Str(
            'token',
            cli_name='token',
            label=_('Retrieval token'),
        ),
        Bytes(
            'kem_private_key',
            cli_name='kem_private_key',
            label=_('ML-KEM private key'),
            doc=_('Private key produced by trust-bootstrap-init'),
        ),
        StrEnum(
            'kem_parameter_set?',
            cli_name='kem_parameter_set',
            label=_('ML-KEM parameter set'),
            doc=_('Must match the parameter set used with '
                  'trust-bootstrap-init'),
            values=_KEM_PARAMETER_SETS,
            default=u'ML-KEM-768',
            autofill=True,
        ),
        Bool(
            'bidirectional?',
            cli_name='two_way',
            label=_('Two-way trust'),
            default=False,
        ),
        Int('base_id?', cli_name='base_id',
            label=_('First Posix ID of the range reserved for the '
                    'trusted domain')),
        Int('range_size?', cli_name='range_size',
            label=_('Size of the ID range reserved for the trusted '
                    'domain')),
        StrEnum('range_type?', cli_name='range_type',
                label=_('Range type'),
                values=(u'ipa-ad-trust-posix',)),
    )

    def execute(self, *args, **options):
        self.check_access()

        url = 'https://%s/ipa/session/trust_bootstrap_fetch' % (
            options['server'],)
        # The remote server's CA chain is exactly what this exchange is
        # meant to deliver -- there is nothing to validate the TLS
        # certificate against yet, so `verify=False` here is deliberate,
        # not an oversight (see doc/designs/ipa_to_ipa_trust.md). Record
        # what certificate was accepted so it isn't a silent trust
        # decision, even though it isn't independently verified either.
        _log_tofu_peer_certificate(options['server'])
        try:
            response = requests.get(
                url, params={'token': options['token']},
                verify=False, timeout=_FETCH_TIMEOUT)
        except requests.exceptions.RequestException as e:
            raise errors.NetworkError(uri=url, error=str(e))

        if response.status_code != 200:
            raise errors.NotFound(
                reason=_('trust bootstrap package not found, expired, or '
                         'already retrieved'))

        parameter_set = options['kem_parameter_set']
        kem_private_key = kem_private_key_from_bytes(
            parameter_set, options['kem_private_key'])

        try:
            plaintext, _signing_cert = open_and_verify(
                response.content, kem_private_key)
        except UnsealError as e:
            raise errors.ValidationError(
                name=_('sealed package'),
                error=_('could not open the trust bootstrap package: '
                        '%s') % (e,))

        payload = json.loads(plaintext.decode('utf-8'))

        ldap = self.api.Backend.ldap2
        for index, b64_der in enumerate(payload['kdc_ca_certs']):
            cert = x509.load_der_x509_certificate(_unb64(b64_der))
            nickname = '%s IPA KDC CA %d' % (payload['realm'], index)
            # Mark the chain as good for validating PKINIT/KDC
            # certificates issued within the trusted realm, not just for
            # generic TLS/LDAP trust -- this is what ipa-cacert-manage
            # install's "-t ...,CT" flag does for a manually-imported
            # foreign CA (ipaserver/install/ipa_cacert_manage.py). This
            # does not narrow the cert to PKINIT-only use: it remains a
            # generally trusted CA (trusted=True) as well.
            certstore.put_ca_cert(
                ldap, self.api.env.basedn, cert, nickname, trusted=True,
                ext_key_usage={
                    x509.EKU_PKINIT_KDC, x509.EKU_PKINIT_CLIENT_AUTH})

        # Sent separately by trust-bootstrap-prepare only when it differs
        # from the KDC/PKINIT chain above -- see _get_realm_ca_chain() and
        # doc/designs/ipa_to_ipa_trust.md. When absent, the KDC chain
        # already covers general realm-wide trust too.
        realm_ca_certs = payload.get('realm_ca_certs', [])
        for index, b64_der in enumerate(realm_ca_certs):
            cert = x509.load_der_x509_certificate(_unb64(b64_der))
            nickname = '%s IPA CA %d' % (payload['realm'], index)
            certstore.put_ca_cert(
                ldap, self.api.env.basedn, cert, nickname, trusted=True)

        trust_add_kw = dict(
            trust_type=u'ipa',
            trust_secret=payload['trust_secret'],
            realm_server=payload['server'],
            bidirectional=options.get('bidirectional', False),
        )
        for opt in _TRUST_ADD_PASSTHROUGH:
            if opt in options:
                trust_add_kw[opt] = options[opt]
        self.api.Command.trust_add(payload['domain'], **trust_add_kw)

        if realm_ca_certs:
            cert_summary = _(
                'Imported %(kdc)d KDC/PKINIT CA certificate(s) and '
                '%(realm)d separate realm-wide CA certificate(s) from '
                '%(domain)s.'
            ) % dict(
                kdc=len(payload['kdc_ca_certs']), realm=len(realm_ca_certs),
                domain=payload['domain'])
        else:
            cert_summary = _(
                "Imported %(kdc)d CA certificate(s) from %(domain)s, "
                "valid for both KDC/PKINIT and general realm-wide trust."
            ) % dict(kdc=len(payload['kdc_ca_certs']),
                     domain=payload['domain'])

        # certstore.put_ca_cert() only writes the LDAP entry; nothing
        # redistributes it to enrolled servers/clients automatically
        # (there is no fleet-wide push anywhere in FreeIPA -- the same is
        # true of ipa-cacert-manage install, see its own reminder message
        # and ipa-cacert-manage(1)). Until ipa-certupdate is run
        # everywhere, enrolled machines of this deployment will not trust
        # the newly-trusted realm's KDC certificates (e.g. for anonymous
        # PKINIT against it), even though this server itself now does.
        return dict(
            result=dict(
                domain=payload['domain'],
                realm=payload['realm'],
            ),
            summary=_(
                "Trust to %(domain)s established. %(cert_summary)s Run "
                "ipa-certupdate on every server, replica, and enrolled "
                "client of this deployment so they trust %(domain)s's "
                "KDC certificates."
            ) % dict(domain=payload['domain'], cert_summary=cert_summary),
        )
