#
# Copyright (C) 2026  Red Hat
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
#
"""Native (Samba-free) implementation of the local half of an
IPA-to-IPA trust.

An IPA-to-IPA trust is a pair of trusted domain objects (TDOs), one
in each deployment, sharing a single symmetric secret, and a set of
cross-realm Kerberos principals in each deployment's Kerberos
database. The layout mirrors what Samba does for an AD trust (see
ipasam_set_trusted_domain() and handle_cross_realm_princs() in
daemons/ipa-sam/ipa_sam.c) with the following differences:

* the TDO lives in the cn=ipa container under cn=trusts and has no
  SID attributes;
* the same secret is used for the incoming and the outgoing
  direction;
* the principals' keys are set locally through the 389-ds keytab
  extended operation (GetKeytabControl, see asn1/ipa_asn1.c), the
  same mechanism ipasam uses via ipaasn1_enc_getkt().
"""

from __future__ import absolute_import

import logging
import struct
import time

from ipalib import _, errors
from ipalib.constants import ALLOWED_NETBIOS_CHARS
from ipapython.dn import DN
from ldap import MOD_ADD, MOD_REPLACE

logger = logging.getLogger()

# OID of the keytab extended operation, shared with the keytab plugin
# and ipasam (see util/ipa_krb5.h)
KEYTAB_GET_OID = '2.16.840.1.113730.3.8.10.5'

# Kerberos enctype numbers (krb5.h) as passed in GetKeytabControl
ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 17
ENCTYPE_AES128_CTS_HMAC_SHA1_96 = 18
ENCTYPE_ARCFOUR_HMAC = 3

# ipaNTSupportedEncryptionTypes bit values (LSA_KERBEROS_ENCTYPE,
# see samba/librpc/idl/lsa.idl)
LSA_KERB_ENCTYPE_RC4_HMAC_MD5 = 0x04
LSA_KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96 = 0x08
LSA_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 0x10

# LSA trust record values (see samba/librpc/idl/lsa.idl)
LSA_TRUST_TYPE_UPLEVEL = 1
LSA_TRUST_DIRECTION_INBOUND = 1
LSA_TRUST_DIRECTION_OUTBOUND = 2
LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008
LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x80

# LSA_TRUST_AUTH_TYPE_CLEAR (see samba/librpc/idl/drsblobs.idl)
LSA_TRUST_AUTH_TYPE_CLEAR = 2

# krbTicketFlags: disallow all tickets, the same value ipasam sets on
# the trust agent principal (IPASAM_DISALLOW_ALL_TIX)
KRB_DISALLOW_ALL_TIX = 0x40

# Magic uidNumber value for TDOs (IPA_MAGIC_ID_STR in ipa_sam.c)
IPA_MAGIC_ID = u'-1'

# Groups granted read access to the trust secrets, the same set the
# AD trust install grants (see ipaserver/install/plugins/adtrust.py)
LDAP_CN_ADTRUST_AGENTS = u'cn=adtrust agents,cn=sysaccounts,cn=etc'
LDAP_CN_TRUST_ADMINS = u'cn=trust admins,cn=groups,cn=accounts'


def fips_enabled():
    """Mirror of the FIPS mode check performed by ipasam."""
    try:
        with open('/proc/sys/crypto/fips_enabled') as f:
            return f.read().strip() == '1'
    except (IOError, OSError):
        return False


def default_enctypes():
    """Kerberos enctypes used for the trust principals, with RC4
    dropped in FIPS mode, mirroring ipasam's default_enctypes list."""
    enctypes = [ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                ENCTYPE_AES128_CTS_HMAC_SHA1_96]
    if not fips_enabled():
        enctypes.append(ENCTYPE_ARCFOUR_HMAC)
    return enctypes


def lsa_enctypes_mask():
    """ipaNTSupportedEncryptionTypes value, mirroring ipasam's
    supported_enctypes default."""
    if fips_enabled():
        return (LSA_KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96 |
                LSA_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96)
    return (LSA_KERB_ENCTYPE_RC4_HMAC_MD5 |
            LSA_KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96 |
            LSA_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96)


def make_netbios_name(s):
    """Same heuristic as ipaserver/install/adtrustinstance.py."""
    return ''.join([c for c in s.split('.')[0].upper()
                    if c in ALLOWED_NETBIOS_CHARS])[:15]


# ---------------------------------------------------------------------------
# GetKeytabControl BER encoding
#
# The ASN.1 definitions live in asn1/ipa.asn1 and are processed by
# asn1c at build time:
#
#   GetKeytabControl ::= CHOICE {
#       newkeys [0] GKNewKeys,
#       curkeys [1] GKCurrentKeys,
#       reply   [2] GKReply
#   }
#   GKNewKeys ::= SEQUENCE {
#       serviceIdentity [0] OCTET STRING,
#       enctypes        [1] SEQUENCE OF Int32,
#       password        [2] OCTET STRING OPTIONAL
#   }
# ---------------------------------------------------------------------------

def _ber_len(length):
    if length < 0x80:
        return struct.pack('B', length)
    data = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return struct.pack('B', 0x80 | len(data)) + data


def _ber(tag, value):
    return struct.pack('B', tag) + _ber_len(len(value)) + value


def _ber_int32(value):
    """Encode a non-negative int32 value as a minimal DER INTEGER,
    the same asn1c does for the Int32 type."""
    if value < 0:
        raise ValueError('only non-negative values are supported')
    nbytes = (value.bit_length() + 8) // 8
    data = value.to_bytes(nbytes, 'big')
    if data[0] & 0x80:
        # Keep the value non-negative in two's complement form
        data = b'\x00' + data
    return _ber(0x02, data)


def encode_getkt_newkeys(principal, enctypes, password=None):
    """Encode the newkeys branch of GetKeytabControl, byte-identical
    to the ipaasn1_enc_getkt() C encoder in asn1/ipa_asn1.c.
    The SEQUENCE fields carry their ASN.1 explicit context tags:

        a0 <len>                            # newkeys [0]
          30 <len>
            a0 <len> 04 <len> <principal>  # serviceIdentity [0]
            a1 <len> 30 <len> <Int32>*     # enctypes [1]
            a2 <len> 04 <len> <password>   # password [2], optional
    """
    seq = _ber(0xa0, _ber(0x04, principal.encode('utf-8')))
    seq += _ber(0xa1, _ber(0x30, b''.join(
        _ber_int32(e) for e in enctypes)))
    if password is not None:
        seq += _ber(0xa2, _ber(0x04, password.encode('utf-8')))
    return _ber(0xa0, _ber(0x30, seq))


def encode_trust_auth_blob(secret):
    """NDR-encode the trustAuthInOutBlob structure (see samba
    librpc/idl/drsblobs.idl) with a single CLEAR password entry.

    This is the layout ipasam stores into the
    ipaNTTrustAuthIncoming/ipaNTTrustAuthOutgoing attributes of the
    TDO, the same layout the trust agents expect to read:

        trustAuthInOutBlob ::= struct {
            uint32 count;                    # 1
            uint32 current_offset;           # 12
            uint32 previous_offset;          # total size, previous is empty
            AuthenticationInformationArray current;
        }
        AuthenticationInformation ::= struct {
            NTTIME LastUpdateTime;           # 8 bytes
            uint32 AuthType;                 # TRUST_AUTH_TYPE_CLEAR
            uint32 size;                     # CLEAR password size
            uint8 password[size];            # UTF-16LE, padded to 4
        }
    """
    password = secret.encode('utf-16-le')
    # Convert the UNIX time to the NT time format, the same
    # samba.unix2nttime() does
    nttime = (int(time.time()) + 11644473600) * 10000000
    # AuthenticationInformation incl. the NDR_ALIGN4 pad
    info = struct.pack('<q', nttime)    # LastUpdateTime
    info += struct.pack('<L', LSA_TRUST_AUTH_TYPE_CLEAR)  # AuthType
    info += struct.pack('<L', len(password))
    info += password
    pad = (4 - (len(info) % 4)) % 4
    info += b'\x00' * pad
    # previous_offset must match the total size of the struct in case
    # the previous array is empty (see drsblobs.idl)
    previous_offset = 12 + len(info)
    return (struct.pack('<L', 1)          # count
            + struct.pack('<L', 12)       # current_offset
            + struct.pack('<L', previous_offset)  # previous_offset
            + info)


def set_principal_key(ldap, principal, password, enctypes):
    """Set the keys of a principal through the keytab extended
    operation.

    :param ldap: ipa LDAP backend (api.Backend.ldap2)
    :param principal: full principal name (incl. the realm)
    :param password: new password for the principal
    :param enctypes: list of Kerberos enctype numbers
    """
    from ldap.extop import ExtendedRequest

    req = ExtendedRequest(KEYTAB_GET_OID,
                          encode_getkt_newkeys(principal, enctypes,
                                               password))
    try:
        resp_oid, resp_value = ldap.conn.extop_s(req)
    except Exception as e:
        raise errors.ExecutionError(
            message=_('Failed to set keys of principal %(principal)s: '
                      '%(error)s') % dict(principal=principal,
                                          error=str(e)))
    if resp_oid != KEYTAB_GET_OID:
        raise errors.ExecutionError(
            message=_('Unexpected response to the keytab extended '
                      'operation for principal %s: %s')
            % (principal, resp_oid))
    return resp_value


def trust_principals(local_realm, local_flatname, remote_realm,
                     remote_flatname, direction, secret):
    """Compute the cross-realm principals of the trust.

    Mirrors handle_cross_realm_princs() in daemons/ipa-sam/ipa_sam.c.
    For IPA-to-IPA trusts the same shared secret is used in both
    directions.

    :param direction: LSA_TRUST_DIRECTION_INBOUND,
        LSA_TRUST_DIRECTION_OUTBOUND or the bitwise OR of the two
    :param secret: the shared trust secret
    :returns: list of dicts with keys: principal, alias, password,
        disabled, agent_permission
    """
    principals = []
    # Incoming trust: the remote deployment authenticates to us
    if direction & LSA_TRUST_DIRECTION_INBOUND:
        principals.append(dict(
            principal=u'krbtgt/%s@%s' % (local_realm, remote_realm),
            alias=None,
            password=secret,
            disabled=False,
            agent_permission=False,
        ))
        principals.append(dict(
            # Used by the trust agents of the remote deployment to
            # retrieve the trusted domain credentials; disabled on our
            # side, the same as for AD trusts
            principal=u'krbtgt/%s@%s' % (local_flatname, remote_realm),
            alias=u'%s$@%s' % (local_flatname, remote_realm),
            password=secret,
            disabled=True,
            agent_permission=True,
        ))
    # Outgoing trust: we authenticate to the remote deployment
    if direction & LSA_TRUST_DIRECTION_OUTBOUND:
        principals.append(dict(
            principal=u'krbtgt/%s@%s' % (remote_realm, local_realm),
            alias=None,
            password=secret,
            disabled=False,
            agent_permission=False,
        ))
        principals.append(dict(
            principal=u'krbtgt/%s@%s' % (remote_flatname, local_realm),
            alias=u'%s$@%s' % (remote_flatname, local_realm),
            password=secret,
            disabled=False,
            agent_permission=False,
        ))
    return principals


def _as_str_list(values):
    """Normalize a list of attribute values to str (LDAP returns
    bytes for non-text attributes)."""
    return [value.decode('utf-8') if isinstance(value, bytes)
            else value for value in values]


def _get_fallback_gid(ldap, env):
    """Resolve the gidNumber for the TDO account.

    The same way ipasam does it: the local Samba domain entry
    (objectClass ipaNTDomainAttrs, present when an AD trust has been
    installed) carries the DN of the fallback primary group. When no
    such entry exists (a pure IPA-to-IPA deployment without Samba)
    the root group is used, the TDO account has no real login.
    """
    entries, _truncated = ldap.find_entries(
        filterstr='(objectclass=ipaNTDomainAttrs)',
        base_dn=env.basedn,
        scope=ldap.SCOPE_SUBTREE,
        attrs_list=['ipaNTFallbackPrimaryGroup'])
    for entry in entries:
        group_dn = entry.get('ipaNTFallbackPrimaryGroup')
        if group_dn:
            group = ldap.get_entry(DN.strdn(group_dn[0]), ['gidNumber'])
            return int(group.get('gidNumber')[0])
    return 0


def tdo_attributes(remote_domain, remote_flatname, secret, direction,
                   external, fallback_gid):
    """Attributes of the trusted domain object, mirroring what
    ipasam_set_trusted_domain() writes (sans the SID attributes and
    the SID blacklists, which do not apply to IPA deployments). The
    ipaTrustObject auxiliary object class and the ipaPartnerTrustType
    attribute are added by the trust_add command itself, the same way
    as for AD trusts.
    """
    if external:
        trust_attributes = LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE
    else:
        trust_attributes = LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE
    return {
        'objectClass': [u'ipaNTTrustedDomain', u'ipaIDobject',
                        u'posixAccount'],
        'cn': remote_domain,
        'uid': u'%s$' % remote_flatname,
        'uidNumber': IPA_MAGIC_ID,
        'gidNumber': str(fallback_gid),
        'homeDirectory': u'/dev/null',
        'ipaNTFlatName': remote_flatname,
        'ipaNTTrustPartner': remote_domain,
        'ipaNTTrustType': str(LSA_TRUST_TYPE_UPLEVEL),
        'ipaNTTrustAttributes': str(trust_attributes),
        'ipaNTTrustDirection': str(direction),
        'ipaNTTrustPosixOffset': '0',
        'ipaNTSupportedEncryptionTypes': str(lsa_enctypes_mask()),
        'ipaNTTrustAuthIncoming': encode_trust_auth_blob(secret),
        'ipaNTTrustAuthOutgoing': encode_trust_auth_blob(secret),
    }


def _upsert_tdo(ldap, tdo_dn, attrs):
    """Create or update the trusted domain object entry."""
    try:
        entry = ldap.get_entry(tdo_dn)
    except errors.NotFound:
        ldap.add_entry(tdo_dn, attrs)
        return False

    existing_oc = [oc.lower() for oc in
                   _as_str_list(entry.get('objectclass', []))]
    mods = [(MOD_REPLACE, name, value)
            for name, value in attrs.items()
            if name != 'objectClass']
    for oc in attrs['objectClass']:
        if oc.lower() not in existing_oc:
            mods.append((MOD_ADD, 'objectClass', [oc]))
    ldap.modify_entry(tdo_dn, mods)
    return True


def _upsert_principal(ldap, env, tdo_dn, princ, enctypes):
    """Create or update a cross-realm principal as a child entry of
    the TDO and set its keys through the keytab extended operation.
    Mirrors set_krb_princ() in daemons/ipa-sam/ipa_sam.c.
    """
    dn = DN(('krbPrincipalName', princ['principal']), tdo_dn)
    try:
        entry = ldap.get_entry(dn)
    except errors.NotFound:
        entry = None

    if entry is None:
        objectclasses = [u'krbPrincipal', u'krbPrincipalAux',
                         u'krbTicketPolicyAux']
        attrs = {
            'objectClass': objectclasses,
            'krbPrincipalName': [princ['principal']],
            'krbCanonicalName': princ['principal'],
        }
        if princ.get('alias'):
            attrs['krbPrincipalName'].append(princ['alias'])
        if princ['disabled']:
            attrs['krbTicketFlags'] = [str(KRB_DISALLOW_ALL_TIX)]
        if princ['agent_permission']:
            objectclasses.append(u'ipaAllowedOperations')
            attrs['ipaAllowedToPerform;read_keys'] = [
                DN(LDAP_CN_ADTRUST_AGENTS, env.basedn),
                DN(LDAP_CN_TRUST_ADMINS, env.basedn),
            ]
        ldap.add_entry(dn, attrs)
    else:
        mods = []
        principal_names = _as_str_list(entry.get('krbPrincipalName', []))
        if princ.get('alias') and princ['alias'] not in principal_names:
            mods.append((MOD_ADD, 'krbPrincipalName', [princ['alias']]))
        if princ['disabled']:
            mods.append((MOD_REPLACE, 'krbTicketFlags',
                         [str(KRB_DISALLOW_ALL_TIX)]))
        if mods:
            ldap.modify_entry(dn, mods)

    set_principal_key(ldap, princ['principal'], princ['password'],
                      enctypes)


def probe_remote_realm(domain, server=None):
    """Probe the remote deployment's LDAP server to determine whether
    it is an IPA deployment or Active Directory.

    The remote server is taken from the given name, or discovered via
    the _ldap._tcp.<domain> SRV record (falling back to the domain's
    A/AAAA records). The determination is based on the remote
    rootDSE: Active Directory servers advertise
    isGlobalCatalogRouter, IPA 389-ds servers expose ipaDomainLevel,
    set by the topology plugin's DSE callback (see
    daemons/ipa-slapi-plugins/topology/topology_init.c).

    :returns: 'ipa', 'ad', or None if the type could not be
        determined
    """
    import ldap
    from ipapython.dnsutil import query_srv, resolve_ip_addresses

    host = None
    if server is not None:
        host = server
    else:
        try:
            srv = query_srv('_ldap._tcp.%s' % domain)
        except Exception:
            srv = []
        if srv:
            host = srv[0].target
            if host.endswith('.'):
                host = host[:-1]
        if host is None:
            try:
                addrs = resolve_ip_addresses(domain)
            except Exception:
                addrs = []
            if addrs:
                host = addrs[0]

    if host is None:
        return None

    conn = None
    result = None
    try:
        conn = ldap.initialize('ldaps://%s:636' % host)
        conn.simple_bind_s('', '')
        msgid = conn.search_ext('', ldap.SCOPE_BASE, '',
                                ['isGlobalCatalogRouter',
                                 'ipaDomainLevel'])
        _result_type, result = conn.result3(msgid)
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.unbind_s()
            except Exception:
                pass

    entries = result.get('data', []) if result is not None else []
    if not entries:
        return None
    _dn, attrs = entries[0]
    if attrs.get('ipaDomainLevel'):
        return 'ipa'
    if attrs.get('isGlobalCatalogRouter'):
        return 'ad'
    return None


def establish_ipa_trust(api, remote_domain, secret, direction,
                        external=False):
    """Establish the local half of an IPA-to-IPA trust.

    Creates or updates the trusted domain object under
    cn=ipa,cn=trusts and the set of cross-realm Kerberos principals
    with the keys derived from the given shared secret.

    :param api: IPA API instance
    :param remote_domain: DNS domain name of the remote deployment
    :param secret: the shared trust secret
    :param direction: LSA_TRUST_DIRECTION_INBOUND,
        LSA_TRUST_DIRECTION_OUTBOUND or the bitwise OR of the two
    :param external: whether the trust is external (non-transitive)
    :returns: dict with the TDO DN
    """
    env = api.env
    realm = env.realm
    remote_realm = remote_domain.upper()
    local_flatname = make_netbios_name(realm)
    remote_flatname = make_netbios_name(remote_domain)

    container_dn = DN(('cn', 'ipa'), ('cn', 'trusts'), (env.basedn,))
    tdo_dn = DN(('cn', remote_domain), container_dn)

    ldap = api.Backend.ldap2
    try:
        ldap.get_entry(container_dn)
    except errors.NotFound:
        raise errors.ConfigurationError(
            message=_('The %s container is missing; the server needs to '
                      'be updated (ipa-server-upgrade) before IPA-to-IPA '
                      'trusts can be established') % container_dn)

    fallback_gid = _get_fallback_gid(ldap, env)

    attrs = tdo_attributes(remote_domain, remote_flatname, secret,
                           direction, external, fallback_gid)
    existed = _upsert_tdo(ldap, tdo_dn, attrs)

    enctypes = default_enctypes()
    for princ in trust_principals(realm, local_flatname, remote_realm,
                                  remote_flatname, direction, secret):
        _upsert_principal(ldap, env, tdo_dn, princ, enctypes)

    return dict(tdo_dn=tdo_dn, existed=existed)
