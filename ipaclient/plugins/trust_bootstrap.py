#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
"""Client-side file convenience for the trust-bootstrap-* commands.

The server-side commands (ipaserver/plugins/trust_bootstrap.py) exchange
ML-KEM keys, a retrieval token, and a server hostname as plain option
values, which is workable but means an admin has to copy/paste long
base64 blobs between two terminals by hand. These overrides let an admin
instead pass `--out=FILE` to have the relevant values written to disk,
and `--*-file=FILE` on the following command to read them back, so the
only manual step left is handing the resulting file to the other
administrator.
"""

from __future__ import absolute_import

import base64
import json
import os

from ipaclient.frontend import MethodOverride
from ipalib import errors, output, Str
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


def _write_json_file(path, data, sensitive):
    with open(path, 'w') as f:
        if sensitive:
            os.fchmod(f.fileno(), 0o600)
        json.dump(data, f)
        f.write('\n')


def _read_json_file(argname, path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (IOError, OSError) as e:
        raise errors.ValidationError(name=argname, error=str(e))
    except ValueError as e:
        raise errors.ValidationError(
            name=argname, error=_('invalid JSON content: %s') % (e,))


def write_keypair_files(out, kem_parameter_set, public_key, private_key):
    """Write a trust-bootstrap-init keypair to out (private) and out.pub
    (public, meant to be shared). Returns (out, out + '.pub')."""
    pub_path = out + '.pub'
    _write_json_file(
        out,
        dict(kem_parameter_set=kem_parameter_set, private_key=private_key),
        sensitive=True)
    _write_json_file(
        pub_path,
        dict(kem_parameter_set=kem_parameter_set, public_key=public_key),
        sensitive=False)
    return out, pub_path


def read_keypair_file(argname, path, key_field):
    """Read a file written by write_keypair_files().

    :param key_field: 'public_key' or 'private_key'
    :returns: (kem_parameter_set, raw key bytes)
    """
    data = _read_json_file(argname, path)
    try:
        parameter_set = data['kem_parameter_set']
        key_bytes = base64.b64decode(data[key_field])
    except (KeyError, TypeError, ValueError) as e:
        raise errors.ValidationError(
            name=argname, error=_('invalid key file: %s') % (e,))
    return parameter_set, key_bytes


def write_prepare_info_file(out, server, token):
    """Write a trust-bootstrap-prepare token+server to out, for the
    requesting side's administrator."""
    _write_json_file(out, dict(server=server, token=token), sensitive=True)


def read_prepare_info_file(argname, path):
    """Read a file written by write_prepare_info_file().

    :returns: (server, token)
    """
    data = _read_json_file(argname, path)
    try:
        return data['server'], data['token']
    except KeyError as e:
        raise errors.ValidationError(
            name=argname,
            error=_('invalid prepare info file: missing %s') % (e,))


@register(override=True, no_fail=True)
class trust_bootstrap_init(MethodOverride):
    has_output = ('result', output.summary)

    takes_options = (
        Str(
            'out?',
            cli_name='out',
            doc=_('File to store the generated one-time keypair. The '
                  'private key is written to FILE (mode 0600, keep it '
                  'secret); the public key, meant to be shared with the '
                  'administrator of the other IPA deployment, is written '
                  'to FILE.pub'),
        ),
    )

    def forward(self, *args, **options):
        out = options.pop('out', None)
        result = super(trust_bootstrap_init, self).forward(*args, **options)

        if out:
            r = result['result']
            parameter_set = r['kem_parameter_set']
            priv_path, pub_path = write_keypair_files(
                out, parameter_set,
                r.pop('public_key'), r.pop('private_key'))
            result['summary'] = _(
                "Private key written to '%(priv)s' (keep this secret); "
                "public key written to '%(pub)s' -- send %(pub)s to the "
                "administrator of the other IPA deployment"
            ) % dict(priv=priv_path, pub=pub_path)

        return result


@register(override=True, no_fail=True)
class trust_bootstrap_prepare(MethodOverride):
    has_output = ('result', output.summary)

    takes_options = (
        Str(
            'remote_kem_public_key_file?',
            cli_name='remote_kem_public_key_file',
            doc=_('File containing the remote ML-KEM public key, as '
                  'produced by trust-bootstrap-init --out (FILE.pub)'),
        ),
        Str(
            'out?',
            cli_name='out',
            doc=_('File to store the retrieval token and server hostname '
                  '(mode 0600) -- send this file to the administrator of '
                  'the requesting IPA deployment'),
        ),
    )

    def get_options(self):
        for option in super(trust_bootstrap_prepare, self).get_options():
            if option.name == 'remote_kem_public_key':
                option = option.clone(required=False)
            yield option

    def forward(self, *args, **options):
        pub_key_file = options.pop('remote_kem_public_key_file', None)
        out = options.pop('out', None)
        pub_key_raw = options.get('remote_kem_public_key')

        if pub_key_file and pub_key_raw:
            raise errors.MutuallyExclusiveError(
                reason=_('remote_kem_public_key and '
                         'remote_kem_public_key_file cannot both be '
                         'given'))
        if pub_key_file:
            parameter_set, key_bytes = read_keypair_file(
                'remote_kem_public_key_file', pub_key_file, 'public_key')
            options['remote_kem_public_key'] = key_bytes
            options['kem_parameter_set'] = parameter_set
        elif not pub_key_raw:
            raise errors.ValidationError(
                name='remote_kem_public_key',
                error=_('one of --remote-kem-public-key or '
                        '--remote-kem-public-key-file is required'))

        result = super(trust_bootstrap_prepare, self).forward(
            *args, **options)

        if out:
            r = result['result']
            write_prepare_info_file(out, r['server'], r.pop('token'))
            result['summary'] = _(
                "Retrieval token written to '%(out)s' -- send this file "
                "to the administrator of the requesting IPA deployment"
            ) % dict(out=out)

        return result


@register(override=True, no_fail=True)
class trust_bootstrap_retrieve(MethodOverride):
    takes_options = (
        Str(
            'kem_private_key_file?',
            cli_name='kem_private_key_file',
            doc=_('File containing the ML-KEM private key, as produced '
                  'by trust-bootstrap-init --out'),
        ),
        Str(
            'prepare_info_file?',
            cli_name='prepare_info_file',
            doc=_('File containing the retrieval token and server '
                  'hostname, as produced by trust-bootstrap-prepare '
                  '--out'),
        ),
    )

    def get_options(self):
        for option in super(trust_bootstrap_retrieve, self).get_options():
            if option.name in ('kem_private_key', 'server', 'token'):
                option = option.clone(required=False)
            yield option

    def forward(self, *args, **options):
        priv_key_file = options.pop('kem_private_key_file', None)
        prepare_info_file = options.pop('prepare_info_file', None)
        priv_key_raw = options.get('kem_private_key')
        server = options.get('server')
        token = options.get('token')

        if priv_key_file and priv_key_raw:
            raise errors.MutuallyExclusiveError(
                reason=_('kem_private_key and kem_private_key_file cannot '
                         'both be given'))
        if priv_key_file:
            parameter_set, key_bytes = read_keypair_file(
                'kem_private_key_file', priv_key_file, 'private_key')
            options['kem_private_key'] = key_bytes
            options['kem_parameter_set'] = parameter_set
        elif not priv_key_raw:
            raise errors.ValidationError(
                name='kem_private_key',
                error=_('one of --kem-private-key or '
                        '--kem-private-key-file is required'))

        if prepare_info_file and (server or token):
            raise errors.MutuallyExclusiveError(
                reason=_('server/token and prepare_info_file cannot both '
                         'be given'))
        if prepare_info_file:
            server, token = read_prepare_info_file(
                'prepare_info_file', prepare_info_file)
            options['server'] = server
            options['token'] = token
        elif not (server and token):
            raise errors.ValidationError(
                name='server',
                error=_('either --prepare-info-file, or both --server '
                        'and --token, are required'))

        return super(trust_bootstrap_retrieve, self).forward(
            *args, **options)
