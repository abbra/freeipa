#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
"""Unit tests for configuring the remote IPA deployment's own half of
an IPA-to-IPA trust (ipaserver/plugins/trust.py
configure_remote_ipa_half).

When remote administrator credentials are given, the trust's remote
half (trust object, cross-realm principal and the ID range for our
domain) is created by running a local-only trust_add on the remote
deployment's own IPA API, authenticated as the given administrator.
"""
from __future__ import absolute_import

from unittest import mock

import pytest

from ipalib import errors

from ipaserver.plugins import trust as trust_mod


class FakeRemoteApi:
    def __init__(self):
        self.Command = mock.MagicMock()
        self.bootstrap_kwargs = None
        self.finalized = 0

    def bootstrap(self, **kwargs):
        self.bootstrap_kwargs = kwargs

    def finalize(self):
        self.finalized += 1


class TestConfigureRemoteIpaHalf:
    def _run(self, api, bidirectional=True,
             kinit_side_effect=None):
        with mock.patch.object(trust_mod, 'create_api',
                               return_value=api), \
             mock.patch.object(
                trust_mod, 'kinit_password',
                side_effect=kinit_side_effect) as kinit:
            trust_mod.configure_remote_ipa_half(
                u'b.example.test',
                u'b-server.example.test',
                u'admin',
                u'password',
                u'ipa.test',
                u'server.ipa.test',
                u'shared-secret',
                bidirectional)
        return kinit

    def test_calls_remote_trust_add_with_matching_secret(self):
        api = FakeRemoteApi()
        self._run(api, bidirectional=True)

        api.Command.trust_add.assert_called_once_with(
            u'ipa.test',
            trust_type=u'ipa',
            trust_secret=u'shared-secret',
            realm_server=u'server.ipa.test',
            bidirectional=True)
        assert api.bootstrap_kwargs['in_server'] is True
        assert api.bootstrap_kwargs['xmlrpc_uri'] == (
            'https://b-server.example.test/ipa/xml')
        # the client API is finalized again after use
        assert api.finalized >= 2

    def test_kinit_uses_remote_admin_principal(self):
        api = FakeRemoteApi()
        kinit = self._run(api, bidirectional=False)

        kinit.assert_called_once_with(
            u'admin@B.EXAMPLE.TEST', u'password')
        assert api.Command.trust_add.call_args[1]['bidirectional'] is \
            False

    def test_kinit_failure_raises_validation_error(self):
        api = FakeRemoteApi()
        with pytest.raises(errors.ValidationError):
            self._run(api, kinit_side_effect=RuntimeError('bad password'))
        # no remote command may have been issued
        api.Command.trust_add.assert_not_called()
