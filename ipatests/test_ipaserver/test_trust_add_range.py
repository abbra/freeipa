#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
"""Unit tests for the ID range selection performed by trust-add
(ipaserver/plugins/trust.py add_range).

IPA-to-IPA trusts must always use the ipa-ad-trust-posix range type and
must not attempt the Active Directory-only msSFU30DomainInfo discovery
step, which cannot possibly succeed against an IPA target.
"""
from __future__ import absolute_import

from unittest import mock

from ipaserver.plugins import trust as trust_mod


def call_add_range(options, base_id=200000, range_size=200000):
    """Invoke trust.add_range() with a fake API and return the kwargs
    passed to idrange_add.

    base_id/range_size are supplied explicitly so the tests do not
    depend on pysss_murmur being available.
    """
    api = mock.MagicMock()
    opts = dict(options)
    opts.setdefault('base_id', base_id)
    opts.setdefault('range_size', range_size)
    trust_mod.add_range(api, None, 'B.EXAMPLE.TEST_id_range',
                        'S-1-5-21-1-2-3',
                        'b.example.test', **opts)
    (call_args, call_kwargs), = api.Command['idrange_add'].call_args_list
    return call_kwargs


class TestAddRangeRangeTypeSelection:
    def test_ipa_trust_defaults_to_posix_range(self):
        # No --range-type given, target is another IPA deployment:
        # must land on ipa-ad-trust-posix, not the algorithmic
        # ipa-ad-trust mapping.
        kwargs = call_add_range({'trust_type': u'ipa'})
        assert kwargs['iparangetype'] == u'ipa-ad-trust-posix'

    def test_ipa_trust_explicit_posix_range_honored(self):
        kwargs = call_add_range(
            {'trust_type': u'ipa', 'range_type': u'ipa-ad-trust-posix'})
        assert kwargs['iparangetype'] == u'ipa-ad-trust-posix'

    def test_ipa_trust_skips_ad_discovery(self):
        # The msSFU30DomainInfo lookup is AD-only; it must not even be
        # attempted against an IPA target. trust.py binds the
        # 'ipaserver' name into its module globals at import time only
        # when the Samba DCE-RPC bindings are available, so inject a
        # fake here.
        fake_ipaserver = mock.MagicMock()
        with mock.patch.dict(trust_mod.__dict__, ipaserver=fake_ipaserver):
            call_add_range({'trust_type': u'ipa'})
        fake_ipaserver.dcerpc.DomainValidator.assert_not_called()

    def test_ad_trust_discovery_failure_falls_back_to_algorithmic(self):
        # Sanity check that the AD code path is untouched: no
        # msSFU30DomainInfo found -> ipa-ad-trust as before.
        fake_ipaserver = mock.MagicMock()
        validator = fake_ipaserver.dcerpc.DomainValidator
        validator.return_value.is_configured.return_value = True
        validator.return_value.search_in_dc.return_value = []
        with mock.patch('ipaserver.plugins.trust.sleep'), \
             mock.patch.dict(trust_mod.__dict__,
                             ipaserver=fake_ipaserver):
            kwargs = call_add_range({'trust_type': u'ad'})
        assert kwargs['iparangetype'] == u'ipa-ad-trust'
        validator.assert_called_once()
