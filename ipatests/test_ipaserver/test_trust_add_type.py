#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
"""Unit tests for the automatic detection of the trust type in
trust-add (ipaserver/plugins/trust.py _resolve_trust_type).

The remote deployment is probed during domain discovery; if its
rootDSE carries the ipaDomainLevel attribute it is an IPA deployment
and the trust type defaults to 'ipa', otherwise it stays 'ad'. An
explicitly given type that contradicts the detection is rejected.
"""
from __future__ import absolute_import

import pytest

from ipalib import errors

from ipaserver.plugins import trust as trust_mod


class TestResolveTrustType:
    def test_defaults_to_ipa_for_ipa_target(self):
        options = {}
        assert trust_mod._resolve_trust_type(
            options, 'b.example.test', remote_is_ipa=True) == u'ipa'
        assert options['trust_type'] == u'ipa'

    def test_defaults_to_ad_for_ad_target(self):
        options = {}
        assert trust_mod._resolve_trust_type(
            options, 'ad.example.test', remote_is_ipa=False) == u'ad'
        assert options['trust_type'] == u'ad'

    def test_explicit_ipa_honored_for_ipa_target(self):
        options = {'trust_type': u'ipa'}
        assert trust_mod._resolve_trust_type(
            options, 'b.example.test', remote_is_ipa=True) == u'ipa'

    def test_explicit_ad_honored_for_ad_target(self):
        options = {'trust_type': u'ad'}
        assert trust_mod._resolve_trust_type(
            options, 'ad.example.test', remote_is_ipa=False) == u'ad'

    def test_explicit_ad_rejected_for_ipa_target(self):
        with pytest.raises(errors.ValidationError):
            trust_mod._resolve_trust_type(
                {'trust_type': u'ad'}, 'b.example.test',
                remote_is_ipa=True)

    def test_explicit_ipa_rejected_for_ad_target(self):
        with pytest.raises(errors.ValidationError):
            trust_mod._resolve_trust_type(
                {'trust_type': u'ipa'}, 'ad.example.test',
                remote_is_ipa=False)
