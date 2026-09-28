#
# Copyright (C) 2026  FreeIPA Contributors.  See COPYING for license
#
"""ipa-otpd's private_key_jwt credential at ahdapa (DARC)."""

from __future__ import absolute_import

import base64
import os
import stat

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12

from ipaplatform.paths import paths
from ipaserver.install import ahdapa_otpd

FQDN = 'kdc1.example.test'


@pytest.fixture
def relabelled(monkeypatch):
    calls = []
    monkeypatch.setattr(ahdapa_otpd.tasks, 'restore_context',
                        lambda path, force=False: calls.append(path))
    return calls


@pytest.fixture
def statedir(tmp_path, monkeypatch, relabelled):
    d = tmp_path / 'ipa-otpd'
    monkeypatch.setattr(paths, 'IPA_OTPD_STATE_DIR', str(d))
    monkeypatch.setattr(paths, 'IPA_OTPD_AHDAPA_P12',
                        str(d / 'ahdapa-client.p12'))
    monkeypatch.setattr(paths, 'IPA_OTPD_AHDAPA_P12_PASSWORD',
                        str(d / 'ahdapa-client.pwd'))
    return d


def _b64url_int(value):
    return int.from_bytes(
        base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)), 'big')


def test_client_id_matches_ipa_otpd():
    assert ahdapa_otpd.otpd_client_id(FQDN) == 'ipa-otpd-' + FQDN


def test_credential_is_private_and_loadable(statedir):
    public_key = ahdapa_otpd.ensure_credential(FQDN)

    assert stat.S_IMODE(os.stat(statedir).st_mode) == 0o700
    for path in (paths.IPA_OTPD_AHDAPA_P12,
                 paths.IPA_OTPD_AHDAPA_P12_PASSWORD):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    # oidc_child needs the key and a certificate (for x5t#S256).
    with open(paths.IPA_OTPD_AHDAPA_P12_PASSWORD, 'rb') as f:
        password = f.read().strip()
    with open(paths.IPA_OTPD_AHDAPA_P12, 'rb') as f:
        key, cert, _extra = pkcs12.load_key_and_certificates(
            f.read(), password)
    assert cert is not None
    assert key.public_key().public_numbers() == public_key.public_numbers()


def test_credential_is_relabelled(statedir, relabelled):
    # ipa_otpd_key_t: the directory and both files, also when the
    # credential already exists (upgrades fix the labels).
    expected = [paths.IPA_OTPD_STATE_DIR, paths.IPA_OTPD_AHDAPA_P12,
                paths.IPA_OTPD_AHDAPA_P12_PASSWORD]
    ahdapa_otpd.ensure_credential(FQDN)
    assert sorted(relabelled) == sorted(expected)
    del relabelled[:]
    ahdapa_otpd.ensure_credential(FQDN)
    assert sorted(relabelled) == sorted(expected)


def test_credential_is_kept_across_runs(statedir):
    first = ahdapa_otpd.ensure_credential(FQDN)
    second = ahdapa_otpd.ensure_credential(FQDN)
    assert first.public_numbers() == second.public_numbers()


def test_unreadable_credential_is_replaced(statedir):
    ahdapa_otpd.ensure_credential(FQDN)
    with open(paths.IPA_OTPD_AHDAPA_P12_PASSWORD, 'w') as f:
        f.write('wrong\n')
    public_key = ahdapa_otpd.ensure_credential(FQDN)
    assert public_key is not None


def test_public_jwk(statedir):
    public_key = ahdapa_otpd.ensure_credential(FQDN)
    jwk = ahdapa_otpd.public_jwk(public_key)
    numbers = public_key.public_numbers()
    assert jwk['kty'] == 'EC' and jwk['crv'] == 'P-256'
    assert jwk['alg'] == 'ES256'
    assert 'd' not in jwk
    assert _b64url_int(jwk['x']) == numbers.x
    assert _b64url_int(jwk['y']) == numbers.y


@pytest.mark.skipif(tomllib is None, reason='tomllib not available')
def test_jwks_toml_is_valid_toml(statedir):
    public_key = ahdapa_otpd.ensure_credential(FQDN)
    doc = tomllib.loads('jwks = ' + ahdapa_otpd.jwks_toml(public_key))
    assert doc['jwks'] == {'keys': [ahdapa_otpd.public_jwk(public_key)]}


def test_remove_credential(statedir):
    ahdapa_otpd.ensure_credential(FQDN)
    ahdapa_otpd.remove_credential()
    assert not os.path.exists(paths.IPA_OTPD_AHDAPA_P12)
    assert not os.path.exists(paths.IPA_OTPD_AHDAPA_P12_PASSWORD)
