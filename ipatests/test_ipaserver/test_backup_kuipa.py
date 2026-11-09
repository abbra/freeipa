#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""
Tests for ipa-backup --kuipa and ipa-restore with a sealed backup.

kuipa itself is replaced by a stub that records its arguments: these tests
cover what FreeIPA passes to it and what it does with the result, not the
sealing, which kuipa tests.
"""

import os
import stat
from types import SimpleNamespace

import pytest

from ipapython import admintool
from ipaserver.install import ipa_backup, ipa_restore

STUB = """#!/bin/sh
echo "$@" >> "{log}"
case "$2" in
seal)
    while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done
    /bin/cat > "$out"
    ;;
open)
    while [ $# -gt 0 ]; do [ "$1" = --out ] && out="$2"; shift; done
    echo tar-contents > "$out"
    ;;
esac
exit ${{STUB_RC:-0}}
"""


@pytest.fixture
def kuipa(monkeypatch, tmp_path):
    log = tmp_path / 'calls'
    stub = tmp_path / 'kuipa'
    stub.write_text(STUB.format(log=log))
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    for module in (ipa_backup, ipa_restore):
        monkeypatch.setattr(module.paths, 'KUIPA', str(stub))
    return log


def test_seal_streams_the_tar_to_kuipa(kuipa, tmp_path):
    source = tmp_path / 'src'
    source.mkdir()
    (source / 'file').write_text('data')
    dest = tmp_path / 'ipa-full.tar.kuipa'

    ipa_backup.kuipa_seal(str(source), '/etc/recipient.json', str(dest))

    assert ('backup seal --recipient /etc/recipient.json -o %s' % dest
            in kuipa.read_text())
    # the stub stores what it read: a gzip stream of the directory
    assert dest.read_bytes()[:2] == b'\x1f\x8b'


def test_a_failed_tar_leaves_no_sealed_file(kuipa, tmp_path, monkeypatch):
    # A truncated archive would seal and look like a backup
    fake = tmp_path / 'bin'
    fake.mkdir()
    tar = fake / 'tar'
    tar.write_text('#!/bin/sh\necho boom >&2\nexit 1\n')
    tar.chmod(0o755)
    monkeypatch.setenv('PATH', str(fake))
    dest = tmp_path / 'ipa-full.tar.kuipa'

    with pytest.raises(admintool.ScriptError, match='boom'):
        ipa_backup.kuipa_seal(str(tmp_path), '/etc/recipient.json', str(dest))

    assert not dest.exists()


def test_check_recipient_reports_kuipa_failure(kuipa, monkeypatch):
    monkeypatch.setenv('STUB_RC', '1')
    with pytest.raises(admintool.ScriptError, match='cannot seal'):
        ipa_backup.kuipa_check_recipient('/etc/recipient.json')


def test_sign_covers_the_files_as_the_host(monkeypatch):
    monkeypatch.setattr(ipa_backup, 'api', SimpleNamespace(
        env=SimpleNamespace(host='ipa1.example.test', realm='EXAMPLE.TEST')))
    tickets = []
    monkeypatch.setattr(
        ipa_backup, 'kinit_keytab',
        lambda principal, keytab, ccache: tickets.append((principal, ccache)))
    calls = []

    def fake_run(args, env=None, raiseonerr=True):
        calls.append((args, env))
        return SimpleNamespace(returncode=0, error_log='')

    monkeypatch.setattr(ipa_backup, 'run', fake_run)

    ipa_backup.kuipa_sign(['/b/ipa-full.tar.kuipa', '/b/header'])

    assert tickets[0][0] == 'host/ipa1.example.test@EXAMPLE.TEST'
    args, env = calls[0]
    assert args[1:] == ['sign', 'blob', '--purpose', 'ipa-backup',
                        '/b/ipa-full.tar.kuipa', '/b/header']
    assert env['KRB5CCNAME'] == 'FILE:%s' % tickets[0][1]


def test_sign_without_a_ticket_is_an_error(monkeypatch):
    monkeypatch.setattr(ipa_backup, 'api', SimpleNamespace(
        env=SimpleNamespace(host='ipa1.example.test', realm='EXAMPLE.TEST')))

    def no_ticket(*args):
        raise RuntimeError('no keytab')

    monkeypatch.setattr(ipa_backup, 'kinit_keytab', no_ticket)
    with pytest.raises(admintool.ScriptError, match='no keytab'):
        ipa_backup.kuipa_sign(['/b/ipa-full.tar.kuipa'])


def options(**kw):
    base = dict(kuipa_no_verify=False, kuipa_realm=None, kuipa_anchor=None,
                kuipa_signer=None, kuipa_recovery_file=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_open_verifies_the_backup_and_its_header(kuipa, tmp_path):
    backup = tmp_path / 'backup'
    backup.mkdir()
    out = ipa_restore.kuipa_open(
        str(backup), str(tmp_path), str(backup / 'ipa-full.tar.kuipa'),
        options(kuipa_realm='EXAMPLE.TEST', kuipa_anchor=['A1', 'A2'],
                kuipa_signer='host/ipa1.example.test'))

    assert out == str(tmp_path / 'ipa-full.tar')
    assert os.path.exists(out)
    call = kuipa.read_text()
    assert '--also %s/header' % backup in call
    assert '--realm EXAMPLE.TEST --anchor A1 --anchor A2' in call
    assert '--signer host/ipa1.example.test' in call
    assert '--no-verify' not in call


def test_no_verify_asks_kuipa_for_no_signature_check(kuipa, tmp_path):
    ipa_restore.kuipa_open(
        str(tmp_path), str(tmp_path), str(tmp_path / 'ipa-full.tar.kuipa'),
        options(kuipa_no_verify=True, kuipa_anchor=['A1']))

    call = kuipa.read_text()
    assert '--no-verify' in call
    assert '--anchor' not in call and '--also' not in call


def test_a_backup_kuipa_refuses_is_not_restored(kuipa, tmp_path, monkeypatch):
    monkeypatch.setenv('STUB_RC', '1')
    with pytest.raises(admintool.ScriptError, match='could not open'):
        ipa_restore.kuipa_open(
            str(tmp_path), str(tmp_path),
            str(tmp_path / 'ipa-full.tar.kuipa'), options())
