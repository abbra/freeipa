#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Which tar failures ipa-backup tolerates."""

from types import SimpleNamespace

import pytest

from ipaserver.install import ipa_backup

CHANGED = (
    "tar: Removing leading `/' from member names\n"
    "tar: /etc/sysconfig/pki: file changed as we read it\n"
)


def result(returncode, error_log):
    return SimpleNamespace(returncode=returncode, error_log=error_log)


def test_a_changed_file_alone_is_tolerated():
    assert ipa_backup.tar_changed_only(result(1, CHANGED))


@pytest.mark.parametrize('failure', [
    result(2, CHANGED),
    result(1, CHANGED + "tar: /etc/ipa: Cannot open: Permission denied\n"),
    result(1, "tar: /etc/ipa: Cannot stat: No such file or directory\n"),
])
def test_anything_else_is_an_error(failure):
    assert not ipa_backup.tar_changed_only(failure)
