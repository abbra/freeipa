# Copyright (C) 2026 FreeIPA Contributors. See COPYING for license.

"""Helpers shared by the kuipa tests that run on one deployment.

Each kuipa area (enrollment, seal administration, Clevis, the TPM service,
...) is a mixin with test methods. A deployment class lists the mixins and
installs the realm once; an area prepares the hosts it needs in a
``stage_*`` classmethod that every test of the area calls first, decorated
with ``@stage('name')``: it runs once, and if it failed (or skipped) the
other tests of the area fail (or skip) with the same reason instead of
running on a half-prepared host. pytest runs the base classes of a class
before the class, the last base first, so the order of a deployment is the
reverse of the order of its bases (see test_kuipa_realm.py).
"""

import functools

import pytest

from ipatests.pytest_ipa.integration import tasks


def stage(name):
    """Make a classmethod run once per test class, and remember its outcome."""
    def decorate(func):
        @functools.wraps(func)
        def wrapper(cls):
            if '_kuipa_stages' not in cls.__dict__:
                cls._kuipa_stages = {}
            if name in cls._kuipa_stages:
                kind, reason = cls._kuipa_stages[name]
                if kind == 'skip':
                    pytest.skip(reason)
                if kind == 'fail':
                    pytest.fail('stage {} failed earlier: {}'.format(
                        name, reason), pytrace=False)
                return
            try:
                func(cls)
            except pytest.skip.Exception as exc:
                cls._kuipa_stages[name] = ('skip', str(exc))
                raise
            except BaseException as exc:
                cls._kuipa_stages[name] = ('fail', repr(exc))
                raise
            cls._kuipa_stages[name] = ('ok', None)
        return wrapper
    return decorate


class KuipaStages:
    """A clean client for an area to start from."""

    @classmethod
    def reset_client(cls, client):
        """Leave `client` unenrolled, with DNS pointing at the master.

        An earlier area may have enrolled it: uninstall (which restores the
        resolver), delete its host entry, then point DNS at the master again.
        """
        master = cls.master
        tasks.uninstall_client(client)
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'host-del', client.hostname],
                           raiseonerr=False)
        client.resolver.backup()
        client.resolver.setup_resolver(master.ip)
