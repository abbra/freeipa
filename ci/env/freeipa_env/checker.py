"""Preset validation for CI gating (``freeipa-env check``).

Parses and semantically validates preset YAML files *without* spawning any
containers or touching the network. It exists so a change to the 1300+
presets (migrated PRCI definitions, Azure jobs, nested examples) can be
gated in CI: every preset must parse as an ``EnvSpec`` and pass the
provider's read-only sanity checks.

Checks per preset:
  * YAML parses and the top-level shape is a valid ``EnvSpec``
    (host roles, a master, run block, known keys, ...).
  * ``provider: podman``  -- every containerized host resolves an image,
    and a channel-style reference names a *known* build channel (a bare
    non-channel, non-reference name is flagged as a likely typo).
  * ``provider: nested``  -- the ``vm:`` block builds a known VM backend
    and ``inner`` names a known provider.
  * ``provider: external``-- every host carries an address.
"""

import os

import yaml

from .envspec import EnvSpec, EnvSpecError
from .image import is_channel
from .vmbackend import VMBackendError, make_backend
from . import queue

KNOWN_PROVIDERS = ('podman', 'external', 'nested')


def check_spec(spec):
    """Validate a parsed EnvSpec. Returns a list of error strings (== []
    when the preset is sound)."""
    errors = []
    if spec.provider == 'nested':
        if spec.inner not in (None,) + KNOWN_PROVIDERS:
            errors.append(f'inner {spec.inner!r} is not a known provider '
                          f'({sorted(KNOWN_PROVIDERS)})')
        try:
            make_backend(spec.vm)
        except VMBackendError as e:
            errors.append(f'vm backend: {e}')
    elif spec.provider == 'podman':
        for h in spec.hosts:
            if h.is_external:
                continue
            try:
                ref = spec.podman_image(h)
            except EnvSpecError as e:
                errors.append(str(e))
                continue
            if not is_channel(ref) and ':' not in ref and '/' not in ref:
                errors.append(
                    f'host {h.name}: image {ref!r} is neither a known build '
                    f'channel (freeipa-current/next/previous) nor an image '
                    f'reference (has no : or /)')
    elif spec.provider == 'external':
        for h in spec.hosts:
            if not h.address:
                errors.append(f'host {h.name}: external host has no address')
    return errors


def check_file(path):
    """Parse + validate one preset file. Returns a list of error strings."""
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f'YAML: {e}']
    except OSError as e:
        return [f'read: {e}']
    if not isinstance(doc, dict):
        return ['not a mapping']
    try:
        spec = EnvSpec.from_dict(doc)
    except EnvSpecError as e:
        return [f'spec: {e}']
    return check_spec(spec)


def discover(paths):
    """Expand paths (files or directories) into a sorted file list.
    Returns (files, missing)."""
    files = set()
    missing = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, fnames in os.walk(p):
                for fn in fnames:
                    if fn.endswith(('.yaml', '.yml')):
                        files.add(os.path.join(root, fn))
        elif os.path.isfile(p):
            files.add(p)
        else:
            missing.append(p)
    return sorted(files), missing


def check_paths(paths=None):
    """Check the given paths (default: all presets under ci/env/presets).
    Returns (results, missing) where results is [(path, [errors])]."""
    if not paths:
        paths = [os.path.join(queue.ENVROOT, 'presets')]
    files, missing = discover(paths)
    results = [(f, check_file(f)) for f in files]
    return results, missing
