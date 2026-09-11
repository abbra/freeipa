"""Build the IPA RPMs ourselves, then bake the channel full image (design §3.10).

Replaces the "consume RPMs delivered by a build farm" model with a
self-contained build lane:

  1. the control node runs `make srpms` (``ci/scripts/make-srpms.sh``) to
     produce a ``freeipa-<ver>.src.rpm`` from the current git snapshot;
  2. that SRPM is shipped to the host that runs the environment (locally for
     a single machine, rsynced by the supervisor for a runner);
  3. on that host, ``ci/images/build.sh --srpm`` compiles the SRPM inside the
     dedicated ``freeipa-ci/build`` image (base + every BuildRequires) and
     bakes the ``freeipa-ci/full:<dist>`` image from the freshly built binary
     RPMs, tagging it with the build channel.

Building and testing share one distro repo snapshot per build, so a delivered
RPM's dependency (e.g. samba) cannot drift out of resolution in the test image
— the breakage class the external build farm used to produce.

This module is the provider-facing glue: given the spec's ``build:`` block and
a set of abstract channel references, it ensures each channel's full image is
present (building the absent ones from the SRPM, or rebuilding when forced),
delegating the actual image production to ``build.sh --srpm``.
"""

import os
import subprocess
import sys

from .image import channel_name, channel_tag, is_channel


class ImageBuildError(Exception):
    pass


def _images_dir():
    """Directory holding ci/images/build.sh (the repo's ci/images tree)."""
    # This file is ci/env/freeipa_env/imagemake.py -> up 2 dirs is ci/.
    return os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', 'images'))


def _build_sh():
    return os.path.join(_images_dir(), 'build.sh')


def build_sh_argv(srpm, channel, dist=None, tool='podman', tag=None,
                  copr=None):
    """Flag arguments (after the build.sh path) that make build.sh compile the
    SRPM and bake one channel image. Shared by the local build path (podman
    provider / `freeipa-env ensure`, which shells out to build.sh here) and
    the remote path (the queue supervisor, which runs the identical command
    on a runner) so both invoke build.sh identically."""
    args = ['--srpm', str(srpm),
            '--channel', str(channel),
            '--dist', str(dist or '44'),
            '--tool', str(tool or 'podman')]
    if tag:
        args += ['--tag', str(tag)]
    for repo in (copr or []):
        args += ['--copr', repo]
    return args


def ensure_channels(spec, workdir, channels, tool='podman', force=False,
                    copr=None):
    """Ensure each abstract channel reference's full image is present on this
    host, building the absent ones (or all, when ``force``) from the spec's
    ``build.srpm``. Returns {ref: (concrete_tag, image_id)}.

    Channels already present are left untouched unless ``force``; the SRPM is
    consumed only when a build is actually needed. Raises ImageBuildError if a
    build is required but the SRPM is missing or build.sh fails.
    """
    build = getattr(spec, 'build', None) or {}
    srpm = build.get('srpm')
    dist = getattr(spec, 'dist', None)
    out = {}
    for ref in channels:
        if not is_channel(ref):
            continue  # explicit refs are resolved by the provider, not built
        concrete = channel_tag(ref)
        # concrete is e.g. freeipa-ci/full:current; build.sh needs the repo
        # (tag) and the short channel name separately. build.sh composes
        # <tag>/full:<dist>, so strip the trailing /full from the repo.
        repo, _, _ = concrete.rpartition(':')
        tag = (repo[:-5] if repo.endswith('/full') else repo) or None
        cname = channel_name(ref)
        img_id = _image_id(tool, concrete)
        if img_id and not force:
            out[ref] = (concrete, img_id)
            continue
        if not srpm:
            raise ImageBuildError(
                f'channel {ref!r} needs a build but no build.srpm is set on '
                f'this env; run `ci/scripts/make-srpms.sh` and add a `build:` '
                f'block (or pass --srpm to the ensure command)')
        _build_one(tool, srpm, cname, dist, tag, workdir, force, copr)
        img_id = _image_id(tool, concrete)
        if not img_id:
            raise ImageBuildError(
                f'build.sh reported success but channel image {concrete} is '
                f'still not present on this host')
        out[ref] = (concrete, img_id)
    return out


def _build_one(tool, srpm, channel, dist, tag, workdir, force, copr=None):
    """Run build.sh --srpm to (re)build one channel image; stream output to
    workdir/logs/images-build.log and the caller's stderr."""
    args = ['bash', _build_sh()] + build_sh_argv(
        srpm, channel, dist=dist, tool=tool, tag=tag, copr=copr)
    verb = 'rebuilding' if force else 'building'
    print(f'== {verb} channel image for {channel} from SRPM {srpm}',
          file=sys.stderr)
    logpath = os.path.join(workdir, 'logs', 'images-build.log')
    os.makedirs(os.path.dirname(logpath), exist_ok=True)
    # Stream the build live to the terminal and append to the log at the
    # same time (a multi-minute rpmbuild + image bake must not be buffered
    # until the end).
    with open(logpath, 'a') as lf, subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, bufsize=1,
            universal_newlines=True) as p:
        header = f'== {verb} channel {channel} (srpm={srpm}, ' \
                 f'dist={dist or 44})'
        lf.write(header + '\n')
        lf.flush()
        for line in p.stdout:
            sys.stderr.write(line)
            lf.write(line)
        lf.flush()
        rc = p.wait()
    if rc != 0:
        raise ImageBuildError(
            f'build.sh --srpm failed ({rc}) for channel {channel!r}; '
            f'see {logpath}')


def _image_id(tool, ref):
    """Local image id for ref, or None if not present."""
    try:
        p = subprocess.run(
            [tool, 'image', 'inspect', ref, '--format', '{{.Id}}'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise ImageBuildError(f'{tool} not found')
    if p.returncode == 0 and p.stdout.strip():
        return p.stdout.decode().strip()
    return None
