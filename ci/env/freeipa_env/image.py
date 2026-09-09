"""Abstract image build channels.

A preset references an *abstract channel name* (``image: freeipa-current``),
never a concrete build — mirroring how PRCI definitions reference one build
generation per file (``fedora-latest`` / ``fedora-previous`` /
``fedora-rawhide``). The build/promotion step tags the concrete image with
the channel tag; the *provider* resolves the abstract name to the concrete
image at ``up`` time. Presets therefore stay provider-agnostic: a
podman provider resolves the channel against the local image store, while an
external provider ignores it (external hosts run their own IPA).
"""

# Abstract channel name (the preset `image:` value) -> podman channel tag.
# The podman tag lives under the same `freeipa-ci/full` repo as the
# dist (`44`) and provenance (`44-<sha>`) tags; only the tag name differs.
CHANNELS = {
    'freeipa-current': 'freeipa-ci/full:current',
    'freeipa-next': 'freeipa-ci/full:next',
    'freeipa-previous': 'freeipa-ci/full:previous',
}

DEFAULT_CHANNEL = 'freeipa-current'


def is_channel(ref):
    """True if ref is a known abstract channel name."""
    return ref in CHANNELS


def channel_tag(ref):
    """Abstract channel name -> podman channel tag.

    Non-channel references (e.g. an explicit ``freeipa-ci/full:44-abc``)
    pass through unchanged so presets may still name a concrete build."""
    return CHANNELS.get(ref, ref)


def channel_name(ref):
    """Abstract channel name -> short channel name (``current`` / ``next`` /
    ``previous``), the value ``ci/images/build.sh --channel NAME`` takes.
    Returns ``None`` if ``ref`` is not a known abstract channel."""
    if ref in CHANNELS:
        return ref.split('-', 1)[1]
    return None


def channel_from_prefix(prefix):
    """Map a PRCI job prefix to an abstract channel name.

    PRCI encodes the build generation in the job prefix
    (``fedora-latest/``, ``fedora-previous/``, ``fedora-rawhide/`` or a
    component channel like ``389ds-fedora/``). Rule:
      * ``previous`` in the prefix   -> freeipa-previous
      * ``rawhide``  in the prefix   -> freeipa-next  (the next release)
      * anything else (``latest`` or a component channel) -> freeipa-current
    """
    p = (prefix or '').lower()
    if 'previous' in p:
        return 'freeipa-previous'
    if 'rawhide' in p:
        return 'freeipa-next'
    return DEFAULT_CHANNEL
