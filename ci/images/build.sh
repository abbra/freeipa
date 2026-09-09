#!/bin/bash
# build.sh (A3) — build the freeipa-ci base and full images.
#
# Usage:
#   ci/images/build.sh --rpms /path/to/rpms --sha 962ac6d0e [options]
#   ci/images/build.sh --srpm /path/to/dist/srpms [options]
#
# Options:
#   --rpms DIR        Directory containing IPA dev-build RPMs (x86_64 +
#                     noarch, any layout).
#   --srpm PATH       Either a path to a single freeipa-*.src.rpm or a
#                     directory containing them (e.g. dist/srpms from
#                     `make srpms`). Builds the IPA binary RPMs ourselves
#                     inside the dedicated freeipa-ci/build image (base + all
#                     BuildRequires), then bakes the full image from them.
#                     Mutually exclusive with --rpms.
#   --sha SHORT_SHA   Git SHA of the IPA build to select from --rpms
#                     (matches the 'git<sha>' version fragment). Omit to
#                     pick the newest per package.
#   --dist N          Fedora dist tag, default 44 (image tags:
#                     <tag>/full:<dist>-<sha> and <tag>/full:<dist>).
#   --channel NAME    Build channel to publish, default current. Tags the
#                     built image as <tag>/full:<channel> (the abstract
#                     channel presets reference via `image: freeipa-<channel>`).
#                     One of: current, next, previous.
#   --tag NAME        Image repo name, default freeipa-ci.
#   --exclude GLOB    Skip files matching GLOB (repeatable). Debuginfo and
#                     debugsource are excluded by default.
#   --pin SPECS       'NVR ...' specs installed before the IPA RPMs
#                     (repo pinning, see full/Dockerfile).
#   --tool TOOL       Container tool: podman (default) or docker.
#
# Example (validation host):
#   ci/images/build.sh --rpms /root/rpmbuild/RPMS --sha 962ac6d0e \
#       --exclude freeipa-server-trust-ad --exclude freeipa-client-samba
#
# Build the IPA RPMs ourselves from a `make srpms` SRPM (control node ships
# the SRPM to the runner; the runner bakes the channel image from it):
#   ci/images/build.sh --srpm /root/freeipa/dist/srpms --channel current
set -euo pipefail

RPMS=
SRPM=
SHA=
DIST=44
TAG=freeipa-ci
CHANNEL=current
EXCLUDES=()
EXCLUDES+=('*debuginfo')
EXCLUDES+=('*debugsource')
PINS=
TOOL=podman
DISTARCH=x86_64
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpms) RPMS="$2"; shift 2 ;;
        --srpm) SRPM="$2"; shift 2 ;;
        --sha) SHA="$2"; shift 2 ;;
        --dist) DIST="$2"; shift 2 ;;
        --channel) CHANNEL="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --exclude) EXCLUDES+=("$2"); shift 2 ;;
        --pin) PINS="$2"; shift 2 ;;
        --tool) TOOL="$2"; shift 2 ;;
        --distarch) DISTARCH="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ -n "$RPMS" && -n "$SRPM" ]]; then
    echo "--rpms and --srpm are mutually exclusive" >&2; exit 2
fi
[[ -n "$RPMS" || -n "$SRPM" ]] || { echo "--rpms or --srpm is required" >&2; exit 2; }
command -v "$TOOL" >/dev/null || { echo "$TOOL not found" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d /tmp/freeipa-ci-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

BASE_IMAGE="$TAG/base:$DIST"
FULL_IMAGE="$TAG/full:$DIST"
SHA_TAG=""
[[ -n "$SHA" ]] && SHA_TAG="$DIST-$SHA"

if [[ "${BASE:-0}" != "1" ]]; then
    echo "==> Building base image $BASE_IMAGE"
    "$TOOL" build -f "$SCRIPT_DIR/base/Dockerfile" -t "$BASE_IMAGE" "$SCRIPT_DIR/base"
fi

# --- select the IPA RPM set (newest per package, scoped to --sha) ----------
# Delivered-RPM path only; --srpm builds the binary RPMs itself (below).
if [[ -n "$RPMS" ]]; then
mkdir -p "$WORK/rpms"
EXCLUDES_NEWLINE="$(printf '%s\n' "${EXCLUDES[@]}")"
export EXCLUDES_NEWLINE
python3 - "$RPMS" "$SHA" "$WORK/rpms" <<'PYEOF'
"""Select RPMs: newest version per package, scoped to --sha.

An rpm filename is <name>-<version>-<release>.<arch>.rpm where the
package name may itself contain dashes; the version field starts with a
digit, so the earliest dash-before-a-digit splits name from version.
"""
import fnmatch, os, re, shutil, sys

rpms_dir, sha, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
excludes = [l for l in os.environ['EXCLUDES_NEWLINE'].splitlines() if l]

NAME_VER_RE = re.compile(r'^(.*?)-(\d.*)\.[a-z0-9_]+\.rpm$')

def ver_key(fname):
    m = NAME_VER_RE.match(fname)
    if not m:
        return []
    return [int(x) if x.isdigit() else x
            for x in re.split(r'[.+\-]', m.group(2))]

candidates = {}
for root, _dirs, files in os.walk(rpms_dir):
    for fname in files:
        m = NAME_VER_RE.match(fname)
        if not m:
            continue
        pkg = m.group(1)
        if any(fnmatch.fnmatch(pkg, pat) or fnmatch.fnmatch(fname, pat)
               for pat in excludes):
            continue
        if sha and f'git{sha}' not in fname and f'git{sha[:7]}' not in fname:
            continue
        cur = candidates.get(pkg)
        if cur is None or ver_key(fname) > ver_key(cur[0]):
            candidates[pkg] = (fname, os.path.join(root, fname))

for pkg in sorted(candidates):
    fname, path = candidates[pkg]
    shutil.copy2(path, os.path.join(out_dir, fname))
    print(f'{pkg}: {fname}', file=sys.stderr)
print(f'selected {len(candidates)} packages', file=sys.stderr)
PYEOF

fi

# --- "build the IPA RPMs ourselves" lane: SRPM -> binary RPMs ---------------
# Instead of consuming RPMs delivered by a build farm, compile the SRPM (from
# `make srpms`) inside the dedicated build image, then let the full-image build
# below install the freshly built RPMs. Build and test share one distro repo
# snapshot per build, so a delivered-RPM dependency (e.g. samba) cannot drift
# out of resolution in the test image.
if [[ -n "$SRPM" ]]; then
    case "$SRPM" in
        *.src.rpm) SRPM_FILE="$SRPM" ;;
        *)
            [[ -d "$SRPM" ]] || { echo "--srpm: not a file or directory: $SRPM" >&2; exit 2; }
            SRPM_FILE="$(find "$SRPM" -name '*.src.rpm' | sort | tail -n 1)"
            [[ -n "$SRPM_FILE" ]] || { echo "--srpm: no .src.rpm found under $SRPM" >&2; exit 2; }
            ;;
    esac
    SRPM_DIR="$(dirname "$SRPM_FILE")"
    echo "==> Building IPA binary RPMs from $(basename "$SRPM_FILE")"

    # Dedicated build image (base + BuildRequires), baked once, not per build.
    BUILD_IMAGE="$TAG/build:$DIST"
    if [[ "${BASE:-0}" != "1" ]] && ! "$TOOL" image inspect "$BUILD_IMAGE" >/dev/null 2>&1; then
        echo "==> Building build image $BUILD_IMAGE"
        "$TOOL" build -f "$SCRIPT_DIR/build/Dockerfile" -t "$BUILD_IMAGE" \
            --build-arg "BASE=$BASE_IMAGE" "$SCRIPT_DIR/build"
    fi

    TOPDIR="$WORK/rpmbuild"
    mkdir -p "$TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    # The base (hence build) image's entrypoint is systemd: without an
    # override the rpmbuild command becomes systemd's arguments and the
    # container boots sshd/avahi/logind instead of running the build.
    # --rebuild unpacks the SRPM (spec -> SPECS/, sources -> SOURCES/) into
    # _topdir and builds the binary RPMs from it. --nocheck skips the spec's
    # %check (the full `make check` unit-test suite) -- CI runs tests in its
    # own `run` lane, so the build lane must not pay for it on a small runner.
    "$TOOL" run --rm \
        --entrypoint /bin/bash \
        -v "$SRPM_DIR":/root/build:z \
        -v "$TOPDIR":/root/rpmbuild:z \
        "$BUILD_IMAGE" \
        -c "rpmbuild --define '_topdir /root/rpmbuild' --nocheck --rebuild /root/build/$(basename "$SRPM_FILE")"

    mkdir -p "$WORK/rpms"
    find "$TOPDIR/RPMS" -name '*.rpm' \
        ! -name '*debuginfo*' ! -name '*debugsource*' \
        -exec cp {} "$WORK/rpms/" \;
    # Fail fast if rpmbuild produced nothing (e.g. the container misbehaved);
    # otherwise the full-image build dies on an empty rpms/ with a confusing
    # "Failed to access RPM /root/rpms/*.rpm" glob error.
    [[ -n "$(ls -A "$WORK/rpms")" ]] || {
        echo "build.sh --srpm: rpmbuild produced no RPMs in $TOPDIR/RPMS" >&2
        exit 1; }
fi

ls "$WORK/rpms"

# --- build the full image ----------------------------------------------------
echo "==> Building full image $FULL_IMAGE"
cp "$SCRIPT_DIR/full/Dockerfile" "$WORK/"
ARGS=(build -f "$WORK/Dockerfile" -t "$FULL_IMAGE" --build-arg "BASE=$BASE_IMAGE" "$WORK")
[[ -n "$PINS" ]] && ARGS+=(--build-arg "PIN_SPECS=$PINS")
"$TOOL" "${ARGS[@]}"

# Image tag contract:
#   <tag>/full:<dist>-<sha>  immutable per-build tag (provenance)
#   <tag>/full:<dist>        rolling dist pointer, re-pointed by every build
#   <tag>/full:<channel>     build channel (current/next/previous) — the
#                            abstract reference presets use. Presets name a
#                            channel (`image: freeipa-<channel>`), never a
#                            concrete build; the podman provider resolves the
#                            channel tag to the concrete image at up time
#                            (freeipa-env resolve).
CHANNEL_TAG="$TAG/full:$CHANNEL"
"$TOOL" tag "$FULL_IMAGE" "$CHANNEL_TAG"
echo "==> Tagged channel $CHANNEL_TAG (= $FULL_IMAGE)"
if [[ -n "$SHA_TAG" ]]; then
    "$TOOL" tag "$FULL_IMAGE" "$TAG/full:$SHA_TAG"
    echo "==> Tagged $TAG/full:$SHA_TAG (provenance)"
fi

echo "==> Done: $CHANNEL_TAG (channel ${SHA_TAG:+and $TAG/full:$SHA_TAG, rolling $FULL_IMAGE})"
