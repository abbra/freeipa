#!/bin/bash
# Run a FreeIPA env queue job on a Testing Farm guest.
#
# Invoked by the tmt test (ci/tmt/tests/freeipa-env/main.fmf). The plan's
# prepare step (how: install) has already placed podman, curl and every
# BuildRequires of freeipa.spec.in on the guest, so the SRPM can be produced
# here without any pre-supplied artifact. The request variables (see
# freeipa_env.testingfarm.build_tf_request) carry FREEIPA_REPO_URL/REF: TF's
# pipeline syncs the fmf tree (TMT_TREE) to the guest as a plain file copy
# (no .git, no submodule contents), so the full flow clones the repo itself
# on the guest. The guest runs as root, so this
# script:
#   1. obtains the preset's channel image (freshness-checked, like the
#      supervisor's remote build):
#        * if FREEIPA_SRPM_URL is set -> download that SRPM;
#        * otherwise (full flow)      -> build freeipa's SRPM ON THE GUEST
#          from the repo it cloned (FREEIPA_REPO_URL@FREEIPA_REPO_REF),
#      then bake the channel image from it (ci/images/build.sh --srpm);
#   2. drives the same `freeipa-env` up -> run -> down recipe a local or ssh
#      runner would, and exits with the `run` step's status.
#
set -uo pipefail

: "${FREEIPA_PRESET:?FREEIPA_PRESET is required (the preset, relative to ci/env)}"

TREE="${TMT_TREE:-$(cd "$(dirname "$0")/../../.." && pwd)}"
CI="$TREE/ci"
CLI="$CI/env/freeipa-env"
ENFFILE="$CI/env/$FREEIPA_PRESET"
JOBKEY="${FREEIPA_JOB_KEY:-$(printf '%s' "$FREEIPA_PRESET" | tr '/' '-')}"
# the request passes a runner-style ~/... path; expand it against the guest
# (root) home, with a default mirroring the supervisor's jobs dir.
WORKDIR="${FREEIPA_WORKDIR:-~/freeipa-jobs/$JOBKEY}"
WORKDIR="${WORKDIR/#\~/$HOME}"
TIMEOUT="${FREEIPA_JOB_TIMEOUT:-14400}"
SRPM_URL="${FREEIPA_SRPM_URL:-}"
CHANNEL="${FREEIPA_CHANNEL:-}"
REPO_URL="${FREEIPA_REPO_URL:-}"
REPO_REF="${FREEIPA_REPO_REF:-HEAD}"

die() { echo "FATAL: $*" >&2; exit 1; }
[ -f "$ENFFILE" ] || die "preset not found: $ENFFILE (FREEIPA_PRESET=$FREEIPA_PRESET)"

echo "== tf-runner: preset=$FREEIPA_PRESET workdir=$WORKDIR timeout=${TIMEOUT}s srpm=${SRPM_URL:-<none>}"

# podman is installed by the plan's prepare step; keep a guard so a missing
# tool fails with a clear message instead of a cryptic `podman` not found.
command -v podman >/dev/null 2>&1 || die "podman not found on the guest (prepare step should have installed it)"
echo "podman: $(podman --version 2>/dev/null | head -1)"
[ -d /run/systemd/system ] && echo "systemd: running" \
    || echo "WARN: systemd not detected; the podman provider may time out waiting for multi-user.target"

# --- resolve the channel + dist the preset needs ----------------------------
# The channel image tag (freeipa-ci/full:<channel>) is what the preset's
# `image: freeipa-<channel>` reference resolves to. Only the three abstract
# channels are buildable (see freeipa_env.image.is_channel); a concrete image
# reference or a missing line skips the build and lets `up`/`resolve` report
# the usual "image not found; build it" error.
if [ -z "$CHANNEL" ]; then
    image="$(sed -nE 's/^image:[[:space:]]*//p' "$ENFFILE" | head -n1 | tr -d '[:space:]"' )"
    case "$image" in
        freeipa-current|freeipa-next|freeipa-previous) CHANNEL="${image#freeipa-}" ;;
        '') echo "WARN: preset has no `image:` line; skipping the channel-image build" ;;
        *) echo "WARN: preset image '$image' is not a known freeipa-* channel; skipping the channel-image build" ;;
    esac
fi
DIST="$(sed -nE 's/^dist:[[:space:]]*//p' "$ENFFILE" | head -n1 | tr -d '[:space:]"' )"
[ -n "$DIST" ] || DIST=44

# build_srpm_from_clone OUT_DIR
#   Build freeipa's SRPM DIRECTLY ON THE GUEST. The plan's prepare step
#   already installed the whole BuildRequires set + toolchain, so no build
#   image is needed. Mirrors makerpms.sh (autoreconf + configure with the
#   spec's rpm-equivalent flags) but only produces the SRPM (make srpms, no
#   binaries, no %check).
#
#   Source: TF's pipeline syncs the fmf tree (TMT_TREE) to the guest as a
#   plain file copy -- no .git, and no submodule contents either (the
#   install/freeipa-webui submodule feeds the dist tarball) -- so it cannot
#   be built from. When FREEIPA_REPO_URL is set, the guest clones the repo
#   itself (git clone --recursive + checkout of FREEIPA_REPO_REF); otherwise
#   TMT_TREE is used, but only if it is a real clone.
build_srpm_from_clone() {
    outdir="$1"
    if [ -n "$REPO_URL" ]; then
        SRC="$WORKDIR/src"
        rm -rf "$SRC"
        echo "==> git clone --recursive $REPO_URL (ref: $REPO_REF) -> $SRC"
        git clone --recursive "$REPO_URL" "$SRC" \
            || die "git clone of $REPO_URL failed"
        cd "$SRC" || die "cannot cd to $SRC"
        [ "$REPO_REF" = "HEAD" ] || \
            git checkout "$REPO_REF" || die "git checkout $REPO_REF failed"
        git submodule update --init --recursive \
            || die "git submodule update failed"
    else
        SRC="$TREE"
        cd "$SRC" || die "cannot cd to $SRC"
        [ -d .git ] || die "no .git in $SRC and no FREEIPA_REPO_URL given; a plain file copy cannot be built (submodules are missing)"
        git submodule update --init --recursive \
            || die "git submodule update failed"
    fi
    git checkout po/*.po 2>/dev/null || true
    test -x configure && echo "configure: present" \
        || { echo "==> autoreconf -i"; autoreconf -i || die "autoreconf -i failed"; }
    echo "==> ./configure (spec-equivalent rpm flags)"
    ./configure --enable-silent-rules \
        --host="$(rpm -E %{_host})" \
        --build="$(rpm -E %{_build})" \
        --prefix="$(rpm -E %{_prefix})" \
        --exec-prefix="$(rpm -E %{_exec_prefix})" \
        --bindir="$(rpm -E %{_bindir})" \
        --sbindir="$(rpm -E %{_sbindir})" \
        --sysconfdir="$(rpm -E %{_sysconfdir})" \
        --datadir="$(rpm -E %{_datadir})" \
        --includedir="$(rpm -E %{_includedir})" \
        --libdir="$(rpm -E %{_libdir})" \
        --libexecdir="$(rpm -E %{_libexecdir})" \
        --localstatedir="$(rpm -E %{_localstatedir})" \
        --sharedstatedir="$(rpm -E %{_sharedstatedir})" \
        --mandir="$(rpm -E %{_mandir})" \
        --infodir="$(rpm -E %{_infodir})" || die "configure failed"

    echo "==> make srpms (on the guest)"
    make srpms || die "make srpms failed"
    ls "$SRC"/dist/srpms/

    cp "$SRC"/dist/srpms/*.src.rpm "$outdir/" \
        || die "make srpms produced no .src.rpm in dist/srpms"
    cd "$CI" || die "cannot cd back to $CI"
}

# --- ensure the channel image (obtain an SRPM + build when needed) ----------
# Mirrors runner._build_channels_on: a present image is left untouched; an
# absent one is baked from an SRPM. The SRPM is either downloaded
# (FREEIPA_SRPM_URL) or built on the guest from the clone (full flow).
if [ -n "$CHANNEL" ]; then
    imgref="freeipa-ci/full:$CHANNEL"
    if podman image inspect "$imgref" >/dev/null 2>&1; then
        echo "== channel $CHANNEL image present; leaving untouched"
    else
        srpm_dir="$WORKDIR/srpm"
        mkdir -p "$srpm_dir"
        if [ -n "$SRPM_URL" ]; then
            echo "== downloading SRPM $SRPM_URL -> $srpm_dir/"
            curl -fsSL -o "$srpm_dir/freeipa.src.rpm" "$SRPM_URL" \
                || die "failed to download SRPM from $SRPM_URL"
        else
            if [ -n "$REPO_URL" ]; then
                echo "== full flow: no SRPM URL; building freeipa's SRPM on the guest (cloning $REPO_URL @ $REPO_REF)"
            else
                echo "== full flow: no SRPM URL; building freeipa's SRPM on the guest from $TREE"
            fi
            build_srpm_from_clone "$srpm_dir"
        fi
        ls -l "$srpm_dir"
        echo "== building channel $CHANNEL image from SRPM (dist $DIST)"
        # build.sh builds the base + build images itself when absent
        # (BASE is not forced), so this one call covers both the SRPM-URL
        # path and the full-flow path.
        bash "$CI/images/build.sh" --srpm "$srpm_dir" --channel "$CHANNEL" \
            --dist "$DIST" --tool podman || die "channel image build failed for $CHANNEL"
        podman image inspect "$imgref" >/dev/null 2>&1 \
            || die "build succeeded but $imgref is still missing"
    fi
fi

# --- the up -> run -> down recipe (identical to a local/ssh job) ------------
cd "$CI" || die "cannot cd to $CI"

echo "== up: $CLI up $ENFFILE --workdir $WORKDIR"
up_out="$("$CLI" up "$ENFFILE" --workdir "$WORKDIR" 2>&1)"
up_rc=$?
echo "$up_out"
if [ "$up_rc" -ne 0 ]; then
    echo "== down (cleanup after up failure): $CLI down $ENFFILE --workdir $WORKDIR"
    "$CLI" down "$ENFFILE" --workdir "$WORKDIR" >/dev/null 2>&1 || true
    exit 1
fi

echo "== run: $CLI run $ENFFILE --workdir $WORKDIR"
run_out="$("$CLI" run "$ENFFILE" --workdir "$WORKDIR" 2>&1)"
run_rc=$?
echo "$run_out"

# best-effort teardown: the guest is ephemeral, but a clean down also collects
# the workdir logs; its status never masks the run result.
echo "== down: $CLI down $ENFFILE --workdir $WORKDIR"
"$CLI" down "$ENFFILE" --workdir "$WORKDIR" 2>&1 || true

exit "$run_rc"
