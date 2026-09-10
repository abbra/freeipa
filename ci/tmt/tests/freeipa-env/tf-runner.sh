#!/bin/bash
# Run a FreeIPA env queue BATCH on a Testing Farm guest (one TF request).
#
# Invoked by the tmt test (ci/tmt/tests/freeipa-env/main.fmf). The plan's
# prepare step (how: install) has already placed podman, curl and every
# BuildRequires of freeipa.spec.in on the guest, so the SRPM can be produced
# here without any pre-supplied artifact.
#
# A request carries a LIST of queue jobs (FREEIPA_JOBS, a JSON array) that all
# run in this one guest. The point: build freeipa's SRPM and the channel
# images ONCE and reuse them across every preset in the batch, instead of the
# old one-request-per-job model that rebuilt them for each job.
#
# Flow:
#   1. parse FREEIPA_JOBS -> the list of (key, preset) jobs;
#   2. obtain the SRPM (download FREEIPA_SRPM_URL, or build it ON the guest
#      from the repo it cloned -- TF syncs the fmf tree as a plain file copy
#      with no .git/submodules, so the guest clones itself when
#      FREEIPA_REPO_URL is set). Needed only if a channel image is missing;
#   3. build the union of the batch's channel images, each freshness-checked
#      (a present freeipa-ci/full:<channel> is left untouched);
#   4. run each preset's up -> run -> down recipe via tf-job.sh, which stages
#      its own per-preset results.yaml + artifacts under the test data dir;
#   5. reparent each preset's collected artifacts into artifacts/<key>/ so the
#      host maps each preset back to its own local workdir.
#
# The test is declared `result: custom` in main.fmf: tmt (1.77+) takes the
# outcome from $TMT_TEST_DATA/results.yaml (the batch parent) plus each
# preset's $TMT_TEST_DATA/<key>/results.yaml (its own stages). The staged
# machinery in stage-lib.sh records the stages with live logs; TF uploads the
# whole tmt workdir, so every stage and artifact shows up in results.xml.
#
set -uo pipefail

TREE="${TMT_TREE:-$(cd "$(dirname "$0")/../../.." && pwd)}"
CI="$TREE/ci"
CLI="$CI/env/freeipa-env"
export CI CLI

# --- the batch: a JSON array of {key, preset_rel} (from build_tf_request) ---
# Backward compat: a request with the old single-preset vars (no FREEIPA_JOBS)
# becomes a one-job batch.
if [ -z "${FREEIPA_JOBS:-}" ]; then
    : "${FREEIPA_PRESET:?FREEIPA_PRESET or FREEIPA_JOBS is required}"
    LEGACY_KEY="${FREEIPA_JOB_KEY:-$(printf '%s' "$FREEIPA_PRESET" | tr '/' '-')}"
    FREEIPA_JOBS="$(printf '[{"key": "%s", "preset_rel": "%s"}]' \
        "$LEGACY_KEY" "$FREEIPA_PRESET")"
fi
export FREEIPA_JOBS

# Parse the job list into "key<TAB>preset" lines (tab- and newline-free fields).
command -v python3 >/dev/null 2>&1 \
    || { echo "FATAL: python3 not found on the guest" >&2; exit 1; }
JOB_LINES="$(python3 - "$FREEIPA_JOBS" <<'PY'
import json, sys
jobs = json.loads(sys.argv[1])
for j in jobs:
    key, preset = j['key'], j['preset_rel']
    for bad in ('\t', '\n'):
        key = key.replace(bad, '_')
        preset = preset.replace(bad, ' ')
    print(f'{key}\t{preset}')
PY
)" || die "could not parse FREEIPA_JOBS: $FREEIPA_JOBS"
[ -n "$JOB_LINES" ] || die "FREEIPA_JOBS parsed to an empty job list"

# stage-lib.sh requires WORKDIR before sourcing. In the batch model the per
# preset workdir only exists inside its tf-job.sh child (it derives
# WORKDIR from JOB_WORKDIR), so the driver points its own namespace at the
# batch home: the driver's stage logs + the batch-parent results.yaml live
# under $STAGEDATA (the tmt test data dir) and the batch home doubles as the
# WORKDIR stage-lib's fallback needs (per-preset jobs use their own).
WORKDIR="$HOME/freeipa-jobs"
# staged results machinery (driver namespace: the tmt test data dir). The
# driver's own results.yaml is the batch parent; each preset child writes its
# own under <key>/ (see tf-job.sh).
source "$CI/tmt/tests/freeipa-env/stage-lib.sh"

# podman is installed by the plan's prepare step; keep a guard so a missing
# tool fails with a clear message instead of a cryptic `podman` not found.
command -v podman >/dev/null 2>&1 || die "podman not found on the guest (prepare step should have installed it)"
echo "podman: $(podman --version 2>/dev/null | head -1)"
[ -d /run/systemd/system ] && echo "systemd: running" \
    || echo "WARN: systemd not detected; the podman provider may time out waiting for multi-user.target"

SRPM_URL="${FREEIPA_SRPM_URL:-}"
REPO_URL="${FREEIPA_REPO_URL:-}"
REPO_REF="${FREEIPA_REPO_REF:-HEAD}"
GLOBAL_CHANNEL="${FREEIPA_CHANNEL:-}"
BATCH_HOME="$HOME/freeipa-jobs"
SRPM_DIR="$BATCH_HOME/batch-srpm"

echo "== tf-runner: batch of $(printf '%s\n' "$JOB_LINES" | grep -c .) job(s); staged results -> $STAGEDATA"

# --- collect the batch's channel images (union across presets) --------------
# Only the three abstract channels are buildable (freeipa_env.image.is_channel);
# a concrete image reference or missing `image:` line skips the build and lets
# `up`/`resolve` report the usual "image not found; build it" error. The
# queue-level FREEIPA_CHANNEL overrides the per-preset channel for every job.
CHANNELS=""
add_channel() {
    case " $CHANNELS " in
        *" $1 "*) ;;
        *) CHANNELS="${CHANNELS:+$CHANNELS }$1" ;;
    esac
}
while IFS=$'\t' read -r JK JPRESET; do
    [ -n "$JPRESET" ] || continue
    [ -f "$CI/env/$JPRESET" ] || die "preset not found: $CI/env/$JPRESET"
    if [ -n "$GLOBAL_CHANNEL" ]; then
        add_channel "$GLOBAL_CHANNEL"
    else
        image="$(sed -nE 's/^image:[[:space:]]*//p' "$CI/env/$JPRESET" | head -n1 | tr -d '[:space:]"' )"
        case "$image" in
            freeipa-current|freeipa-next|freeipa-previous) add_channel "${image#freeipa-}" ;;
        esac
    fi
done <<EOF
$JOB_LINES
EOF

# build_srpm_from_clone OUT_DIR
#   Build freeipa's SRPM DIRECTLY ON THE GUEST. The plan's prepare step
#   already installed the whole BuildRequires set + toolchain, so no build
#   image is needed. Mirrors makerpms.sh (autoreconf + configure with the
#   spec's rpm-equivalent flags) but only produces the SRPM (make srpms, no
#   binaries, no %check). TF's pipeline syncs the fmf tree as a plain file
#   copy (no .git, no submodule contents), so the guest clones the repo
#   itself when FREEIPA_REPO_URL is set; otherwise TMT_TREE is used only if
#   it is a real clone.
build_srpm_from_clone() {
    outdir="$1"
    if [ -n "$REPO_URL" ]; then
        SRC="$BATCH_HOME/src"
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

# --- ensure the SRPM + every missing channel image (build ONCE) -------------
# The SRPM is only needed when at least one channel image is absent (a batch
# whose images are all pre-baked skips both the SRPM build and the bake).
MISSING=""
for c in $CHANNELS; do
    if ! podman image inspect "freeipa-ci/full:$c" >/dev/null 2>&1; then
        MISSING="${MISSING:+$MISSING }$c"
    fi
done
if [ -n "$MISSING" ]; then
    mkdir -p "$SRPM_DIR"
    if [ -n "$SRPM_URL" ]; then
        echo "== downloading SRPM $SRPM_URL -> $SRPM_DIR/"
        curl -fsSL -o "$SRPM_DIR/freeipa.src.rpm" "$SRPM_URL" \
            || die "failed to download SRPM from $SRPM_URL"
    elif [ -n "$REPO_URL" ]; then
        echo "== full flow: no SRPM URL; building freeipa's SRPM on the guest (cloning $REPO_URL @ $REPO_REF)"
        build_srpm_from_clone "$SRPM_DIR" || die "SRPM build on the guest failed"
    else
        build_srpm_from_clone "$SRPM_DIR" || die "SRPM build on the guest failed"
    fi
    ls -l "$SRPM_DIR"
    for c in $MISSING; do
        echo "== building channel $c image from SRPM"
        # build.sh builds the base + build images itself when absent, so this
        # one call covers both the SRPM-URL and the full-flow paths; present
        # channel images were skipped above (freshness: build once, reuse).
        bash "$CI/images/build.sh" --srpm "$SRPM_DIR" --channel "$c" \
            --tool podman || die "channel image build failed for $c"
        podman image inspect "freeipa-ci/full:$c" >/dev/null 2>&1 \
            || die "build succeeded but freeipa-ci/full:$c is still missing"
    done
else
    echo "== all channel image(s) present: $(echo $CHANNELS); SRPM build skipped"
fi

# --- run each preset's recipe (per-preset staged results) -------------------
cd "$CI" || die "cannot cd to $CI"
WORST_RC=0
JOBS_NOTED=""
# Read the job list from fd 3, NOT fd 0. tf-job.sh (and its podman/ssh/test
# descendants) inherits the loop's stdin; if the list lived on fd 0 the
# first job's child would consume the remaining lines, so the outer read
# would hit EOF and every preset after the first would be silently skipped --
# while WORST_RC stayed 0 and the batch still reported as passed. A dedicated
# fd keeps the list out of reach of any child process. The child's own stdin
# is pinned to /dev/null (a batch job is non-interactive; never read fd 0).
while IFS=$'\t' read -r -u 3 JK JPRESET; do
    [ -n "$JK" ] || continue
    echo ""
    echo "########## job $JK: preset=$JPRESET ##########"
    export JOBKEY="$JK" ENFPRESET="$JPRESET" \
        JOB_WORKDIR="$BATCH_HOME/$JK"
    bash "$CI/tmt/tests/freeipa-env/tf-job.sh" </dev/null
    rc=$?
    [ "$rc" -gt "$WORST_RC" ] && WORST_RC=$rc
    JOBS_NOTED="${JOBS_NOTED:+$JOBS_NOTED, }$JK=rc$rc"
done 3<<EOF
$JOB_LINES
EOF

# --- reparent each preset's collected artifacts into artifacts/<key>/ -------
# tf-job.sh staged them under <key>/artifacts/ (so they never collided while
# running); the host's fetch_artifacts maps .../artifacts/<key>/<rel> back to
# the <key> job's local workdir/logs/<rel>.
mkdir -p "$STAGEDATA/artifacts"
for d in "$STAGEDATA"/*/; do
    key="$(basename "$d")"
    [ -d "$STAGEDATA/artifacts/$key" ] && continue
    if [ -d "$d/artifacts" ]; then
        mv "$d/artifacts" "$STAGEDATA/artifacts/$key" \
            && echo "== reparented $STAGEDATA/$key/artifacts -> $STAGEDATA/artifacts/$key/"
    fi
done

# --- batch parent results ---------------------------------------------------
[ "$WORST_RC" -eq 0 ] || OVERALL=fail
if [ -n "$FATAL_NOTE" ]; then
    :  # a die() set the parent note (and exited via the trap)
else
    # The batch summary is informational, not a fatal: a green batch must not
    # carry a "fatal:" note. Only a die() (a genuine fatal that exits) leaves
    # FATAL_NOTE set; on the normal completion path it is empty, so the
    # summary goes in PARENT_NOTE and is emitted without the fatal: prefix.
    PARENT_NOTE="batch: $(printf '%s\n' "$JOB_LINES" | grep -c .) job(s); $JOBS_NOTED"
fi
RUN_RC="$WORST_RC"
write_results
rm -f "$STAGEDATA/.results-pending"
echo "== results: $RESULTS_FILE"
echo "== batch finished, worst job rc $WORST_RC"
exit "$WORST_RC"
