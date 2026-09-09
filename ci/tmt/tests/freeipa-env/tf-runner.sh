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
# on the guest. The guest runs as root, so this script:
#   1. obtains the preset's channel image (freshness-checked, like the
#      supervisor's remote build):
#        * if FREEIPA_SRPM_URL is set -> download that SRPM;
#        * otherwise (full flow)      -> build freeipa's SRPM ON THE GUEST
#          from the repo it cloned (FREEIPA_REPO_URL@FREEIPA_REPO_REF),
#      then bake the channel image from it (ci/images/build.sh --srpm);
#   2. drives the same `freeipa-env` up -> run -> down recipe a local or ssh
#      runner would, and exits with the `run` step's status.
#
# The test is declared `result: custom` in main.fmf: tmt (1.77+) then takes
# the outcome from $TMT_TEST_DATA/results.yaml instead of the exit code.
# The staged machinery in stage-lib.sh (same directory) records each stage
# (srpm-build, image-build, env-up, test-run, env-down) with its own live
# log, and after the recipe the job workdir artifacts (run console, xunit
# report, collected host logs) are copied to $TMT_TEST_DATA/artifacts/.
# Testing Farm uploads the whole tmt workdir, so every stage shows up in
# results.xml as its own testcase with a downloadable log, and the job
# artifacts are downloadable under .../data/artifacts/.
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

# staged results machinery (logs under $TMT_TEST_DATA + results.yaml +
# EXIT-trap fallback that still writes results on early death)
source "$CI/tmt/tests/freeipa-env/stage-lib.sh"

echo "== tf-runner: preset=$FREEIPA_PRESET workdir=$WORKDIR timeout=${TIMEOUT}s srpm=${SRPM_URL:-<none>}"
echo "== tf-runner: staged results -> $STAGEDATA"

[ -f "$ENFFILE" ] || die "preset not found: $ENFFILE (FREEIPA_PRESET=$FREEIPA_PRESET)"

# podman is installed by the plan's prepare step; keep a guard so a missing
# tool fails with a clear message instead of a cryptic `podman` not found.
command -v podman >/dev/null 2>&1 || die "podman not found on the guest (prepare step should have installed it)"
echo "podman: $(podman --version 2>/dev/null | head -1)"
[ -d /run/systemd/system ] && echo "systemd: running" \
    || echo "WARN: systemd not detected; the podman provider may time out waiting for multi-user.target"

# --- resolve the channel + dist the preset needs -----------------------------
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
#   (Runs in the stage_run subshell: cd/exit stay contained.)
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
        stage_begin image-build
        stage_set info "image $imgref already present; build skipped"
        STAGE_END[image-build]=$(date +%s)
    else
        srpm_dir="$WORKDIR/srpm"
        mkdir -p "$srpm_dir"
        if [ -n "$SRPM_URL" ]; then
            echo "== downloading SRPM $SRPM_URL -> $srpm_dir/"
            stage_begin srpm-build
            curl -fsSL -o "$srpm_dir/freeipa.src.rpm" "$SRPM_URL" 2>&1 | tee "$STAGEDATA/srpm-build.log"
            stage_record "${PIPESTATUS[0]}"
            [ "${STAGE_RC[srpm-build]}" -eq 0 ] || die "failed to download SRPM from $SRPM_URL"
        else
            if [ -n "$REPO_URL" ]; then
                echo "== full flow: no SRPM URL; building freeipa's SRPM on the guest (cloning $REPO_URL @ $REPO_REF)"
            else
                echo "== full flow: no SRPM URL; building freeipa's SRPM on the guest from $TREE"
            fi
            stage_run srpm-build build_srpm_from_clone "$srpm_dir" \
                || die "SRPM build on the guest failed"
        fi
        ls -l "$srpm_dir"
        echo "== building channel $CHANNEL image from SRPM (dist $DIST)"
        # build.sh builds the base + build images itself when absent
        # (BASE is not forced), so this one call covers both the SRPM-URL
        # path and the full-flow path.
        stage_run image-build bash "$CI/images/build.sh" --srpm "$srpm_dir" \
            --channel "$CHANNEL" --dist "$DIST" --tool podman \
            || die "channel image build failed for $CHANNEL"
        podman image inspect "$imgref" >/dev/null 2>&1 \
            || die "build succeeded but $imgref is still missing"
    fi
fi

# --- the up -> run -> down recipe (identical to a local/ssh job) ------------
cd "$CI" || die "cannot cd to $CI"

echo "== up: $CLI up $ENFFILE --workdir $WORKDIR"
stage_begin env-up
"$CLI" up "$ENFFILE" --workdir "$WORKDIR" 2>&1 | tee "$STAGEDATA/env-up.log"
stage_record "${PIPESTATUS[0]}"
if [ "${STAGE_RC[env-up]}" -ne 0 ]; then
    FATAL_NOTE="env up failed (rc ${STAGE_RC[env-up]})"
    OVERALL=fail
    STAGE_END[env-up]=$(date +%s)
    # cleanup so the guest does not leak containers; best effort, and it
    # becomes its own (warned) stage so it is visible in TF
    echo "== down (cleanup after up failure): $CLI down $ENFFILE --workdir $WORKDIR"
    stage_begin env-down
    "$CLI" down "$ENFFILE" --workdir "$WORKDIR" 2>&1 | tee "$STAGEDATA/env-down.log"
    stage_record "${PIPESTATUS[0]}"
    [ "${STAGE_RC[env-down]}" -eq 0 ] || stage_set warn "cleanup down rc ${STAGE_RC[env-down]} after up failure"
    write_results; rm -f "$STAGEDATA/.results-pending"
    exit 1
fi

echo "== run: $CLI run $ENFFILE --workdir $WORKDIR"
stage_run test-run "$CLI" run "$ENFFILE" --workdir "$WORKDIR"
RUN_RC=$?
[ "$RUN_RC" -eq 0 ] || OVERALL=fail

# best-effort teardown: the guest is ephemeral, but a clean down also collects
# the workdir logs; its status never masks the run result.
echo "== down: $CLI down $ENFFILE --workdir $WORKDIR"
stage_begin env-down
"$CLI" down "$ENFFILE" --workdir "$WORKDIR" 2>&1 | tee "$STAGEDATA/env-down.log"
stage_record "${PIPESTATUS[0]}"
[ "${STAGE_RC[env-down]}" -eq 0 ] || \
    stage_set warn "down rc ${STAGE_RC[env-down]} (best effort; does not mask the run result)"

# --- collect the job artifacts into the uploaded test data dir --------------
# The job workdir itself is NOT part of the tmt workdir TF uploads, so the
# job's own artifacts must be copied here to be downloadable: the run console
# (the tmt-managed output.txt only carries the outer script's stdout), the
# xunit report, and the collected per-host logs.
cp -f "$STAGEDATA/test-run.log" "$STAGEDATA/run.log" 2>/dev/null || true
if [ -d "$WORKDIR/logs" ]; then
    mkdir -p "$STAGEDATA/artifacts"
    cp -rf "$WORKDIR/logs/." "$STAGEDATA/artifacts/" 2>/dev/null \
        && echo "== collected $WORKDIR/logs -> $STAGEDATA/artifacts/" \
        || echo "WARN: could not copy $WORKDIR/logs"
fi
if [ -f "$WORKDIR/nosetests.xml" ]; then
    mkdir -p "$STAGEDATA/artifacts"
    cp -f "$WORKDIR/nosetests.xml" "$STAGEDATA/artifacts/nosetests.xml"
fi

write_results
rm -f "$STAGEDATA/.results-pending"
echo "== results: $RESULTS_FILE"
echo "== run finished with exit code $RUN_RC"
exit "$RUN_RC"
