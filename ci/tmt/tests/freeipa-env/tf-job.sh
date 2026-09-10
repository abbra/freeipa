#!/bin/bash
# Run ONE preset's env recipe on a Testing Farm guest, as a child of the
# tf-runner.sh batch driver.
#
# The driver (tf-runner.sh) has already obtained the SRPM and built every
# channel image the batch needs (build-once, reuse-across-presets); this
# child only drives the `freeipa-env` up -> run -> down recipe for its one
# preset and stages its own per-preset results.
#
# Env contract (set by the driver):
#   JOBKEY          the queue job key (dir name; also the preset fallback)
#   ENFPRESET       the preset, relative to ci/env (e.g. netgroup/azure/enf)
#   JOB_WORKDIR     this job's workdir (already ~-expanded by the driver)
#   CI, CLI         paths to the ci/ tree and the freeipa-env CLI
#   TMT_TEST_DATA   the tmt test data dir (the driver's STAGEDATA); this
#                   child stages into $TMT_TEST_DATA/$JOBKEY/
#
# Staged results (stage-lib.sh) are namespaced per key: stage logs +
# collected artifacts under $TMT_TEST_DATA/$JOBKEY/, and results.yaml at
# $TMT_TEST_DATA/$JOBKEY/results.yaml. The driver reparents the artifacts
# into $TMT_TEST_DATA/artifacts/$JOBKEY/ so the host's fetch_artifacts maps
# each preset back to its own local workdir.
#
set -uo pipefail

: "${JOBKEY:?tf-job.sh: JOBKEY must be set (by the driver)}"
: "${ENFPRESET:?tf-job.sh: ENFPRESET must be set (by the driver)}"
: "${JOB_WORKDIR:?tf-job.sh: JOB_WORKDIR must be set (by the driver)}"
: "${CI:?tf-job.sh: CI must be set}"
: "${CLI:?tf-job.sh: CLI must be set}"
: "${TMT_TEST_DATA:?tf-job.sh: TMT_TEST_DATA must be set (the driver data dir)}"

ENFFILE="$CI/env/$ENFPRESET"
WORKDIR="$JOB_WORKDIR"
mkdir -p "$WORKDIR"

# per-key staged-results namespace (stage-lib.sh honours these overrides so
# the child's logs/results never collide with the driver's or a sibling's)
export STAGE_DATA_DIR="$TMT_TEST_DATA/$JOBKEY"
export RESULTS_FILE="$TMT_TEST_DATA/$JOBKEY/results.yaml"

source "$CI/tmt/tests/freeipa-env/stage-lib.sh"

echo "== tf-job: key=$JOBKEY preset=$ENFPRESET workdir=$WORKDIR"
echo "== tf-job: staged results -> $STAGEDATA"

[ -f "$ENFFILE" ] || die "preset not found: $ENFFILE"
command -v podman >/dev/null 2>&1 || die "podman not found on the guest"

# --- the up -> run -> down recipe (identical to a local/ssh job) ------------
# The CLI resolves its preset argument against the CWD, so we cd to $CI but
# must pass the absolute preset path ($ENFFILE = $CI/env/$ENFPRESET) — the
# same convention the local/ssh runner uses (runner.py: envfile =
# {remote_ci}/env/{preset_rel}). Passing the bare $ENFPRESET here would
# resolve against $CI (no presets/ under it) and fail with FileNotFoundError.
cd "$CI" || die "cannot cd to $CI"

echo "== up: $CLI up $ENFFILE --workdir $WORKDIR"
stage_begin env-up
"$CLI" up "$ENFFILE" --workdir "$WORKDIR" 2>&1 | tee "$STAGEDATA/env-up.log"
stage_record "${PIPESTATUS[0]}"
if [ "${STAGE_RC[env-up]}" -ne 0 ]; then
    FATAL_NOTE="env up failed (rc ${STAGE_RC[env-up]})"
    OVERALL=fail
    STAGE_END[env-up]=$(date +%s)
    # best-effort cleanup so the guest does not leak containers
    echo "== down (cleanup after up failure): $CLI down $ENFFILE --workdir $WORKDIR"
    stage_begin env-down
    "$CLI" down "$ENFFILE" --workdir "$WORKDIR" 2>&1 | tee "$STAGEDATA/env-down.log"
    stage_record "${PIPESTATUS[0]}"
    [ "${STAGE_RC[env-down]}" -eq 0 ] || \
        stage_set warn "cleanup down rc ${STAGE_RC[env-down]} after up failure"
    write_results; rm -f "$STAGEDATA/.results-pending"
    exit 1
fi

echo "== run: $CLI run $ENFFILE --workdir $WORKDIR"
stage_run test-run "$CLI" run "$ENFFILE" --workdir "$WORKDIR"
RUN_RC=$?
[ "$RUN_RC" -eq 0 ] || OVERALL=fail

# best-effort teardown; a clean down also collects the workdir logs
echo "== down: $CLI down $ENFFILE --workdir $WORKDIR"
stage_begin env-down
"$CLI" down "$ENFFILE" --workdir "$WORKDIR" 2>&1 | tee "$STAGEDATA/env-down.log"
stage_record "${PIPESTATUS[0]}"
[ "${STAGE_RC[env-down]}" -eq 0 ] || \
    stage_set warn "down rc ${STAGE_RC[env-down]} (best effort; does not mask the run result)"

# --- render the self-contained HTML report (best effort) -------------------
# From the now-collected logs + xunit, render <workdir>/logs/results.html. It
# must run BEFORE the $WORKDIR/logs copy below so the report rides the same
# artifacts/ tree onto the TF artifact server (and is picked up locally by
# `tf-logs --html`). A failure only warns: it must never mask the run result,
# and the raw logs are still collected regardless.
if [ -d "$WORKDIR/logs" ]; then
    echo "== report: $CLI report --workdir $WORKDIR"
    "$CLI" report --workdir "$WORKDIR" 2>&1 | tee "$STAGEDATA/report.log" \
        || echo "WARN: freeipa-env report failed (logs still collected)"
fi

# --- collect this preset's artifacts into its own staged dir ---------------
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
echo "== tf-job $JOBKEY finished with exit code $RUN_RC"
exit "$RUN_RC"
