# Staged-results machinery for the freeipa-env tmt test.
#
# Sourced by tf-runner.sh (the batch driver) and tf-job.sh (the per-preset
# child), and by the local tmt smoke test. The caller must define WORKDIR
# before sourcing; the machinery then records each stage (console tee'd live
# to <stage>.log under STAGEDATA) and writes RESULTS_FILE, which tmt (1.77+,
# `result: custom` in main.fmf) turns into per-stage testcases with
# downloadable logs.
#
# Schema notes (tmt/schemas/results.yaml, verified against tmt 1.77.0):
#  - note entries must be YAML-quoted strings (an unquoted colon makes
#    yaml parse a dict, which hard-fails tmt validation);
#  - start-time/end-time need fractional seconds
#    (^\d{2,}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:\+\d{2}:\d{2}|Z)$);
#  - duration is HH:MM:SS (^[0-9]{2,}:[0-5][0-9]:[0-5][0-9]$);
#  - start/end/duration are optional; serial-number/guest must NOT be set.

: "${WORKDIR:?stage-lib.sh: WORKDIR must be set before sourcing}"

# STAGEDATA: where the stage logs + collected artifacts live. The driver uses
# the tmt test data dir (uploaded by tmt); a per-job child points this at a
# per-key subdir so its live logs never collide with the driver's or with
# another job's. Outside tmt (local debugging) fall back to a workdir-local
# dir; the flow still runs, tmt just gets no custom results.
STAGEDATA="${STAGE_DATA_DIR:-${TMT_TEST_DATA:-$WORKDIR/tmt-stage}}"
mkdir -p "$STAGEDATA"
# RESULTS_FILE: under tmt it sits in the data dir (STAGEDATA); outside tmt,
# beside the stage logs. A caller may pin an explicit path.
RESULTS_FILE="${RESULTS_FILE:-$STAGEDATA/results.yaml}"

declare -A STAGE_RC STAGE_RES STAGE_START STAGE_END STAGE_NOTE
STAGE_SEEN=""                       # space-separated started stage names
STAGE=""                            # stage currently running
OVERALL=pass                        # the test-level outcome
RUN_RC=""                           # the `run` step exit code (job status)
FATAL_NOTE=""                       # die() message, for the parent note
RESULTS_WRITTEN=""                  # guard: write_results runs once

# iso TIME: epoch seconds -> schema-valid timestamp (fractional seconds, UTC)
iso() { date -u -d "@$1" '+%Y-%m-%dT%H:%M:%S.%6NZ'; }

# yaml_note STRING: one single-quoted YAML list item; colons, semicolons and
# embedded quotes in the note are safe this way.
yaml_note() {
    local s="${1//\'/\'\'}"
    printf "    - '%s'\n" "$s"
}

die() {
    echo "FATAL: $*" >&2
    FATAL_NOTE="$*"
    OVERALL=fail
    [ -n "$STAGE" ] && { STAGE_RC[$STAGE]=1; STAGE_NOTE[$STAGE]="$*"; }
    exit 1
}

# stage_begin NAME: start a stage; its log exists from this point on (the
# caller tees the stage's console into it, live, on every path).
stage_begin() {
    STAGE="$1"
    STAGE_START[$STAGE]=$(date +%s)
    case " $STAGE_SEEN " in
        *" $1 "*) ;;
        *) STAGE_SEEN="$STAGE_SEEN $1" ;;
    esac
    : > "$STAGEDATA/$STAGE.log"
    echo "== stage $STAGE"
}

# stage_run NAME CMD...: run a stage, streaming to console + <stage>.log.
# tee keeps the output live on long stages (a $(...) capture would buffer
# until completion); the command's exit code comes from PIPESTATUS[0].
stage_run() {
    local name="$1"; shift
    stage_begin "$name"
    "$@" 2>&1 | tee "$STAGEDATA/$name.log"
    local rc=${PIPESTATUS[0]}
    STAGE_RC[$name]="$rc"
    STAGE_END[$name]=$(date +%s)
    STAGE_NOTE[$name]="rc $rc"
    return "$rc"
}

# stage_record RC: record the exit code of a command that was tee'd inline
# (instead of via stage_run) for the current stage.
stage_record() {
    local rc="${1:-}"
    STAGE_RC[$STAGE]="$rc"
    STAGE_END[$STAGE]=$(date +%s)
    STAGE_NOTE[$STAGE]="${STAGE_NOTE[$STAGE]:-rc $rc}"
}

# stage_set RESULT NOTE: set a stage's result directly (info/warn/skip paths).
stage_set() {
    STAGE_RES[$STAGE]="$1"
    STAGE_NOTE[$STAGE]="$2"
}

# write $STAGEDATA/results.yaml from the collected stage state. Safe to call
# from the EXIT trap at any point: unfinished stages are omitted, missing
# times are omitted (start/end/duration are optional in the schema).
#
# The parent entry is name '/' (the test itself; tmt overwrites its
# start/end/duration/context from the invocation). Stage entries are named
# /<stage>: tmt prefixes every non-'/' name with the test name, producing
# <test>/<stage>.
write_results() {
    [ -n "$RESULTS_WRITTEN" ] && return 0
    RESULTS_WRITTEN=1
    local out="$STAGEDATA/.results.tmp"
    local i t e d rc res
    {
        # parent entry: the test itself
        printf -- '- name: /\n  result: %s\n  note:\n' "$OVERALL"
        if [ -n "$FATAL_NOTE" ]; then
            yaml_note "fatal: $FATAL_NOTE"
        elif [ -n "$RUN_RC" ]; then
            yaml_note "run exit $RUN_RC; stages: $(printf '%s' "$STAGE_SEEN" | sed -e 's/^ //' -e 's/ /, /g')"
        else
            yaml_note "no stage completed"
        fi
        printf '  log:\n'
        # the test's own console is the tmt output file, one level up
        printf '    - ../output.txt\n'
        [ -f "$STAGEDATA/run.log" ] && printf '    - run.log\n'
        [ -f "$STAGEDATA/artifacts/nosetests.xml" ] && printf '    - artifacts/nosetests.xml\n'
        for i in srpm-build image-build env-up test-run env-down; do
            case " $STAGE_SEEN " in
                *" $i "*) ;;
                *) continue ;;
            esac
            rc="${STAGE_RC[$i]:-}"
            res="${STAGE_RES[$i]:-}"
            [ -n "$res" ] || {
                [ -n "$rc" ] && [ "$rc" -eq 0 ] && res=pass
                [ -n "$res" ] || res=fail
            }
            printf -- '- name: /%s\n  result: %s\n  note:\n' "$i" "$res"
            yaml_note "${STAGE_NOTE[$i]:-rc ${rc:-?}}"
            t="${STAGE_START[$i]:-}"; e="${STAGE_END[$i]:-}"
            if [ -n "$t" ] && [ -n "$e" ] && [ "$e" -ge "$t" ]; then
                d=$((e - t))
                printf "  start-time: '%s'\n  end-time: '%s'\n  duration: %02d:%02d:%02d\n" \
                    "$(iso "$t")" "$(iso "$e")" $((d / 3600)) $((d % 3600 / 60)) $((d % 60))
            fi
            printf '  log:\n    - %s.log\n' "$i"
            if [ "$i" = test-run ] && [ -f "$STAGEDATA/artifacts/nosetests.xml" ]; then
                printf '    - artifacts/nosetests.xml\n'
            fi
        done
    } > "$out" && mv "$out" "$RESULTS_FILE"
}

# make sure a results.yaml exists even when the sourcing script dies before
# the normal write; the normal path marks .results-pending gone first.
echo init > "$STAGEDATA/.results-pending"
trap 'if [ -f "$STAGEDATA/.results-pending" ]; then [ -n "$STAGE" ] && STAGE_END[$STAGE]=$(date +%s); write_results; echo "== wrote $RESULTS_FILE (trap)" >&2; fi' EXIT
trap 'OVERALL=fail; [ -n "$FATAL_NOTE" ] || FATAL_NOTE="interrupted by signal"; exit 1' INT TERM
