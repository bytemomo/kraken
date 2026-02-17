#!/bin/bash

# Mosquitto Fuzzer Entrypoint
# Supports multiple fuzzing targets and modes with structured JSON output

OUTPUT_DIR="/work/output"
CORPUS_DIR="/work/corpus"
DICT_FILE="/work/corpus/mqtt.dict"
TIMEOUT=300
GUI_MODE=0
RESUME_MODE=0
USE_MUTATOR=0

START_TIME=$(date +%s)
FUZZER_PID=""
TERMINATED=0

usage() {
    cat <<EOF
Mosquitto Fuzzer

Usage: entrypoint.sh [OPTIONS] <MODE> [TARGET] [EXTRA_ARGS...]

Modes:
  fuzz          - AFL++ fuzzing with JSON results (default)
  report        - Collect and output JSON results from previous run
  repro         - Reproduce a crash file (requires crash file as extra arg)
  minimize      - Minimize a crash file (requires crash file as extra arg)
  cov           - Run coverage on seed corpus
  shell         - Start interactive shell
  list          - List available fuzzers

Targets:
  packet_read   - Client packet parsing (default)
  connect       - Broker CONNECT handler
  publish       - Broker PUBLISH handler
  subscribe     - Broker SUBSCRIBE handler
  property      - MQTT 5.0 property parsing

Options:
  -t, --timeout SEC    Fuzzing timeout in seconds (default: 300)
  -g, --gui            Show AFL++ interactive GUI instead of JSON output
  -r, --resume         Resume a previous fuzzing run
  -m, --mutator        Use custom structure-aware mutator (connect only)
  -o, --output DIR     Output directory (default: /work/output)
  -c, --corpus DIR     Corpus directory (default: /work/corpus)
  -h, --help           Show this help

Examples:
  entrypoint.sh fuzz connect                     # JSON output after 300s
  entrypoint.sh -t 60 fuzz packet_read           # JSON output after 60s
  entrypoint.sh -g fuzz connect                  # Interactive GUI mode
  entrypoint.sh -r fuzz connect                  # Resume previous run
  entrypoint.sh -m fuzz connect                  # Use custom MQTT mutator
  entrypoint.sh repro connect /path/to/crash
EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -g|--gui)
            GUI_MODE=1
            shift
            ;;
        -r|--resume)
            RESUME_MODE=1
            shift
            ;;
        -m|--mutator)
            USE_MUTATOR=1
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -c|--corpus)
            CORPUS_DIR="$2"
            DICT_FILE="$CORPUS_DIR/mqtt.dict"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

MODE="${1:-fuzz}"
TARGET="${2:-packet_read}"
EXTRA_ARGS="${@:3}"

# Map target names to binaries
resolve_target() {
    case "$TARGET" in
        packet_read|client)
            FUZZER_BIN="./fuzz_packet_read"
            ;;
        connect|broker_connect)
            FUZZER_BIN="./fuzz_broker_connect"
            ;;
        publish|broker_publish)
            FUZZER_BIN="./fuzz_broker_publish"
            ;;
        subscribe|broker_subscribe)
            FUZZER_BIN="./fuzz_broker_subscribe"
            ;;
        property|properties)
            FUZZER_BIN="./fuzz_property_parse"
            ;;
        *)
            echo "Unknown target: $TARGET"
            echo "Available targets: packet_read, connect, publish, subscribe, property"
            exit 1
            ;;
    esac
}

handle_term() {
    TERMINATED=1
    if [[ -n "$FUZZER_PID" ]] && kill -0 "$FUZZER_PID" 2>/dev/null; then
        kill -TERM "$FUZZER_PID" 2>/dev/null || true
    fi
}

trap handle_term SIGTERM SIGINT

get_stat() {
    local stats_file="$1"
    local key="$2"
    grep "^${key}" "$stats_file" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ' || echo ""
}

collect_findings() {
    local target_output="$OUTPUT_DIR/$TARGET"
    local findings="[]"
    local crashes_dir="$target_output/default/crashes"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    if [[ -d "$crashes_dir" ]]; then
        for crash_file in "$crashes_dir"/id:*; do
            [[ -f "$crash_file" ]] || continue

            local crash_id
            crash_id=$(basename "$crash_file")
            local crash_hex
            crash_hex=$(xxd -p "$crash_file" | tr -d '\n')
            local crash_b64
            crash_b64=$(base64 -w0 "$crash_file")

            local triage_output=""
            # Use ./repro for packet_read, fuzzer binary for other targets
            if [[ "$TARGET" == "packet_read" || "$TARGET" == "client" ]] && [[ -x "./repro" ]]; then
                triage_output=$(./repro "$crash_file" 2>&1 | head -100 || true)
            elif [[ -x "$FUZZER_BIN" ]]; then
                triage_output=$($FUZZER_BIN "$crash_file" 2>&1 | head -100 || true)
            fi

            local finding
            finding=$(jq -n \
                --arg id "afl-crash-${crash_id}" \
                --arg module_id "mosquitto-fuzz-${TARGET}" \
                --arg title "AFL++ Crash: $crash_id" \
                --arg desc "Fuzzing crash in $TARGET" \
                --arg crash_file "$crash_file" \
                --arg crash_hex "$crash_hex" \
                --arg crash_b64 "$crash_b64" \
                --arg triage "$triage_output" \
                --arg ts "$timestamp" \
                '{
                    id: $id,
                    module_id: $module_id,
                    success: true,
                    title: $title,
                    severity: "high",
                    description: $desc,
                    evidence: {
                        crash_file: $crash_file,
                        crash_input_hex: $crash_hex,
                        crash_input_base64: $crash_b64,
                        triage_output: $triage
                    },
                    tags: ["fuzzing", "mqtt", "mosquitto", "afl", "crash"],
                    timestamp: $ts
                }')

            findings=$(echo "$findings" | jq --argjson f "$finding" '. + [$f]')
        done
    fi

    echo "$findings"
}

collect_stats() {
    local target_output="$OUTPUT_DIR/$TARGET"
    local stats_file="$target_output/default/fuzzer_stats"

    if [[ ! -f "$stats_file" ]]; then
        jq -n \
            --arg timeout "$TIMEOUT" \
            '{
                configured_timeout_seconds: ($timeout | tonumber),
                error: "No fuzzer_stats file found"
            }'
        return
    fi

    local execs_done execs_per_sec corpus_count corpus_favored
    local max_depth pending_favs pending_total
    local bitmap_cvg stability saved_crashes saved_hangs
    local run_time start_time last_update

    execs_done=$(get_stat "$stats_file" "execs_done")
    execs_per_sec=$(get_stat "$stats_file" "execs_per_sec")
    corpus_count=$(get_stat "$stats_file" "corpus_count")
    corpus_favored=$(get_stat "$stats_file" "corpus_favored")
    max_depth=$(get_stat "$stats_file" "max_depth")
    pending_favs=$(get_stat "$stats_file" "pending_favs")
    pending_total=$(get_stat "$stats_file" "pending_total")
    bitmap_cvg=$(get_stat "$stats_file" "bitmap_cvg")
    stability=$(get_stat "$stats_file" "stability")
    saved_crashes=$(get_stat "$stats_file" "saved_crashes")
    saved_hangs=$(get_stat "$stats_file" "saved_hangs")
    run_time=$(get_stat "$stats_file" "run_time")
    start_time=$(get_stat "$stats_file" "start_time")
    last_update=$(get_stat "$stats_file" "last_update")

    local crash_count=0 hang_count=0
    [[ -d "$target_output/default/crashes" ]] && crash_count=$(find "$target_output/default/crashes" -name 'id:*' 2>/dev/null | wc -l)
    [[ -d "$target_output/default/hangs" ]] && hang_count=$(find "$target_output/default/hangs" -name 'id:*' 2>/dev/null | wc -l)

    jq -n \
        --arg run_time "${run_time:-0}" \
        --arg start_time "${start_time:-0}" \
        --arg last_update "${last_update:-0}" \
        --arg timeout "$TIMEOUT" \
        --arg execs_done "${execs_done:-0}" \
        --arg execs_per_sec "${execs_per_sec:-0}" \
        --arg corpus_count "${corpus_count:-0}" \
        --arg corpus_favored "${corpus_favored:-0}" \
        --arg max_depth "${max_depth:-0}" \
        --arg pending_favs "${pending_favs:-0}" \
        --arg pending_total "${pending_total:-0}" \
        --arg bitmap_cvg "${bitmap_cvg:-0}" \
        --arg stability "${stability:-0}" \
        --arg saved_crashes "${saved_crashes:-0}" \
        --arg saved_hangs "${saved_hangs:-0}" \
        --arg crash_count "$crash_count" \
        --arg hang_count "$hang_count" \
        '{
            run_time_seconds: ($run_time | tonumber),
            start_time_epoch: ($start_time | tonumber),
            last_update_epoch: ($last_update | tonumber),
            configured_timeout_seconds: ($timeout | tonumber),
            executions: {
                total: ($execs_done | tonumber),
                per_second: ($execs_per_sec | tonumber)
            },
            coverage: {
                bitmap_coverage: $bitmap_cvg,
                stability: $stability,
                max_depth: ($max_depth | tonumber)
            },
            corpus: {
                count: ($corpus_count | tonumber),
                favored: ($corpus_favored | tonumber),
                pending_favored: ($pending_favs | tonumber),
                pending_total: ($pending_total | tonumber)
            },
            findings: {
                crashes: ($crash_count | tonumber),
                hangs: ($hang_count | tonumber)
            }
        }'
}

build_result() {
    local findings="$1"
    local stats="$2"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local crash_count hang_count execs_total bitmap_cvg run_secs
    crash_count=$(echo "$stats" | jq -r '.findings.crashes')
    hang_count=$(echo "$stats" | jq -r '.findings.hangs')
    execs_total=$(echo "$stats" | jq -r '.executions.total')
    bitmap_cvg=$(echo "$stats" | jq -r '.coverage.bitmap_coverage')
    run_secs=$(echo "$stats" | jq -r '.run_time_seconds')

    local severity="info"
    local success="false"
    if [[ "$crash_count" -gt 0 ]]; then
        severity="high"
        success="true"
    elif [[ "$hang_count" -gt 0 ]]; then
        severity="medium"
        success="true"
    fi

    local run_human
    run_human=$(printf '%dh%02dm%02ds' $((run_secs/3600)) $(((run_secs%3600)/60)) $((run_secs%60)))

    local summary
    summary=$(jq -n \
        --arg id "afl-summary-${TARGET}" \
        --arg module_id "mosquitto-fuzz-${TARGET}" \
        --arg title "AFL++ Fuzzing Summary: $TARGET" \
        --arg desc "Ran ${run_human}. Executed $execs_total tests. Coverage: $bitmap_cvg. Crashes: $crash_count, Hangs: $hang_count" \
        --arg severity "$severity" \
        --argjson success "$success" \
        --argjson stats "$stats" \
        --arg ts "$timestamp" \
        '{
            id: $id,
            module_id: $module_id,
            success: $success,
            title: $title,
            severity: $severity,
            description: $desc,
            evidence: $stats,
            tags: ["fuzzing", "mqtt", "mosquitto", "afl", "summary"],
            timestamp: $ts
        }')

    findings=$(echo "$findings" | jq --argjson f "$summary" '. + [$f]')

    jq -n \
        --arg target "$TARGET" \
        --argjson findings "$findings" \
        '{
            target: { image: ("mosquitto-fuzz:" + $target) },
            findings: $findings,
            logs: []
        }'
}

output_results() {
    local findings stats
    findings=$(collect_findings)
    stats=$(collect_stats)
    build_result "$findings" "$stats"
}

get_seeds_dir() {
    case "$TARGET" in
        connect|broker_connect)
            echo "$CORPUS_DIR/connect"
            ;;
        publish|broker_publish)
            echo "$CORPUS_DIR/publish"
            ;;
        subscribe|broker_subscribe)
            echo "$CORPUS_DIR/subscribe"
            ;;
        property|properties)
            echo "$CORPUS_DIR/property"
            ;;
        packet_read|client|*)
            # Use all seeds for generic packet parsing
            echo "$CORPUS_DIR"
            ;;
    esac
}

get_mutator_lib() {
    case "$TARGET" in
        connect|broker_connect)
            echo "./mutator_connect.so"
            ;;
        property|properties)
            echo "./mutator_property.so"
            ;;
        publish|broker_publish)
            echo "./mutator_publish.so"
            ;;
        subscribe|broker_subscribe)
            echo "./mutator_subscribe.so"
            ;;
        *)
            echo ""
            ;;
    esac
}

run_fuzzer() {
    local target_output="$OUTPUT_DIR/$TARGET"
    local seeds_dir
    seeds_dir=$(get_seeds_dir)
    mkdir -p "$target_output"

    local AFL_CMD
    if [[ "$RESUME_MODE" == "1" ]]; then
        # Resume from existing output directory
        AFL_CMD="afl-fuzz -i- -o $target_output"
    else
        AFL_CMD="afl-fuzz -i $seeds_dir -o $target_output"
    fi
    [[ -f "$DICT_FILE" ]] && AFL_CMD="$AFL_CMD -x $DICT_FILE"

    # Add custom mutator if requested and available for target
    if [[ "$USE_MUTATOR" == "1" ]]; then
        local mutator_lib
        mutator_lib=$(get_mutator_lib)
        if [[ -n "$mutator_lib" && -f "$mutator_lib" ]]; then
            export AFL_CUSTOM_MUTATOR_LIBRARY="$mutator_lib"
            echo "Using custom mutator: $mutator_lib"
        else
            echo "Warning: No custom mutator available for target '$TARGET'"
        fi
    fi

    AFL_CMD="$AFL_CMD $EXTRA_ARGS -- $FUZZER_BIN"

    if [[ "$GUI_MODE" == "1" ]]; then
        echo "Running: $AFL_CMD"
        exec $AFL_CMD
    else
        timeout --signal=SIGINT "${TIMEOUT}s" $AFL_CMD >/dev/null 2>&1 &
        FUZZER_PID=$!
        wait "$FUZZER_PID" 2>/dev/null || true
        FUZZER_PID=""
    fi
}

# Main
resolve_target

echo "=== Mosquitto Fuzzer ==="
echo "Mode: $MODE"
echo "Target: $TARGET"
echo "Binary: $FUZZER_BIN"
echo "Corpus: $CORPUS_DIR"
echo "Seeds: $(get_seeds_dir)"
echo ""

case "$MODE" in
    fuzz)
        if [[ "$GUI_MODE" == "1" ]]; then
            echo "Starting AFL++ fuzzing (GUI mode)..."
        else
            echo "Starting AFL++ fuzzing (${TIMEOUT}s)..."
        fi
        run_fuzzer
        if [[ "$GUI_MODE" == "0" ]]; then
            output_results
        fi
        ;;

    report|results)
        echo "Collecting results..."
        output_results
        ;;

    repro|reproduce|triage)
        if [[ -z "$3" ]]; then
            echo "Usage: $0 repro <target> <crash_file>"
            exit 1
        fi
        CRASH_FILE="$3"
        echo "Reproducing crash: $CRASH_FILE"
        # Use ./repro for packet_read (built with client library + ASan)
        # Use fuzzer binary directly for broker targets (has ASan but also AFL++)
        if [[ "$TARGET" == "packet_read" || "$TARGET" == "client" ]]; then
            exec ./repro "$CRASH_FILE"
        else
            echo "Note: Using fuzzer binary (no dedicated repro for $TARGET)"
            exec $FUZZER_BIN "$CRASH_FILE"
        fi
        ;;

    minimize|min)
        if [[ -z "$3" ]]; then
            echo "Usage: $0 minimize <target> <crash_file>"
            exit 1
        fi
        CRASH_FILE="$3"
        MINIMIZED="${CRASH_FILE}.min"
        echo "Minimizing: $CRASH_FILE -> $MINIMIZED"
        exec afl-tmin -i "$CRASH_FILE" -o "$MINIMIZED" -- $FUZZER_BIN
        ;;

    cov|coverage)
        echo "Running LLVM source-based coverage..."

        # Map target to coverage binary
        case "$TARGET" in
            connect|broker_connect)
                COV_BIN="./cov_broker_connect"
                ;;
            publish|broker_publish)
                COV_BIN="./cov_broker_publish"
                ;;
            subscribe|broker_subscribe)
                COV_BIN="./cov_broker_subscribe"
                ;;
            property|properties)
                COV_BIN="./cov_property_parse"
                ;;
            *)
                echo "Error: No coverage binary for target '$TARGET'"
                echo "Available: connect, publish, subscribe, property"
                exit 1
                ;;
        esac

        if [[ ! -x "$COV_BIN" ]]; then
            echo "Error: Coverage binary not found: $COV_BIN"
            exit 1
        fi

        # Determine input directory - use corpus from fuzzing output if available, else seeds
        cov_target_output="$OUTPUT_DIR/$TARGET"
        if [[ -d "$cov_target_output/default/queue" ]]; then
            cov_input_dir="$cov_target_output/default/queue"
            echo "Using fuzzer corpus: $cov_input_dir"
        else
            cov_input_dir=$(get_seeds_dir)
            echo "Using seed corpus: $cov_input_dir"
        fi

        # Setup coverage output
        cov_output="$OUTPUT_DIR/coverage/$TARGET"
        mkdir -p "$cov_output"
        export LLVM_PROFILE_FILE="$cov_output/default.profraw"

        echo "Coverage binary: $COV_BIN"
        echo "Profile output: $LLVM_PROFILE_FILE"
        echo ""

        # Run all inputs through coverage binary
        cov_count=0
        cov_failed=0
        for input_file in "$cov_input_dir"/*; do
            [[ -f "$input_file" ]] || continue
            cov_count=$((cov_count + 1))
            if ! $COV_BIN "$input_file" >/dev/null 2>&1; then
                cov_failed=$((cov_failed + 1))
            fi
        done
        echo "Processed $cov_count inputs ($cov_failed failed/crashed)"

        # Check if profraw was generated
        if [[ ! -f "$cov_output/default.profraw" ]]; then
            echo "Error: No profile data generated"
            echo "This may indicate the coverage binary lacks a main() for standalone execution"
            exit 1
        fi

        # Merge profile data
        echo ""
        echo "Merging profile data..."
        llvm-profdata-19 merge -sparse "$cov_output/default.profraw" -o "$cov_output/coverage.profdata"

        # Generate coverage report
        echo "Generating coverage report..."
        llvm-cov-19 report "$COV_BIN" \
            -instr-profile="$cov_output/coverage.profdata" \
            2>/dev/null | tee "$cov_output/report.txt"

        # Generate detailed line coverage for key files
        echo ""
        echo "=== Detailed Function Coverage ==="
        llvm-cov-19 report "$COV_BIN" \
            -instr-profile="$cov_output/coverage.profdata" \
            -show-functions 2>/dev/null | head -100 | tee "$cov_output/functions.txt"

        # Export to JSON for programmatic analysis
        llvm-cov-19 export "$COV_BIN" \
            -instr-profile="$cov_output/coverage.profdata" \
            -format=text 2>/dev/null > "$cov_output/coverage.json"

        echo ""
        echo "Coverage artifacts saved to: $cov_output/"
        echo "  - report.txt      Summary report"
        echo "  - functions.txt   Per-function coverage"
        echo "  - coverage.json   JSON export for analysis"
        echo "  - coverage.profdata  Merged profile data"
        ;;

    shell|bash)
        echo "Starting shell..."
        exec /bin/bash
        ;;

    list)
        echo "Available fuzzers:"
        ls -la ./fuzz_* 2>/dev/null || echo "No fuzzers found"
        ;;

    *)
        echo "Unknown mode: $MODE"
        echo ""
        echo "Run with -h or --help for usage information"
        exit 1
        ;;
esac
