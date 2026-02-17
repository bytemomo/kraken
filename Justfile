set shell := ["bash", "-c"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

CONFIG := "Release"
GEN := "Ninja"
TOOLCHAIN_WIN := "D:\\.scoop\\apps\\vcpkg\\current\\scripts\\buildsystems\\vcpkg.cmake"

FUZZ_DIR := "modules/protocols"
ABI_DIR := "modules/protocols"

_default:
    @just --list

# ==============================================================================
# == Main Applications
# ==============================================================================

[doc('Builds the complete Kraken application.
This is a convenience recipe that first builds the main Go binary and then
compiles all the necessary ABI modules.')]
kraken-build-all: kraken-build abi-clean-all abi-build-all

[doc('Builds the main Kraken Go application binary.
It first generates the required protobuf files before compiling the application.')]
kraken-build:
    cd kraken/pkg/modulepb && go generate
    cd kraken && go build -o ../dist/kraken main.go

[doc('Runs the tests for the nautilus suite.')]
test:
    go test ./kraken/... -v -timeout 10s
    go test ./trident/... -v -timeout 10s

    @read -p "Continue? Sudo required (y/N) " RESP; \
        if [ "$RESP" != "y" ] && [ "$RESP" != "Y" ]; then \
            exit 0; \
        fi

    @go test -c ./trident/conduit/datalink/... -o ./dist/sudo_tests/
    @go test -c ./trident/conduit/network/... -o ./dist/sudo_tests/

    @for test in ./dist/sudo_tests/*.test; do \
        sudo $test -test.v -test.timeout 10s; \
    done




# ==============================================================================
# == Scenarios
# ==============================================================================

# Scenario labels for display
_scenario_label_a := "MQTT ICS"
_scenario_label_c := "RTSP Surveillance"

[doc("Run a podman-based scenario (a or c) with security profiles. Need `tmux`. scenario=a|c, sec_level=insecure|partial|hardened")]
scenario_run scenario sec_level:
    #!/bin/bash
    set -euo pipefail

    if [[ ! "{{scenario}}" =~ ^(a|c)$ ]]; then
        echo "Error: Invalid scenario '{{scenario}}'. Use 'a' or 'c'."
        exit 1
    fi
    if [[ ! "{{sec_level}}" =~ ^(hardened|insecure|partial)$ ]]; then
        echo "Error: Invalid security level '{{sec_level}}'"
        exit 1
    fi

    SCENARIO_NAME="scenario-{{scenario}}"
    SESSION_NAME="scenario_lab_{{scenario}}"

    [[ -d "resources/$SCENARIO_NAME" ]] || { echo "Directory not found: resources/$SCENARIO_NAME"; exit 1; }
    [[ `command -v tmux` ]] || { echo "This recipe requires the tmux command."; exit 1; }

    echo "Pre-flight: Cleaning..."
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
    just scenario_clean {{scenario}} > /dev/null 2>&1 || true

    WORK_DIR="$(pwd)/resources/$SCENARIO_NAME"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$WORK_DIR/results/{{sec_level}}"

    # Create tmux session
    tmux new-session -d -s "$SESSION_NAME" -c "$WORK_DIR"
    tmux rename-window -t "$SESSION_NAME:0" "${SCENARIO_NAME}_Lab"

    # Pane 0 (Left): Main environment
    tmux send-keys -t "$SESSION_NAME:0" "export SECURITY_PROFILE={{sec_level}}" C-m
    tmux send-keys -t "$SESSION_NAME:0" "echo 'Starting $SCENARIO_NAME ({{sec_level}})...'" C-m
    tmux send-keys -t "$SESSION_NAME:0" "podman compose up --build 2>&1 | tee results/{{sec_level}}/main_${TIMESTAMP}.log" C-m

    sleep 3

    # Pane 1 (Right): Kraken scanner
    tmux split-window -h -t "$SESSION_NAME:0" -c "$WORK_DIR"
    tmux send-keys -t "$SESSION_NAME:0.1" "export SECURITY_PROFILE={{sec_level}}" C-m
    tmux send-keys -t "$SESSION_NAME:0.1" "echo 'Starting Kraken Scanner...'" C-m
    tmux send-keys -t "$SESSION_NAME:0.1" "podman compose --profile tools run --no-deps --build -it --rm kraken 2>&1 | tee results/{{sec_level}}/tools_${TIMESTAMP}.log" C-m

    tmux attach-session -t "$SESSION_NAME"

    echo "Session ended. Cleaning up..."
    just scenario_clean {{scenario}} || true

[doc("Clean up a podman-based scenario (a or c). scenario=a|c")]
scenario_clean scenario:
    #!/bin/bash
    set -euo pipefail

    if [[ ! "{{scenario}}" =~ ^(a|c)$ ]]; then
        echo "Error: Invalid scenario '{{scenario}}'. Use 'a' or 'c'."
        exit 1
    fi

    SCENARIO_NAME="scenario-{{scenario}}"
    pushd "resources/$SCENARIO_NAME" > /dev/null

    echo "Cleaning up $SCENARIO_NAME (all profiles)..."
    for profile in insecure partial hardened; do
        SECURITY_PROFILE=$profile podman compose --profile tools --profile bridge down -v --remove-orphans 2>/dev/null || true
    done

    echo "Environment cleaned:"
    podman ps -a --filter "name=scenario-{{scenario}}"
    popd > /dev/null

[doc("Run scenario B (EtherCAT fieldbus). Requires sudo + docker. Need `tmux`.")]
scenario_b_run:
    #!/bin/bash
    set -euo pipefail
    SCENARIO_NAME="scenario-b"
    SESSION_NAME="scenario_lab_b"

    [[ -d "resources/$SCENARIO_NAME" ]] || { echo "Directory not found"; exit 1; }
    [[ `command -v tmux` ]] || { echo "This recipe requires the tmux command."; exit 1; }

    echo "Pre-flight: Cleaning..."
    tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
    just scenario_b_clean > /dev/null 2>&1 || true

    WORK_DIR="$(pwd)/resources/$SCENARIO_NAME"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$WORK_DIR/results"

    tmux new-session -d -s "$SESSION_NAME" -c "$WORK_DIR"
    tmux rename-window -t "$SESSION_NAME:0" "EtherCAT_Lab"

    # Pane 0 (Left): Simulator + Master
    tmux send-keys -t "$SESSION_NAME:0" "echo 'Starting EtherCAT Simulator + Master...'" C-m
    tmux send-keys -t "$SESSION_NAME:0" "sudo docker compose --profile default up --build 2>&1 | tee results/sim_${TIMESTAMP}.log" C-m

    sleep 5

    # Pane 1 (Right): Kraken scanner
    tmux split-window -h -t "$SESSION_NAME:0" -c "$WORK_DIR"
    tmux send-keys -t "$SESSION_NAME:0.1" "echo 'Starting Kraken Scanner...'" C-m
    tmux send-keys -t "$SESSION_NAME:0.1" "sudo docker compose --profile tools run --build -it --rm kraken 2>&1 | tee results/kraken_${TIMESTAMP}.log" C-m

    tmux attach-session -t "$SESSION_NAME"

    echo "Session ended. Cleaning up..."
    just scenario_b_clean || true

[doc("Clean scenario B (EtherCAT)")]
scenario_b_clean:
    #!/bin/bash
    set -euo pipefail
    pushd resources/scenario-b > /dev/null
    echo "Cleaning up scenario-b..."
    sudo docker compose --profile default --profile tools down -v --remove-orphans || true
    echo "Environment cleaned:"
    sudo docker ps -a --filter "name=scenario-b"
    popd > /dev/null

# ==============================================================================
# == Fuzzing
# ==============================================================================

[doc('Builds a containerized fuzzing environment.
Format: <target>:<harness> where target is the software being fuzzed and harness is the fuzzer type.
Examples: just fuzz-build mosquitto:aflpp, just fuzz-build nanomq:aflnet')]
fuzz-build spec:
    #!/bin/bash
    set -euo pipefail
    SPEC="{{spec}}"
    TARGET="${SPEC%:*}"
    HARNESS="${SPEC#*:}"
    if [[ "$TARGET" == "$HARNESS" ]]; then
        echo "Error: Invalid format. Use <target>:<harness> (e.g., mosquitto:aflpp)"
        exit 1
    fi
    # Find the target directory (e.g., modules/protocols/mqtt/fuzz/mosquitto)
    FUZZ_PATH=$(find {{FUZZ_DIR}} -type d -name "$TARGET" -path "*/fuzz/*" | head -1)
    if [[ -z "$FUZZ_PATH" ]]; then
        echo "Error: Target '$TARGET' not found in {{FUZZ_DIR}}/*/fuzz/"
        exit 1
    fi
    # Use protocol directory as context (e.g., modules/protocols/mqtt) so corpus is accessible
    PROTOCOL_DIR=$(dirname "$(dirname "$FUZZ_PATH")")
    DOCKERFILE="$FUZZ_PATH/Dockerfile"
    echo "==> Building $TARGET-$HARNESS fuzzer"
    echo "    Context: $PROTOCOL_DIR"
    echo "    Dockerfile: $DOCKERFILE"
    podman build -t "$TARGET-$HARNESS:latest" -f "$DOCKERFILE" "$PROTOCOL_DIR"

[doc('Runs a fuzzer container.
Format: <target>:<harness> where target is the software being fuzzed and harness is the fuzzer type.
Examples: just fuzz-run mosquitto:aflpp')]
fuzz-run spec:
    #!/bin/bash
    set -euo pipefail
    SPEC="{{spec}}"
    TARGET="${SPEC%:*}"
    HARNESS="${SPEC#*:}"
    if [[ "$TARGET" == "$HARNESS" ]]; then
        echo "Error: Invalid format. Use <target>:<harness> (e.g., mosquitto:aflpp)"
        exit 1
    fi
    FUZZ_PATH=$(find {{FUZZ_DIR}} -type d -name "$TARGET" -path "*/fuzz/*" | head -1)
    if [[ -z "$FUZZ_PATH" ]]; then
        echo "Error: Target '$TARGET' not found in {{FUZZ_DIR}}/*/fuzz/"
        exit 1
    fi
    echo "==> Running $TARGET:$HARNESS fuzzer"
    pushd "$FUZZ_PATH" > /dev/null
    ./run.sh
    popd > /dev/null

[doc('Configures the host system for optimal fuzzing performance.
This sets the core dump pattern to `core` and changes the CPU frequency scaling
governor to `performance` (need sudo)')]
fuzz-setup:
    @echo "==> Setting up AFL++ fuzzing environment"
    echo core | sudo tee /proc/sys/kernel/core_pattern
    cd /sys/devices/system/cpu && (echo performance | sudo tee cpu*/cpufreq/scaling_governor)

# ==============================================================================
# == ABI Modules
# ==============================================================================

[doc('Builds all ABI modules (Rust/C++).')]
abi-build-all:
		@just {{ if os() == "windows" { "_abi-build-all-windows" } else { "_abi-build-all-unix" } }}

[doc('Cleans all build artifacts and then recompiles all ABI modules from scratch.
Useful for ensuring a clean and consistent build state.')]
abi-rebuild-all:
		@just {{ if os() == "windows" { "_abi-clean-all-windows && just _abi-build-all-windows" } else { "_abi-clean-all-unix && just _abi-build-all-unix" } }}

[doc('Builds a single, specific ABI module by its directory name.')]
abi-build-one name:
		@just {{ if os() == "windows" { "_abi-build-one-windows " + name } else { "_abi-build-one-unix " + name } }}

[doc('Removes all build artifacts from all ABI modules.')]
abi-clean-all:
		@just {{ if os() == "windows" { "_abi-clean-all-windows" } else { "_abi-clean-all-unix" } }}


# ==============================================================================
# == Private Recipes
# ==============================================================================

_abi-build-all-unix:
	#!/usr/bin/env bash
	set -euo pipefail
	# Find all directories containing CMakeLists.txt or Cargo.toml
	find {{ABI_DIR}} -type f \( -name "CMakeLists.txt" -o -name "Cargo.toml" \) | while read -r buildfile; do
		d=$(dirname "$buildfile")
		if [[ -f "$d/CMakeLists.txt" ]]; then
			echo "==> Configuring $d"
			cmake -S "$d" -B "$d/build" -G {{GEN}} -DCMAKE_BUILD_TYPE={{CONFIG}}
			echo "==> Building $d"
			cmake --build "$d/build" --config {{CONFIG}}
		elif [[ -f "$d/Cargo.toml" ]]; then
			echo "==> Building $d"
			(cd "$d" && cargo build --release)
		fi
	done

_abi-build-one-unix name:
	#!/usr/bin/env bash
	set -euo pipefail
	dir="{{ABI_DIR}}/{{name}}"
	if [[ -f "$dir/CMakeLists.txt" ]]; then
		echo "==> Configuring $dir"
		cmake -S "$dir" -B "$dir/build" -G {{GEN}} -DCMAKE_BUILD_TYPE={{CONFIG}}
		echo "==> Building $dir"
		cmake --build "$dir/build" --config {{CONFIG}}
	elif [[ -f "$dir/Cargo.toml" ]]; then
		echo "==> Building $dir"
		(cd "$dir" && cargo build --release)
	else
		echo "No build method found for '$dir' (cargo / cmake) !" >&2
		exit 1
	fi

_abi-clean-all-unix:
	#!/usr/bin/env bash
	set -euo pipefail
	# Find and remove all build/target directories
	find {{ABI_DIR}} -type d \( -name "build" -o -name "target" \) | while read -r builddir; do
		echo "==> Removing $builddir"
		rm -rf "$builddir"
	done

_abi-build-all-windows:
	#! pwsh
	$ErrorActionPreference = "Stop"
	# Find all directories with CMakeLists.txt
	Get-ChildItem -Path "{{ABI_DIR}}" -Recurse -Filter "CMakeLists.txt" | ForEach-Object {
		$dir = $_.DirectoryName
		Write-Host "==> Configuring $dir"
		cmake -S $dir -B (Join-Path $dir 'build') -G {{GEN}} -DCMAKE_TOOLCHAIN_FILE="{{TOOLCHAIN_WIN}}" -DCMAKE_BUILD_TYPE={{CONFIG}}
		Write-Host "==> Building $dir"
		cmake --build (Join-Path $dir 'build') --config {{CONFIG}}
	}

_abi-build-one-windows name:
	#! pwsh
	$ErrorActionPreference = "Stop"
	$dir = Join-Path "{{ABI_DIR}}" "{{name}}"
	if (!(Test-Path (Join-Path $dir 'CMakeLists.txt'))) {
		Write-Error "No CMakeLists.txt in $dir"
		exit 1
	}
	Write-Host "==> Configuring $dir"
	cmake -S $dir -B (Join-Path $dir 'build') -G {{GEN}} -DCMAKE_TOOLCHAIN_FILE="{{TOOLCHAIN_WIN}}" -DCMAKE_BUILD_TYPE={{CONFIG}}
	Write-Host "==> Building $dir"
	cmake --build (Join-Path $dir 'build') --config {{CONFIG}}

_abi-clean-all-windows:
	#! pwsh
	$ErrorActionPreference = "Stop"
	# Find and remove all build/target directories
	Get-ChildItem -Path "{{ABI_DIR}}" -Recurse -Directory | Where-Object { $_.Name -eq 'build' -or $_.Name -eq 'target' } | ForEach-Object {
		Write-Host "==> Removing $($_.FullName)"
		Remove-Item -Recurse -Force $_.FullName
	}
