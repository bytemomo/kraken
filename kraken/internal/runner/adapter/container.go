package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"

	"github.com/sirupsen/logrus"
)

// decodeJSON decodes a JSON object from data, skipping any leading non-JSON text.
func decodeJSON(data []byte, v any) error {
	start := bytes.IndexByte(data, '{')
	if start == -1 {
		return fmt.Errorf("no JSON object found in output")
	}
	return json.NewDecoder(bytes.NewReader(data[start:])).Decode(v)
}

// ContainerModuleAdapter executes modules packaged as OCI container images.
// It expects the container to emit a domain.RunResult JSON payload on stdout.
type ContainerModuleAdapter struct{}

// NewContainerModuleAdapter creates a new container module adapter.
func NewContainerModuleAdapter() *ContainerModuleAdapter { return &ContainerModuleAdapter{} }

// Supports returns true if the module defines a container execution block.
func (a *ContainerModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}
	return m.ExecConfig.Container != nil && m.Type == domain.Container
}

// Run executes the configured container image.
func (a *ContainerModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	runtime := m.ExecConfig.Container.Runtime
	if runtime != "" && runtime != "host" && runtime != "podman" && runtime != "docker" {
		logrus.Warnf("Unsupported container runtime: %s, no official support for this runtime's API", runtime)
	}

	// Check if running on host (no container)
	if runtime == "host" || runtime == "" && m.ExecConfig.Container.Image == "" {
		return a.runOnHost(ctx, m, params, t)
	}

	return a.runInContainer(ctx, m, params, t, runtime)
}

// runOnHost executes the command directly on the host without containerization.
// Image field is used as the executable path, Command as arguments.
func (a *ContainerModuleAdapter) runOnHost(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target) (domain.RunResult, error) {
	var result domain.RunResult

	executable := m.ExecConfig.Container.Image
	if executable == "" {
		return result, fmt.Errorf("executable path (image field) is required for host runtime")
	}

	args := make([]string, 0, len(m.ExecConfig.Container.Command))
	args = append(args, m.ExecConfig.Container.Command...)

	// Pass target information based on campaign type (not for fuzz campaigns)
	isFuzzCampaign := false
	if campType, ok := ctx.Value(contextkeys.CampaignType).(*domain.CampaignType); ok && campType != nil {
		isFuzzCampaign = *campType == domain.CampaignFuzz
	}
	if !isFuzzCampaign {
		switch target := t.(type) {
		case domain.HostPort:
			if target.Host != "" || target.Port != 0 {
				args = append(args, "--host", target.Host, "--port", fmt.Sprintf("%d", target.Port))
			}
		case domain.EtherCATMaster:
			args = append(args, buildEtherCATMasterArgs(target)...)
		}
	}

	// Pass output directory if available
	if outDir, ok := ctx.Value(contextkeys.OutDir).(*string); ok && outDir != nil && *outDir != "" {
		args = append(args, "--output-dir", *outDir)
	}

	// Add params as arguments
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, k, fmt.Sprintf("%v", params[k]))
	}

	cmd := exec.CommandContext(ctx, executable, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// Try to parse output even if the command was killed (e.g., timeout)
	if stdout.Len() > 0 {
		if err := decodeJSON(stdout.Bytes(), &result); err == nil {
			return result, nil
		}
	}

	// No valid output - return the original error if any
	if runErr != nil {
		return result, fmt.Errorf("error running host module %s: %w: %s", m.ModuleID, runErr, stderr.String())
	}

	if stdout.Len() == 0 {
		return result, fmt.Errorf("error the module did not output any data")
	}

	return result, fmt.Errorf("error decoding module output: %s", stdout.String())
}

// runInContainer executes the module inside a container.
func (a *ContainerModuleAdapter) runInContainer(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, runtime string) (domain.RunResult, error) {
	var result domain.RunResult

	cidFile, err := os.CreateTemp("", "kraken-cid-*")
	if err != nil {
		return result, fmt.Errorf("creating cidfile: %w", err)
	}
	if err := cidFile.Close(); err != nil {
		return result, fmt.Errorf("closing cidfile: %w", err)
	}
	defer os.Remove(cidFile.Name())

	args := []string{"run", "--cidfile", cidFile.Name()}
	for _, mount := range m.ExecConfig.Container.Mounts {
		// Create host directory if it doesn't exist (for output directories)
		if !mount.ReadOnly {
			if err := os.MkdirAll(mount.HostPath, 0755); err != nil {
				logrus.Warnf("Failed to create mount directory %s: %v", mount.HostPath, err)
			}
		}
		spec := fmt.Sprintf("%s:%s", mount.HostPath, mount.ContainerPath)
		if mount.ReadOnly {
			spec = spec + ":ro"
		}
		args = append(args, "-v", spec)
	}

	args = append(args, m.ExecConfig.Container.Image)
	if len(m.ExecConfig.Container.Command) > 0 {
		args = append(args, m.ExecConfig.Container.Command...)
	}

	// Pass target information based on campaign type (not for fuzz campaigns)
	isFuzzCampaign := false
	if campType, ok := ctx.Value(contextkeys.CampaignType).(*domain.CampaignType); ok && campType != nil {
		isFuzzCampaign = *campType == domain.CampaignFuzz
	}
	if !isFuzzCampaign {
		switch target := t.(type) {
		case domain.HostPort:
			if target.Host != "" || target.Port != 0 {
				args = append(args, "--host", target.Host, "--port", fmt.Sprintf("%d", target.Port))
			}
		case domain.EtherCATMaster:
			args = append(args, buildEtherCATMasterArgs(target)...)
		}
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, k, fmt.Sprintf("%v", params[k]))
	}

	runtimeBin := m.ExecConfig.Container.Runtime
	if runtimeBin == "" {
		runtimeBin = os.Getenv("KRAKEN_CONTAINER_RUNTIME")
	}
	if runtimeBin == "" {
		runtimeBin = "podman"
	}

	cmd := exec.Command(runtimeBin, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return result, fmt.Errorf("error starting container module %s: %w", m.ModuleID, err)
	}

	// Wait for completion or context cancellation
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var runErr error
	var stopped bool
	select {
	case runErr = <-done:
		// Command completed normally
	case <-ctx.Done():
		// Context cancelled - use podman stop to send SIGTERM to container
		stopped = true
		cid := readCID(cidFile.Name())
		if cid != "" {
			stopContainer(runtimeBin, cid)
		}
		// Wait for process to finish
		select {
		case runErr = <-done:
		case <-time.After(15 * time.Second):
			// Force kill if still running
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			runErr = <-done
		}
		// Try to get output from container logs if stdout is empty
		if stdout.Len() == 0 && cid != "" {
			if logs := getContainerLogs(runtimeBin, cid); len(logs) > 0 {
				stdout.Write(logs)
			}
		}
	}

	// Only cleanup if we stopped it (otherwise --rm handles it)
	if stopped {
		if cid := readCID(cidFile.Name()); cid != "" {
			cleanupContainer(runtimeBin, cid)
		}
	}

	// Try to parse output even if the command was killed (e.g., timeout)
	// This is expected for fuzzing containers that run until killed
	if stdout.Len() > 0 {
		if err := decodeJSON(stdout.Bytes(), &result); err == nil {
			return result, nil
		}
	}

	// No valid output - return the original error if any
	if runErr != nil {
		return result, fmt.Errorf("error running container module %s: %w: %s", m.ModuleID, runErr, stderr.String())
	}

	if stdout.Len() == 0 {
		return result, fmt.Errorf("error the module did not output any data")
	}

	return result, fmt.Errorf("error decoding module output: %s", stdout.String())
}

func readCID(cidFilePath string) string {
	data, err := os.ReadFile(cidFilePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// stopContainer sends SIGTERM to the container for graceful shutdown.
func stopContainer(runtimeBin, cid string) {
	if cid == "" {
		return
	}
	// Use "stop" with timeout - sends SIGTERM, then SIGKILL after timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runtimeBin, "stop", "-t", "10", cid)
	_ = cmd.Run()
}

// getContainerLogs retrieves stdout/stderr from a stopped container.
func getContainerLogs(runtimeBin, cid string) []byte {
	if cid == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runtimeBin, "logs", cid)
	out, _ := cmd.Output()
	return out
}

func cleanupContainer(runtimeBin, cid string) {
	if cid == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runtimeBin, "rm", "-f", cid)
	_ = cmd.Run()
}
