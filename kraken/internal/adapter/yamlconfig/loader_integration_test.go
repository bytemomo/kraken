//go:build integration

package yamlconfig

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testdataPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "testdata", "campaigns", name)
}

func TestIntegration_CampaignLoad_Basic(t *testing.T) {
	campaign, err := LoadCampaign(testdataPath("basic.yaml"))
	require.NoError(t, err)

	assert.Equal(t, "test-basic", campaign.ID)
	assert.Equal(t, "1.0.0", campaign.Version)
	assert.Equal(t, domain.NetworkCampaign, campaign.Type)
	assert.Equal(t, "Basic Test Campaign", campaign.Name)

	// Verify policy loaded
	policy := campaign.EffectivePolicy()
	assert.False(t, policy.Safety.AllowAggressive)
	assert.True(t, *policy.Safety.RequireMaxDuration)
	assert.Equal(t, 2, policy.Runner.MaxParallelTargets)
	assert.Equal(t, 5*time.Second, policy.Runner.Defaults.ConnectionTimeout)
	assert.Equal(t, 100*time.Millisecond, policy.Runner.Defaults.ConnectionBackoff)
	assert.Equal(t, 2, policy.Runner.Defaults.MaxReconnects)

	// Verify scanner
	require.Len(t, campaign.Scanners, 1)
	assert.Equal(t, "nmap", campaign.Scanners[0].Type)

	// Verify tasks
	require.Len(t, campaign.Tasks, 1)
	assert.Equal(t, "mqtt-conformance-test", campaign.Tasks[0].ModuleID)
	assert.Equal(t, domain.Native, campaign.Tasks[0].Type)
	assert.Equal(t, 30*time.Second, campaign.Tasks[0].MaxDuration)
}

func TestIntegration_CampaignLoad_ConduitTemplates(t *testing.T) {
	campaign, err := LoadCampaign(testdataPath("templates.yaml"))
	require.NoError(t, err)

	assert.Equal(t, "test-templates", campaign.ID)

	// Verify conduit templates defined
	require.Len(t, campaign.ConduitTemplates, 2)

	tcpTemplate := campaign.ConduitTemplates[0]
	assert.Equal(t, "tcp", tcpTemplate.Name)
	assert.Len(t, tcpTemplate.Stack, 1)
	assert.Equal(t, "tcp", tcpTemplate.Stack[0].Name)

	tlsTemplate := campaign.ConduitTemplates[1]
	assert.Equal(t, "tls", tlsTemplate.Name)
	assert.Len(t, tlsTemplate.Stack, 2)
	assert.Contains(t, tlsTemplate.RequiredTags, "supports:tls")

	// Verify task references conduit templates
	require.Len(t, campaign.Tasks, 1)
	task := campaign.Tasks[0]
	assert.Equal(t, "mqtt-auth-check", task.ModuleID)

	// Template expansion should create variants
	// The original task should have conduit_templates: [tcp, tls]
	require.NotNil(t, task.ExecConfig.ConduitTemplates)
	assert.Contains(t, task.ExecConfig.ConduitTemplates, "tcp")
	assert.Contains(t, task.ExecConfig.ConduitTemplates, "tls")
}

func TestIntegration_CampaignLoad_InvalidPolicy_AggressiveBlocked(t *testing.T) {
	_, err := LoadCampaign(testdataPath("invalid-policy.yaml"))

	// Should fail because aggressive task is defined but allow_aggressive is false
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aggressive")
}

func TestIntegration_CampaignLoad_InvalidPolicy_MissingDuration(t *testing.T) {
	_, err := LoadCampaign(testdataPath("missing-duration.yaml"))

	// Should fail because task lacks max_duration but require_max_duration is true
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_duration")
}

func TestIntegration_CampaignLoad_MultiScanner(t *testing.T) {
	campaign, err := LoadCampaign(testdataPath("multi-scanner.yaml"))
	require.NoError(t, err)

	assert.Equal(t, "test-multi-scanner", campaign.ID)

	// Verify both scanners loaded
	require.Len(t, campaign.Scanners, 2)

	// First scanner: nmap
	assert.Equal(t, "nmap", campaign.Scanners[0].Type)
	require.NotNil(t, campaign.Scanners[0].Nmap)

	// Second scanner: ethercat
	assert.Equal(t, "ethercat", campaign.Scanners[1].Type)
	require.NotNil(t, campaign.Scanners[1].EtherCAT)
	assert.Equal(t, "eth0", campaign.Scanners[1].EtherCAT.Interface)

	// Verify tasks with different required_tags
	require.Len(t, campaign.Tasks, 2)

	mqttTask := campaign.Tasks[0]
	assert.Equal(t, "mqtt-auth-check", mqttTask.ModuleID)
	assert.Contains(t, mqttTask.RequiredTags, "protocol:mqtt")

	ecatTask := campaign.Tasks[1]
	assert.Equal(t, "ethercat-info", ecatTask.ModuleID)
	assert.Contains(t, ecatTask.RequiredTags, "protocol:ethercat")
}

func TestIntegration_CampaignLoad_EffectivePolicy_Defaults(t *testing.T) {
	// Load basic campaign which has explicit policy
	campaign, err := LoadCampaign(testdataPath("basic.yaml"))
	require.NoError(t, err)

	policy := campaign.EffectivePolicy()

	// Verify explicit values
	assert.Equal(t, 2, policy.Runner.MaxParallelTargets)
	assert.Equal(t, 5*time.Second, policy.Runner.Defaults.ConnectionTimeout)

	// Verify defaults are applied for unspecified values
	assert.Equal(t, 1, policy.Runner.Defaults.MaxConnectionsPerTarget)
}

func TestIntegration_CampaignLoad_NonExistentFile(t *testing.T) {
	_, err := LoadCampaign(testdataPath("nonexistent.yaml"))
	require.Error(t, err)
}

func TestIntegration_CampaignLoad_InvalidYAML(t *testing.T) {
	// Create a temp file with invalid YAML
	// This test ensures the loader handles malformed YAML gracefully
	_, err := LoadCampaign("/dev/null")
	require.Error(t, err)
}
