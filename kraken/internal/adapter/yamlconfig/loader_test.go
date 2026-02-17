package yamlconfig

import (
	"os"
	"path/filepath"
	"testing"

	"bytemomo/kraken/internal/domain"
	cnd "bytemomo/trident/conduit"
)

func TestLoadCampaign_Basic(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
type: network
policy:
  runner:
    max_parallel_targets: 2
tasks:
  - id: test-task
    type: native
    max_duration: 30s
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	campaign, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("LoadCampaign failed: %v", err)
	}

	if campaign.ID != "test-campaign" {
		t.Errorf("expected ID 'test-campaign', got %q", campaign.ID)
	}
	if campaign.Type != domain.CampaignNetwork {
		t.Errorf("expected type 'network', got %q", campaign.Type)
	}
	if len(campaign.Tasks) != 1 {
		t.Errorf("expected 1 task, got %d", len(campaign.Tasks))
	}
}

func TestLoadCampaign_DefaultType(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
tasks:
  - id: test-task
    type: native
    max_duration: 30s
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	campaign, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("LoadCampaign failed: %v", err)
	}

	if campaign.Type != domain.CampaignNetwork {
		t.Errorf("expected default type 'network', got %q", campaign.Type)
	}
}

func TestLoadCampaign_ConduitTemplateExpansion(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
conduit_templates:
  - name: tcp
    kind: stream
    stack:
      - name: tcp
  - name: tls
    kind: stream
    stack:
      - name: tcp
      - name: tls
tasks:
  - id: my-task
    type: native
    max_duration: 30s
    exec:
      conduit_templates: [tcp, tls]
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	campaign, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("LoadCampaign failed: %v", err)
	}

	if len(campaign.Tasks) != 2 {
		t.Fatalf("expected 2 expanded tasks, got %d", len(campaign.Tasks))
	}

	// Check task IDs
	taskIDs := make(map[string]bool)
	for _, task := range campaign.Tasks {
		taskIDs[task.ModuleID] = true
	}

	if !taskIDs["my-task-tcp"] {
		t.Error("expected task 'my-task-tcp' not found")
	}
	if !taskIDs["my-task-tls"] {
		t.Error("expected task 'my-task-tls' not found")
	}
}

func TestLoadCampaign_ConduitTemplateTagMerging(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
conduit_templates:
  - name: tcp
    kind: stream
    stack:
      - name: tcp
  - name: tls
    kind: stream
    required_tags: ["supports:tls"]
    stack:
      - name: tcp
      - name: tls
tasks:
  - id: my-task
    type: native
    required_tags: ["protocol:mqtt"]
    max_duration: 30s
    exec:
      conduit_templates: [tcp, tls]
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	campaign, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("LoadCampaign failed: %v", err)
	}

	// Find the TLS task
	var tlsTask *domain.Module
	for _, task := range campaign.Tasks {
		if task.ModuleID == "my-task-tls" {
			tlsTask = task
			break
		}
	}

	if tlsTask == nil {
		t.Fatal("TLS task not found")
	}

	// Check that tags are merged
	hasProtocolMqtt := false
	hasSupportsTls := false
	for _, tag := range tlsTask.RequiredTags {
		if tag == "protocol:mqtt" {
			hasProtocolMqtt = true
		}
		if tag == "supports:tls" {
			hasSupportsTls = true
		}
	}

	if !hasProtocolMqtt {
		t.Error("TLS task missing 'protocol:mqtt' tag")
	}
	if !hasSupportsTls {
		t.Error("TLS task missing 'supports:tls' tag")
	}
}

func TestLoadCampaign_ConduitTemplateConduitSet(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
conduit_templates:
  - name: tcp
    kind: stream
    stack:
      - name: tcp
tasks:
  - id: my-task
    type: native
    max_duration: 30s
    exec:
      conduit_templates: [tcp]
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	campaign, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("LoadCampaign failed: %v", err)
	}

	if len(campaign.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(campaign.Tasks))
	}

	task := campaign.Tasks[0]
	if task.ExecConfig.Conduit == nil {
		t.Fatal("Conduit not set on expanded task")
	}

	if task.ExecConfig.Conduit.Kind != cnd.KindStream {
		t.Errorf("expected conduit kind %d, got %d", cnd.KindStream, task.ExecConfig.Conduit.Kind)
	}

	if len(task.ExecConfig.Conduit.Stack) != 1 {
		t.Fatalf("expected 1 layer in stack, got %d", len(task.ExecConfig.Conduit.Stack))
	}

	if task.ExecConfig.Conduit.Stack[0].Name != "tcp" {
		t.Errorf("expected layer name 'tcp', got %q", task.ExecConfig.Conduit.Stack[0].Name)
	}
}

func TestLoadCampaign_NoTemplates(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
tasks:
  - id: my-task
    type: native
    max_duration: 30s
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	campaign, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("LoadCampaign failed: %v", err)
	}

	if len(campaign.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(campaign.Tasks))
	}

	if campaign.Tasks[0].ModuleID != "my-task" {
		t.Errorf("expected task ID 'my-task', got %q", campaign.Tasks[0].ModuleID)
	}
}

func TestLoadCampaign_UnknownTemplate(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
conduit_templates:
  - name: tcp
    kind: stream
    stack:
      - name: tcp
tasks:
  - id: my-task
    type: native
    max_duration: 30s
    exec:
      conduit_templates: [tcp, nonexistent]
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error for unknown template")
	}
}

func TestLoadCampaign_DuplicateTemplateName(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
conduit_templates:
  - name: tcp
    kind: stream
    stack:
      - name: tcp
  - name: tcp
    kind: stream
    stack:
      - name: tcp
tasks:
  - id: my-task
    type: native
    max_duration: 30s
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error for duplicate template name")
	}
}

func TestLoadCampaign_TemplateMissingName(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
conduit_templates:
  - kind: stream
    stack:
      - name: tcp
tasks:
  - id: my-task
    type: native
    max_duration: 30s
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error for template missing name")
	}
}

func TestCloneModuleWithTemplate(t *testing.T) {
	mod := &domain.Module{
		ModuleID:     "test-module",
		RequiredTags: []string{"protocol:mqtt"},
		Type:         domain.Native,
	}

	tmpl := &domain.ConduitTemplate{
		Name:         "tls",
		Kind:         cnd.KindStream,
		RequiredTags: []string{"supports:tls"},
		Stack: []domain.LayerHint{
			{Name: "tcp"},
			{Name: "tls"},
		},
	}

	clone := cloneModuleWithTemplate(mod, tmpl)

	// Check ID is modified
	if clone.ModuleID != "test-module-tls" {
		t.Errorf("expected ID 'test-module-tls', got %q", clone.ModuleID)
	}

	// Check original is unchanged
	if mod.ModuleID != "test-module" {
		t.Error("original module was modified")
	}

	// Check tags are merged
	if len(clone.RequiredTags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(clone.RequiredTags))
	}

	// Check conduit is set
	if clone.ExecConfig.Conduit == nil {
		t.Fatal("conduit not set")
	}
	if clone.ExecConfig.Conduit.Kind != cnd.KindStream {
		t.Errorf("expected kind %d, got %d", cnd.KindStream, clone.ExecConfig.Conduit.Kind)
	}
	if len(clone.ExecConfig.Conduit.Stack) != 2 {
		t.Errorf("expected 2 layers, got %d", len(clone.ExecConfig.Conduit.Stack))
	}

	// Check conduit_templates is cleared
	if len(clone.ExecConfig.ConduitTemplates) != 0 {
		t.Error("conduit_templates should be cleared after expansion")
	}
}

func TestCloneModuleWithTemplate_NoDuplicateTags(t *testing.T) {
	mod := &domain.Module{
		ModuleID:     "test-module",
		RequiredTags: []string{"protocol:mqtt", "supports:tls"},
	}

	tmpl := &domain.ConduitTemplate{
		Name:         "tls",
		Kind:         cnd.KindStream,
		RequiredTags: []string{"supports:tls"}, // Already in module
	}

	clone := cloneModuleWithTemplate(mod, tmpl)

	// Should not duplicate the tag
	count := 0
	for _, tag := range clone.RequiredTags {
		if tag == "supports:tls" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 'supports:tls' tag, got %d", count)
	}
}

func TestContainsString(t *testing.T) {
	tests := []struct {
		slice    []string
		s        string
		expected bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{[]string{}, "a", false},
		{[]string{"abc"}, "ab", false},
		{[]string{"abc"}, "abc", true},
	}

	for _, tt := range tests {
		result := containsString(tt.slice, tt.s)
		if result != tt.expected {
			t.Errorf("containsString(%v, %q) = %v, expected %v", tt.slice, tt.s, result, tt.expected)
		}
	}
}

func TestLoadCampaign_FileNotFound(t *testing.T) {
	_, err := LoadCampaign("/nonexistent/path/campaign.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadCampaign_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
tasks:
  - this is not valid yaml: [
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadCampaign_InvalidCampaignType(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
type: invalid-type
tasks:
  - id: test-task
    type: native
    max_duration: 30s
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error for invalid campaign type")
	}
}

func TestLoadAttackTrees(t *testing.T) {
	dir := t.TempDir()
	treePath := filepath.Join(dir, "trees.yaml")

	content := `
- name: "Test Attack"
  description: "A test attack tree"
  children: []
`
	if err := os.WriteFile(treePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	trees, err := LoadAttackTrees(treePath)
	if err != nil {
		t.Fatalf("LoadAttackTrees failed: %v", err)
	}

	if len(trees) != 1 {
		t.Errorf("expected 1 tree, got %d", len(trees))
	}
}

func TestLoadAttackTrees_FileNotFound(t *testing.T) {
	_, err := LoadAttackTrees("/nonexistent/path/trees.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// --- Policy Validation Tests ---

func TestValidatePolicy_AggressiveTaskBlocked(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
policy:
  safety:
    allow_aggressive: false
tasks:
  - id: fuzzer
    type: container
    aggressive: true
    max_duration: 60s
    exec:
      container:
        image: fuzz:latest
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error for aggressive task with allow_aggressive: false")
	}

	expectedMsg := "is marked aggressive"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("error should mention aggressive task, got: %v", err)
	}
}

func TestValidatePolicy_AggressiveTaskAllowed(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
policy:
  safety:
    allow_aggressive: true
tasks:
  - id: fuzzer
    type: container
    aggressive: true
    max_duration: 60s
    exec:
      container:
        image: fuzz:latest
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("aggressive task should be allowed when allow_aggressive: true, got: %v", err)
	}
}

func TestValidatePolicy_MissingMaxDurationBlocked(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
policy:
  safety:
    require_max_duration: true
tasks:
  - id: no-timeout
    type: native
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error for task without max_duration")
	}

	expectedMsg := "missing max_duration"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("error should mention missing max_duration, got: %v", err)
	}
}

func TestValidatePolicy_MissingMaxDurationAllowed(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
policy:
  safety:
    require_max_duration: false
tasks:
  - id: no-timeout
    type: native
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("task without max_duration should be allowed when require_max_duration: false, got: %v", err)
	}
}

func TestValidatePolicy_DefaultRequiresMaxDuration(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	// No policy section - uses defaults (require_max_duration: true)
	content := `
id: test-campaign
tasks:
  - id: no-timeout
    type: native
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error - default policy requires max_duration")
	}
}

func TestValidatePolicy_DefaultBlocksAggressive(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	// No policy section - uses defaults (allow_aggressive: false)
	content := `
id: test-campaign
tasks:
  - id: fuzzer
    type: cli
    aggressive: true
    max_duration: 60s
    exec:
      cli:
        command: /bin/fuzz
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error - default policy blocks aggressive tasks")
	}
}

func TestValidatePolicy_ExpandedTasksValidated(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	// Task uses template but has no max_duration
	content := `
id: test-campaign
conduit_templates:
  - name: tcp
    kind: stream
    stack:
      - name: tcp
tasks:
  - id: no-timeout
    type: native
    exec:
      conduit_templates: [tcp]
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCampaign(campaignPath)
	if err == nil {
		t.Fatal("expected error - expanded tasks should also be validated")
	}

	// Error should reference the expanded task ID
	if !contains(err.Error(), "no-timeout-tcp") {
		t.Errorf("error should reference expanded task ID, got: %v", err)
	}
}

func TestValidatePolicy_WithPolicySection(t *testing.T) {
	dir := t.TempDir()
	campaignPath := filepath.Join(dir, "campaign.yaml")

	content := `
id: test-campaign
policy:
  safety:
    allow_aggressive: false
    require_max_duration: true
  runner:
    max_parallel_targets: 2
tasks:
  - id: safe-task
    type: native
    max_duration: 30s
`
	if err := os.WriteFile(campaignPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	campaign, err := LoadCampaign(campaignPath)
	if err != nil {
		t.Fatalf("LoadCampaign failed: %v", err)
	}

	policy := campaign.EffectivePolicy()
	if policy.Safety.AllowAggressive {
		t.Error("expected allow_aggressive: false")
	}
	if !policy.Safety.RequiresMaxDuration() {
		t.Error("expected require_max_duration: true")
	}
	if policy.Runner.MaxParallelTargets != 2 {
		t.Errorf("expected max_parallel_targets: 2, got %d", policy.Runner.MaxParallelTargets)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
