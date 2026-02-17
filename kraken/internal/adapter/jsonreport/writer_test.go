package jsonreport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"bytemomo/kraken/internal/domain"
)

func TestSave_CreatesRunFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := New(dir)

	target := domain.HostPort{Host: "10.0.0.1", Port: 1883}
	res := domain.RunResult{
		Target: target,
		Findings: []domain.Finding{
			{ID: "f1", ModuleID: "mod-a", Success: true, Title: "finding one"},
		},
	}

	if err := w.Save(target, res); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path := filepath.Join(dir, "runs", safeName(target.Key())+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}

	var got domain.RunResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got.Findings))
	}
	if got.Findings[0].ID != "f1" {
		t.Errorf("expected finding ID f1, got %s", got.Findings[0].ID)
	}
}

func TestSave_MergesWithExistingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := New(dir)

	target := domain.ContainerTarget{Image: "mosquitto-fuzz:aflpp"}

	first := domain.RunResult{
		Target: target,
		Findings: []domain.Finding{
			{ID: "f1", ModuleID: "mod-a", Success: true},
		},
		Logs: []string{"log-a"},
	}
	if err := w.Save(target, first); err != nil {
		t.Fatalf("Save first: %v", err)
	}

	second := domain.RunResult{
		Target: target,
		Findings: []domain.Finding{
			{ID: "f2", ModuleID: "mod-b", Success: false},
		},
		Logs: []string{"log-b"},
	}
	if err := w.Save(target, second); err != nil {
		t.Fatalf("Save second: %v", err)
	}

	path := filepath.Join(dir, "runs", safeName(target.Key())+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var got domain.RunResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Findings) != 2 {
		t.Fatalf("expected 2 merged findings, got %d", len(got.Findings))
	}
	if got.Findings[0].ID != "f1" {
		t.Errorf("expected first finding f1, got %s", got.Findings[0].ID)
	}
	if got.Findings[1].ID != "f2" {
		t.Errorf("expected second finding f2, got %s", got.Findings[1].ID)
	}
	if len(got.Logs) != 2 {
		t.Fatalf("expected 2 merged logs, got %d", len(got.Logs))
	}
}

func TestSave_ThreeTasksSameTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := New(dir)

	target := domain.ContainerTarget{Image: "img:v1"}

	for i, id := range []string{"f1", "f2", "f3"} {
		res := domain.RunResult{
			Target:   target,
			Findings: []domain.Finding{{ID: id, ModuleID: "mod", Success: i%2 == 0}},
		}
		if err := w.Save(target, res); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}

	path := filepath.Join(dir, "runs", safeName(target.Key())+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var got domain.RunResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Findings) != 3 {
		t.Fatalf("expected 3 findings after 3 saves, got %d", len(got.Findings))
	}
}

func TestMergeByTarget_CombinesSameKey(t *testing.T) {
	t.Parallel()

	target := domain.HostPort{Host: "10.0.0.1", Port: 1883}
	all := []domain.RunResult{
		{
			Target:   target,
			Findings: []domain.Finding{{ID: "f1"}},
			Logs:     []string{"log1"},
		},
		{
			Target:   target,
			Findings: []domain.Finding{{ID: "f2"}},
			Logs:     []string{"log2"},
		},
	}

	merged := mergeByTarget(all)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged result, got %d", len(merged))
	}
	if len(merged[0].Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(merged[0].Findings))
	}
	if len(merged[0].Logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(merged[0].Logs))
	}
}

func TestMergeByTarget_DifferentKeysStaySeparate(t *testing.T) {
	t.Parallel()

	all := []domain.RunResult{
		{
			Target:   domain.HostPort{Host: "10.0.0.1", Port: 1883},
			Findings: []domain.Finding{{ID: "f1"}},
		},
		{
			Target:   domain.HostPort{Host: "10.0.0.2", Port: 1883},
			Findings: []domain.Finding{{ID: "f2"}},
		},
	}

	merged := mergeByTarget(all)

	if len(merged) != 2 {
		t.Fatalf("expected 2 separate results, got %d", len(merged))
	}
}

func TestMergeByTarget_PreservesOrder(t *testing.T) {
	t.Parallel()

	all := []domain.RunResult{
		{Target: domain.HostPort{Host: "b", Port: 1}, Findings: []domain.Finding{{ID: "b1"}}},
		{Target: domain.HostPort{Host: "a", Port: 1}, Findings: []domain.Finding{{ID: "a1"}}},
		{Target: domain.HostPort{Host: "b", Port: 1}, Findings: []domain.Finding{{ID: "b2"}}},
	}

	merged := mergeByTarget(all)

	if len(merged) != 2 {
		t.Fatalf("expected 2 results, got %d", len(merged))
	}
	// "b" seen first, so it comes first
	if merged[0].Target.Key() != "b:1" {
		t.Errorf("expected first key b:1, got %s", merged[0].Target.Key())
	}
	if merged[1].Target.Key() != "a:1" {
		t.Errorf("expected second key a:1, got %s", merged[1].Target.Key())
	}
	if len(merged[0].Findings) != 2 {
		t.Errorf("expected 2 findings for b, got %d", len(merged[0].Findings))
	}
}

func TestMergeByTarget_NilTarget(t *testing.T) {
	t.Parallel()

	all := []domain.RunResult{
		{Target: nil, Findings: []domain.Finding{{ID: "f1"}}},
		{Target: nil, Findings: []domain.Finding{{ID: "f2"}}},
	}

	merged := mergeByTarget(all)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged result for nil targets, got %d", len(merged))
	}
	if len(merged[0].Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(merged[0].Findings))
	}
}

func TestMergeByTarget_Empty(t *testing.T) {
	t.Parallel()

	merged := mergeByTarget(nil)
	if len(merged) != 0 {
		t.Fatalf("expected empty, got %d", len(merged))
	}
}

func TestAggregate_MergesSameTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := New(dir)

	target := domain.ContainerTarget{Image: "img:v1"}
	all := []domain.RunResult{
		{
			Target:   target,
			Findings: []domain.Finding{{ID: "f1", Success: true}},
		},
		{
			Target:   target,
			Findings: []domain.Finding{{ID: "f2", Success: false}},
		},
	}

	path, err := w.Aggregate(all)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var assessment struct {
		Results []domain.RunResult `json:"results"`
	}
	if err := json.Unmarshal(data, &assessment); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(assessment.Results) != 1 {
		t.Fatalf("expected 1 merged result, got %d", len(assessment.Results))
	}
	if len(assessment.Results[0].Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(assessment.Results[0].Findings))
	}
}

func TestAggregate_SuccessFileOnlyHasSuccessFindings(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := New(dir)

	target := domain.HostPort{Host: "10.0.0.1", Port: 1883}
	all := []domain.RunResult{
		{
			Target: target,
			Findings: []domain.Finding{
				{ID: "f1", Success: true},
				{ID: "f2", Success: false},
				{ID: "f3", Success: true},
			},
		},
	}

	if _, err := w.Aggregate(all); err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "assessment.success.json"))
	if err != nil {
		t.Fatalf("read success file: %v", err)
	}

	var assessment struct {
		Results []domain.RunResult `json:"results"`
	}
	if err := json.Unmarshal(data, &assessment); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(assessment.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(assessment.Results))
	}
	if len(assessment.Results[0].Findings) != 2 {
		t.Fatalf("expected 2 success findings, got %d", len(assessment.Results[0].Findings))
	}
	for _, f := range assessment.Results[0].Findings {
		if !f.Success {
			t.Errorf("expected only success findings, got %s with success=false", f.ID)
		}
	}
}

func TestAggregate_SuccessFileExcludesTargetsWithNoSuccessFindings(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := New(dir)

	all := []domain.RunResult{
		{
			Target:   domain.HostPort{Host: "10.0.0.1", Port: 1883},
			Findings: []domain.Finding{{ID: "f1", Success: false}},
		},
		{
			Target:   domain.HostPort{Host: "10.0.0.2", Port: 1883},
			Findings: []domain.Finding{{ID: "f2", Success: true}},
		},
	}

	if _, err := w.Aggregate(all); err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "assessment.success.json"))
	if err != nil {
		t.Fatalf("read success file: %v", err)
	}

	var assessment struct {
		Results []domain.RunResult `json:"results"`
	}
	if err := json.Unmarshal(data, &assessment); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(assessment.Results) != 1 {
		t.Fatalf("expected 1 result (only host with success), got %d", len(assessment.Results))
	}
}

func TestFilterSuccess_NoSuccessFindings(t *testing.T) {
	t.Parallel()

	results := []domain.RunResult{
		{
			Target:   domain.HostPort{Host: "10.0.0.1", Port: 1883},
			Findings: []domain.Finding{{ID: "f1", Success: false}},
		},
	}

	filtered := filterSuccess(results)
	if len(filtered) != 0 {
		t.Fatalf("expected empty results, got %d", len(filtered))
	}
}

func TestSafeName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"10.0.0.1:1883", "10.0.0.1_1883"},
		{"container:img:v1", "container_img_v1"},
		{"simple", "simple"},
		{"a/b/c", "a_b_c"},
		{"a b c", "a_b_c"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := safeName(tc.input)
			if got != tc.expected {
				t.Errorf("safeName(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}
