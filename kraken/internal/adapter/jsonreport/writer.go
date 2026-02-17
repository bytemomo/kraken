package jsonreport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"bytemomo/kraken/internal/domain"
)

type Writer struct {
	OutDir string
}

func New(out string) *Writer { return &Writer{OutDir: out} }

func (w *Writer) Save(target domain.Target, res domain.RunResult) error {
	dir := filepath.Join(w.OutDir, "runs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := safeName(target.Key()) + ".json"
	path := filepath.Join(dir, name)

	// Merge with existing file if present (same target from a previous task)
	if data, err := os.ReadFile(path); err == nil {
		var existing domain.RunResult
		if json.Unmarshal(data, &existing) == nil && len(existing.Findings) > 0 {
			res.Findings = append(existing.Findings, res.Findings...)
			res.Logs = append(existing.Logs, res.Logs...)
		}
	}

	return writeJSONAtomic(path, res)
}

func (w *Writer) Aggregate(all []domain.RunResult) (string, error) {
	if err := os.MkdirAll(w.OutDir, 0o755); err != nil {
		return "", err
	}

	merged := mergeByTarget(all)

	path := filepath.Join(w.OutDir, "assessment.json")
	successPath := filepath.Join(w.OutDir, "assessment.success.json")

	payload := struct {
		Version   string             `json:"version"`
		Generated string             `json:"generated_utc"`
		Results   []domain.RunResult `json:"results"`
	}{
		Version:   "1.0",
		Generated: time.Now().UTC().Format(time.RFC3339),
		Results:   merged,
	}

	if err := writeJSONAtomic(path, payload); err != nil {
		return "", err
	}

	successOnly := filterSuccess(merged)
	successPayload := struct {
		Version   string             `json:"version"`
		Generated string             `json:"generated_utc"`
		Results   []domain.RunResult `json:"results"`
	}{
		Version:   "1.0",
		Generated: payload.Generated,
		Results:   successOnly,
	}

	if err := writeJSONAtomic(successPath, successPayload); err != nil {
		return "", err
	}

	return path, nil
}

// mergeByTarget combines RunResults that share the same target key.
func mergeByTarget(all []domain.RunResult) []domain.RunResult {
	order := make([]string, 0)
	index := make(map[string]*domain.RunResult)

	for _, r := range all {
		key := ""
		if r.Target != nil {
			key = r.Target.Key()
		}
		if existing, ok := index[key]; ok {
			existing.Findings = append(existing.Findings, r.Findings...)
			existing.Logs = append(existing.Logs, r.Logs...)
		} else {
			merged := r
			order = append(order, key)
			index[key] = &merged
		}
	}

	out := make([]domain.RunResult, 0, len(order))
	for _, key := range order {
		out = append(out, *index[key])
	}
	return out
}


var invalidRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s string) string { return invalidRe.ReplaceAllString(s, "_") }

func writeJSONAtomic(path string, v any) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(sanitize(v)); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("encode json: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}

	_ = os.Remove(path)
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename into place: %w", err)
	}

	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func sanitize(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = sanitize(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[fmt.Sprint(k)] = sanitize(vv)
		}
		return out
	case []any:
		for i := range t {
			t[i] = sanitize(t[i])
		}
		return t
	default:
		return t
	}
}

func filterSuccess(results []domain.RunResult) []domain.RunResult {
	out := make([]domain.RunResult, 0, len(results))
	for _, r := range results {
		var filtered []domain.Finding
		for _, f := range r.Findings {
			if f.Success {
				filtered = append(filtered, f)
			}
		}
		if len(filtered) == 0 {
			continue
		}
		r.Findings = filtered
		out = append(out, r)
	}
	return out
}
