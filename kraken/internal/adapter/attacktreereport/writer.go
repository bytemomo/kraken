package attacktreereport

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
)

// Writer writes attack tree evaluation results as Markdown files.
type Writer struct {
	OutDir string
}

// New creates a new attack tree report writer.
func New(outDir string) *Writer {
	return &Writer{OutDir: outDir}
}

// Save saves the evaluated attack trees to the result directory.
// It creates markdown files with both table and Mermaid graph representations.
func (w *Writer) Save(results []domain.AttackTreeResult) error {
	if len(results) == 0 {
		return nil
	}

	dir := filepath.Join(w.OutDir, "attack-trees")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create attack-trees dir: %w", err)
	}

	// Group by target
	byTarget := make(map[string][]domain.AttackTreeResult)
	for _, r := range results {
		key := safeName(r.Target.Key())
		byTarget[key] = append(byTarget[key], r)
	}

	// Write per-target markdown files
	for targetKey, treeResults := range byTarget {
		if err := w.writeTargetFile(dir, targetKey, treeResults); err != nil {
			return err
		}
	}

	// Also write a combined summary file
	return w.writeSummary(dir, results)
}

func (w *Writer) writeTargetFile(dir, targetKey string, treeResults []domain.AttackTreeResult) error {
	var sb strings.Builder
	target := treeResults[0].Target
	sb.WriteString(fmt.Sprintf("# Attack Trees for %s\n\n", target.String()))
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	// Summary table
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Attack Tree | Result |\n")
	sb.WriteString("|-------------|--------|\n")
	for _, tr := range treeResults {
		status := "Failed"
		if tr.Tree.Success {
			status = "Succeeded"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s |\n", tr.Tree.Name, status))
	}
	sb.WriteString("\n---\n\n")

	// Detailed view for each tree
	for _, tr := range treeResults {
		sb.WriteString(tr.Tree.RenderMarkdown())
		sb.WriteString("\n---\n\n")
	}

	path := filepath.Join(dir, targetKey+".md")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		return fmt.Errorf("write attack tree markdown: %w", err)
	}
	return nil
}

func (w *Writer) writeSummary(dir string, results []domain.AttackTreeResult) error {
	var sb strings.Builder
	sb.WriteString("# Attack Trees Summary\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	// Count successes per tree name
	treeSuccesses := make(map[string]struct {
		total   int
		success int
	})

	for _, r := range results {
		entry := treeSuccesses[r.Tree.Name]
		entry.total++
		if r.Tree.Success {
			entry.success++
		}
		treeSuccesses[r.Tree.Name] = entry
	}

	sb.WriteString("## Overall Results by Attack Tree\n\n")
	sb.WriteString("| Attack Tree | Targets Evaluated | Successful Attacks |\n")
	sb.WriteString("|-------------|-------------------|--------------------|\n")
	for name, counts := range treeSuccesses {
		sb.WriteString(fmt.Sprintf("| %s | %d | %d |\n", name, counts.total, counts.success))
	}
	sb.WriteString("\n")

	// Full results table
	sb.WriteString("## Detailed Results\n\n")
	sb.WriteString("| Target | Attack Tree | Result |\n")
	sb.WriteString("|--------|-------------|--------|\n")
	for _, r := range results {
		status := "Failed"
		if r.Tree.Success {
			status = "Succeeded"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", r.Target.String(), r.Tree.Name, status))
	}

	path := filepath.Join(dir, "summary.md")
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func safeName(s string) string {
	var result strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}
