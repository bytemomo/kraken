package domain

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// NodeType is the type of a node in an attack tree.
type NodeType string

const (
	// LEAF is a leaf node in an attack tree.
	LEAF NodeType = "LEAF"
	// AND is an AND node in an attack tree.
	AND NodeType = "AND"
	// OR is an OR node in an attack tree.
	OR NodeType = "OR"
)

// SuccessMode is the mode for determining success of a leaf node.
type SuccessMode string

const (
	// SuccessModeAny means any finding is enough for success.
	SuccessModeAny SuccessMode = "any"
	// SuccessModeAll means all findings must be successful.
	SuccessModeAll SuccessMode = "all"
	// SuccessModeThreshold means a certain number of findings must be successful.
	SuccessModeThreshold SuccessMode = "threshold"
)

// AttackTreeResult represents the evaluation result of an attack tree for a target.
type AttackTreeResult struct {
	Target Target
	Tree   *AttackNode
}

// AttackNode is a node in an attack tree.
type AttackNode struct {
	Name     string        `yaml:"name"`
	Type     NodeType      `yaml:"type"`
	Children []*AttackNode `yaml:"children,omitempty"`
	Success  bool

	// NOTE: Only used on LEAF nodes
	FindingIDs       []string    `yaml:"finding_ids"`
	FindingMode      SuccessMode `yaml:"finding_mode"`
	FindingThreshold int         `yaml:"finding_threshold,omitempty"`
}

// Clone creates a deep copy of the attack tree node and all its children.
func (t *AttackNode) Clone() *AttackNode {
	if t == nil {
		return nil
	}

	clone := &AttackNode{
		Name:             t.Name,
		Type:             t.Type,
		Success:          false, // Reset success state
		FindingMode:      t.FindingMode,
		FindingThreshold: t.FindingThreshold,
	}

	if len(t.FindingIDs) > 0 {
		clone.FindingIDs = make([]string, len(t.FindingIDs))
		copy(clone.FindingIDs, t.FindingIDs)
	}

	if len(t.Children) > 0 {
		clone.Children = make([]*AttackNode, len(t.Children))
		for i, child := range t.Children {
			clone.Children[i] = child.Clone()
		}
	}

	return clone
}

// Evaluate evaluates the attack tree against a set of findings.
func (t *AttackNode) Evaluate(findings []Finding) bool {
	switch t.Type {
	case LEAF:
		return t.EvaluateLeaf(findings)
	case AND:
		{
			for _, child := range t.Children {
				if !child.Evaluate(findings) {
					return false
				}
			}
			t.Success = true
			return true
		}
	case OR:
		{
			for _, child := range t.Children {
				if child.Evaluate(findings) {
					t.Success = true
					return true
				}
			}
			return false
		}
	default:
		log.Errorf("Invalid attack tree's node type (available types are: LEAF, OR, AND): %s\n", nodeTypeToString(t.Type))
		return false
	}
}

// EvaluateLeaf evaluates a leaf node against a set of findings.
func (t *AttackNode) EvaluateLeaf(findings []Finding) bool {
	switch t.FindingMode {
	case SuccessModeAny:
		{
			for _, fid := range t.FindingIDs {
				for _, finding := range findings {
					if fid == finding.ID && finding.Success {
						t.Success = true
						return true
					}
				}
			}
			return false
		}
	case SuccessModeAll:
		{
			for _, fid := range t.FindingIDs {
				for _, finding := range findings {
					if fid == finding.ID && !finding.Success {
						return false
					}
				}
			}
			t.Success = true
			return true
		}
	case SuccessModeThreshold:
		{
			count := 0
			for _, pid := range t.FindingIDs {
				for _, finding := range findings {
					if pid == finding.ID && finding.Success {
						count += 1
						if count >= t.FindingThreshold {
							t.Success = true
							return true
						}
					}
				}
			}
			return false
		}
	default:
		log.Errorf("Invalid module mode in attack tree's settings (available types are: any, all, threshold): %s\n", moduleModeToString(t.FindingMode))
		return false
	}
}

// RenderTree renders the attack tree as a Mermaid graph.
func (t *AttackNode) RenderTree() string {
	var sb strings.Builder
	sb.WriteString("graph TD\n")

	var counter int
	var renderNode func(node *AttackNode, parentID string)

	renderNode = func(node *AttackNode, parentID string) {
		counter++
		nodeID := fmt.Sprintf("N%d", counter)

		var label string
		switch node.Type {
		case AND:
			label = fmt.Sprintf("%s{AND}", node.Name)
		case OR:
			label = fmt.Sprintf("%s{OR}", node.Name)
		case LEAF:
			label = fmt.Sprintf("%s[%s]", node.Name, "LEAF")
		default:
			label = node.Name
		}

		sb.WriteString(fmt.Sprintf("    %s[%q]\n", nodeID, label))
		if parentID != "" {
			sb.WriteString(fmt.Sprintf("    %s --- %s\n", parentID, nodeID))
		}
		if node.Success {
			sb.WriteString(fmt.Sprintf("    class %s success;\n", nodeID))
		}
		for _, child := range node.Children {
			renderNode(child, nodeID)
		}
	}

	renderNode(t, "")

	// Define Mermaid classes
	sb.WriteString("\n    classDef success fill:#ffcccc,stroke:#ff0000,stroke-width:2px;\n")

	return sb.String()
}

func nodeTypeToString(t NodeType) string {
	switch t {
	case LEAF:
		return "LEAF"
	case AND:
		return "AND"
	case OR:
		return "OR"
	default:
		return string(t)
	}
}

func moduleModeToString(m SuccessMode) string {
	switch m {
	case SuccessModeAll:
		return "all"
	case SuccessModeThreshold:
		return "threshold"
	case SuccessModeAny:
		return "any"
	default:
		return string(m)
	}
}

// RenderTable renders the attack tree as a markdown table.
func (t *AttackNode) RenderTable() string {
	var sb strings.Builder
	sb.WriteString("| Node | Type | Status | Finding IDs | Finding Mode |\n")
	sb.WriteString("|------|------|--------|-------------|-------------|\n")

	var renderRow func(node *AttackNode, depth int)
	renderRow = func(node *AttackNode, depth int) {
		indent := strings.Repeat("  ", depth)
		name := indent + node.Name

		status := "❌"
		if node.Success {
			status = "✅"
		}

		findingIDs := "-"
		findingMode := "-"
		if node.Type == LEAF {
			if len(node.FindingIDs) > 0 {
				findingIDs = strings.Join(node.FindingIDs, ", ")
			}
			findingMode = string(node.FindingMode)
			if node.FindingMode == SuccessModeThreshold {
				findingMode = fmt.Sprintf("%s (%d)", node.FindingMode, node.FindingThreshold)
			}
		}

		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			name, node.Type, status, findingIDs, findingMode))

		for _, child := range node.Children {
			renderRow(child, depth+1)
		}
	}

	renderRow(t, 0)
	return sb.String()
}

// RenderMarkdown renders the attack tree as a complete markdown document with both table and Mermaid graph.
func (t *AttackNode) RenderMarkdown() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Attack Tree: %s\n\n", t.Name))

	// Overall result
	result := "**Result: FAILED**"
	if t.Success {
		result = "**Result: SUCCEEDED**"
	}
	sb.WriteString(result + "\n\n")

	// Table view
	sb.WriteString("## Table View\n\n")
	sb.WriteString(t.RenderTable())
	sb.WriteString("\n")

	// Mermaid graph
	sb.WriteString("## Graph View\n\n")
	sb.WriteString("```mermaid\n")
	sb.WriteString(t.RenderTree())
	sb.WriteString("```\n")

	return sb.String()
}
