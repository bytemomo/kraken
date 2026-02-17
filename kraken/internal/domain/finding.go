package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

// Finding is a security finding that has been identified by a module.
type Finding struct {
	ID          string         `json:"id"`
	ModuleID    string         `json:"module_id"`
	Success     bool           `json:"success"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence"`
	Tags        []Tag          `json:"tags"`
	Timestamp   time.Time      `json:"timestamp"`
	Target      Target         `json:"target"`
}

// UnmarshalJSON implements custom unmarshaling for Finding to handle the Target interface.
func (f *Finding) UnmarshalJSON(data []byte) error {
	type Alias Finding
	aux := &struct {
		Target json.RawMessage `json:"target"`
		*Alias
	}{
		Alias: (*Alias)(f),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	if len(aux.Target) > 0 {
		target, err := unmarshalTarget(aux.Target)
		if err != nil {
			return fmt.Errorf("unmarshal finding target: %w", err)
		}
		f.Target = target
	}

	return nil
}
