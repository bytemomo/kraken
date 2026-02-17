package native

import (
	"context"
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"
	cnd "bytemomo/trident/conduit"
)

func clearRegistry() {
	registry = map[string]Descriptor{}
}

func TestRegister_ValidModule(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	desc := Descriptor{
		Run: func(ctx context.Context, mod *domain.Module, target domain.Target, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
			return domain.RunResult{}, nil
		},
		Kind:        cnd.KindStream,
		Description: "Test module",
	}

	Register("test-module", desc)

	found, ok := Lookup("test-module")
	if !ok {
		t.Fatal("expected to find registered module")
	}
	if found.Description != "Test module" {
		t.Errorf("expected description 'Test module', got %q", found.Description)
	}
	if found.Kind != cnd.KindStream {
		t.Errorf("expected kind KindStream, got %v", found.Kind)
	}
}

func TestRegister_EmptyID(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	desc := Descriptor{
		Run: func(ctx context.Context, mod *domain.Module, target domain.Target, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
			return domain.RunResult{}, nil
		},
	}

	Register("", desc)

	if len(registry) != 0 {
		t.Error("should not register module with empty ID")
	}
}

func TestRegister_NilRun(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	desc := Descriptor{
		Run:  nil,
		Kind: cnd.KindStream,
	}

	Register("test-module", desc)

	if len(registry) != 0 {
		t.Error("should not register module with nil Run function")
	}
}

func TestRegister_OverwriteExisting(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	desc1 := Descriptor{
		Run: func(ctx context.Context, mod *domain.Module, target domain.Target, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
			return domain.RunResult{}, nil
		},
		Description: "First",
	}
	desc2 := Descriptor{
		Run: func(ctx context.Context, mod *domain.Module, target domain.Target, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
			return domain.RunResult{}, nil
		},
		Description: "Second",
	}

	Register("test-module", desc1)
	Register("test-module", desc2)

	found, ok := Lookup("test-module")
	if !ok {
		t.Fatal("expected to find registered module")
	}
	if found.Description != "Second" {
		t.Errorf("expected description 'Second' after overwrite, got %q", found.Description)
	}
}

func TestLookup_NotFound(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	_, ok := Lookup("nonexistent")
	if ok {
		t.Error("should not find unregistered module")
	}
}

func TestLookup_Found(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	desc := Descriptor{
		Run: func(ctx context.Context, mod *domain.Module, target domain.Target, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
			return domain.RunResult{}, nil
		},
		Kind: cnd.KindDatagram,
	}

	Register("udp-module", desc)

	found, ok := Lookup("udp-module")
	if !ok {
		t.Fatal("expected to find registered module")
	}
	if found.Kind != cnd.KindDatagram {
		t.Errorf("expected kind KindDatagram, got %v", found.Kind)
	}
}

func TestList_Empty(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	entries := List()
	if len(entries) != 0 {
		t.Errorf("expected empty list, got %d entries", len(entries))
	}
}

func TestList_MultipleModules(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	modules := []string{"mqtt-auth", "mqtt-dict", "coap-discover"}
	for _, id := range modules {
		Register(id, Descriptor{
			Run: func(ctx context.Context, mod *domain.Module, target domain.Target, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
				return domain.RunResult{}, nil
			},
			Description: id + " description",
		})
	}

	entries := List()
	if len(entries) != len(modules) {
		t.Fatalf("expected %d entries, got %d", len(modules), len(entries))
	}

	// Check all registered modules are in the list
	found := make(map[string]bool)
	for _, entry := range entries {
		found[entry.ID] = true
	}

	for _, id := range modules {
		if !found[id] {
			t.Errorf("module %q not found in list", id)
		}
	}
}

func TestDescriptor_WithStack(t *testing.T) {
	clearRegistry()
	defer clearRegistry()

	desc := Descriptor{
		Run: func(ctx context.Context, mod *domain.Module, target domain.Target, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
			return domain.RunResult{}, nil
		},
		Kind: cnd.KindStream,
		Stack: []domain.LayerHint{
			{Name: "tls"},
		},
	}

	Register("tls-module", desc)

	found, ok := Lookup("tls-module")
	if !ok {
		t.Fatal("expected to find registered module")
	}
	if len(found.Stack) != 1 {
		t.Fatalf("expected 1 stack layer, got %d", len(found.Stack))
	}
	if found.Stack[0].Name != "tls" {
		t.Errorf("expected stack layer name 'tls', got %q", found.Stack[0].Name)
	}
}
