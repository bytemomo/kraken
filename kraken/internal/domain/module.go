package domain

import (
	cnd "bytemomo/trident/conduit"
	"fmt"
	"time"
)

// ModuleType is the type of a module.
type ModuleType string

const (
	// Native is a native module.
	Native ModuleType = "native"
	// Lib is a library module.
	Lib ModuleType = "lib"
	// Grpc is a gRPC module.
	Grpc ModuleType = "grpc"
	// Container is a containerized module (Docker/Podman/OCI).
	Container ModuleType = "container"
)

// ModuleAPIVersion is the version of the module API.
type ModuleAPIVersion string

const (
	// ModuleV1 is version 1 of the module API.
	ModuleV1 ModuleAPIVersion = "v1"
	// ModuleV2 is version 2 of the module API.
	ModuleV2 ModuleAPIVersion = "v2"
)

// Module is a module that can be run against a target.
type Module struct {
	ModuleID     string        `yaml:"id"`
	RequiredTags []string      `yaml:"required_tags,omitempty"`
	MaxDuration  time.Duration `yaml:"max_duration,omitempty"`
	Type         ModuleType    `yaml:"type"` // native|lib|grpc|cli|fuzz

	// Aggressive marks this task as potentially disruptive to OT devices.
	// Aggressive tasks may cause: connection churn, malformed packets,
	// high-frequency polling, fuzzing, write operations, or protocol violations.
	// Requires policy.safety.allow_aggressive: true to run.
	Aggressive bool `yaml:"aggressive,omitempty"`

	ExecConfig struct {
		ABI *struct {
			Version     ModuleAPIVersion `yaml:"api"`
			LibraryPath string           `yaml:"library_path"`
			Symbol      string           `yaml:"symbol"`
		} `yaml:"abi,omitempty"`

		GRPC *struct {
			ServerAddr  string         `yaml:"server_addr"`
			DialTimeout *time.Duration `yaml:"dial_timeout,omitempty"`
		} `yaml:"grpc,omitempty"`

		Container *ContainerConfig `yaml:"container,omitempty"`

		Conduit *struct {
			Kind  cnd.Kind    `yaml:"kind"`
			Stack []LayerHint `yaml:"stack,omitempty"`
		} `yaml:"conduit,omitempty"`

		ConduitTemplates []string `yaml:"conduit_templates,omitempty"`

		Params map[string]any `yaml:"params,omitempty"`
	} `yaml:"exec"`
}

// ContainerConfig configures the execution of a containerized module.
type ContainerConfig struct {
	Runtime string           `yaml:"runtime,omitempty"`
	Image   string           `yaml:"image"`
	Command []string         `yaml:"command,omitempty"`
	Mounts  []ContainerMount `yaml:"mounts,omitempty"`
}

// ContainerMount defines a bind mount to inject into the container.
type ContainerMount struct {
	HostPath      string `yaml:"host_path"`
	ContainerPath string `yaml:"container_path"`
	ReadOnly      bool   `yaml:"read_only,omitempty"`
}

// LayerHint is a hint for a layer in a conduit stack.
type LayerHint struct {
	Name   string         `yaml:"name"`
	Params map[string]any `yaml:"params,omitempty"`
}

// String implements the fmt.Stringer interface for LayerHint.
func (lh LayerHint) String() string {
	return fmt.Sprintf("%s", lh.Name)
}

// ConduitTemplate is a reusable conduit configuration.
type ConduitTemplate struct {
	Name         string      `yaml:"name"`
	Kind         cnd.Kind    `yaml:"kind"`
	Stack        []LayerHint `yaml:"stack,omitempty"`
	RequiredTags []string    `yaml:"required_tags,omitempty"`
}

// Validate validates the module configuration.
func (m *Module) Validate() error {
	if m.ModuleID == "" {
		return fmt.Errorf("module ID is required")
	}

	// Check that exactly one execution type is configured
	// Note: Conduit is transport configuration, not an execution type
	hasABI := m.ExecConfig.ABI != nil
	hasGRPC := m.ExecConfig.GRPC != nil
	hasContainer := m.ExecConfig.Container != nil

	count := 0
	if hasABI {
		count++
	}
	if hasGRPC {
		count++
	}
	if hasContainer {
		count++
	}

	if count == 0 {
		if m.Type != Native {
			return fmt.Errorf("module must specify one execution type (abi, grpc, or container)")
		}
	} else if count > 1 {
		return fmt.Errorf("module can only specify one execution type")
	}

	// Validate ABI config
	// ABI supports both V1 and V2
	if hasABI {
		if m.ExecConfig.ABI.Version != "v1" && m.ExecConfig.ABI.Version != "v2" {
			return fmt.Errorf("abi.version is required and accept only two valid values: v1 or v2")
		}

		if m.ExecConfig.ABI.LibraryPath == "" {
			return fmt.Errorf("abi.library_path is required")
		}
		if m.ExecConfig.ABI.Symbol == "" {
			return fmt.Errorf("abi.symbol is required")
		}
		if m.Type != Native && m.Type != Lib {
			return fmt.Errorf("abi execution requires type 'native' or 'lib'")
		}
		// ABI works with both V1 and V2 - no version restriction
	}

	// Validate GRPC config
	if hasGRPC {
		if m.ExecConfig.GRPC.ServerAddr == "" {
			return fmt.Errorf("grpc.server_addr is required")
		}
		if m.Type != Grpc {
			return fmt.Errorf("grpc execution requires type 'grpc'")
		}
	}

	// Validate Container config
	if hasContainer {
		if m.ExecConfig.Container.Image == "" {
			return fmt.Errorf("container.image is required")
		}
		if m.Type != Container {
			return fmt.Errorf("container execution requires type 'container'")
		}
		for i, mount := range m.ExecConfig.Container.Mounts {
			if mount.HostPath == "" {
				return fmt.Errorf("container.mounts[%d].host_path is required", i)
			}
			if mount.ContainerPath == "" {
				return fmt.Errorf("container.mounts[%d].container_path is required", i)
			}
		}
	}

	// Validate Conduit config (if present)
	// Conduit is optional and only used in V2 execution
	// For V1 modules with conduit config, it will be ignored (allows transition)
	if m.ExecConfig.Conduit != nil {
		if m.ExecConfig.Conduit.Kind == 0 {
			return fmt.Errorf("conduit.kind is required when conduit is specified")
		}
		// Conduit is only meaningful for V2, but we allow it in V1 for transition
		// (it will simply be ignored by V1 executors)
	}

	return nil
}
