package registry

import (
	"context"
	"fmt"

	"bytemomo/kraken/internal/domain"
)

// Resolver resolves modules from the registry and populates their ExecConfig
type Resolver struct {
	client *Client
}

// NewResolver creates a new module resolver
func NewResolver(client *Client) *Resolver {
	return &Resolver{
		client: client,
	}
}

// ResolveModule fetches a module from registry and populates its ExecConfig
// Uses lazy loading: only fetches metadata during campaign load, defers artifact download to execution
func (r *Resolver) ResolveModule(ctx context.Context, mod *domain.Module) error {
	if mod.Registry == "" {
		return nil // Not a registry module
	}

	version := mod.Registry
	if version == "true" {
		version = "latest"
	}

	// ResolveOnly fetches metadata and manifest without downloading the artifact
	resolved, err := r.client.ResolveOnly(ctx, mod.ModuleID, version)
	if err != nil {
		return fmt.Errorf("resolve module %s: %w", mod.ModuleID, err)
	}

	// Store resolved info for lazy download during execution
	mod.RegistryResolved = resolved

	// Validate module type if already set in campaign
	if mod.Type != "" && !isCompatibleType(mod.Type, resolved.Type) {
		return fmt.Errorf("module %s: type mismatch - campaign specifies %s but registry has %s",
			mod.ModuleID, mod.Type, resolved.Type)
	}

	// Populate ExecConfig based on module type from manifest
	switch resolved.Type {
	case "abi":
		if err := r.populateABIConfig(mod, resolved); err != nil {
			return err
		}

	case "container":
		if err := r.populateContainerConfig(mod, resolved); err != nil {
			return err
		}

	case "grpc":
		return fmt.Errorf("gRPC modules from registry not yet supported")

	default:
		return fmt.Errorf("unknown module type: %s", resolved.Type)
	}

	return nil
}

func (r *Resolver) populateABIConfig(mod *domain.Module, resolved *ResolvedModule) error {
	if mod.ExecConfig.ABI == nil {
		mod.ExecConfig.ABI = &struct {
			Version     domain.ModuleAPIVersion `yaml:"api"`
			LibraryPath string                  `yaml:"library_path"`
			Symbol      string                  `yaml:"symbol"`
		}{}
	}

	// LibraryPath is set lazily during EnsureReady() when artifact is downloaded

	// Use manifest values, with campaign overrides taking precedence
	if resolved.Manifest != nil && resolved.Manifest.ABI != nil {
		if mod.ExecConfig.ABI.Symbol == "" {
			mod.ExecConfig.ABI.Symbol = resolved.Manifest.ABI.Symbol
		}
		if mod.ExecConfig.ABI.Version == "" {
			mod.ExecConfig.ABI.Version = parseAPIVersion(resolved.Manifest.ABI.API)
		}
	}

	// Final defaults if still empty
	if mod.ExecConfig.ABI.Symbol == "" {
		mod.ExecConfig.ABI.Symbol = "kraken_run_v2"
	}
	if mod.ExecConfig.ABI.Version == "" {
		mod.ExecConfig.ABI.Version = domain.ModuleV2
	}

	if mod.Type == "" {
		mod.Type = domain.Lib
	}

	return nil
}

func (r *Resolver) populateContainerConfig(mod *domain.Module, resolved *ResolvedModule) error {
	if mod.ExecConfig.Container == nil {
		mod.ExecConfig.Container = &domain.ContainerConfig{}
	}

	// Image path is set lazily during EnsureReady() when artifact is downloaded

	if mod.Type == "" {
		mod.Type = domain.Container
	}

	return nil
}

func parseAPIVersion(api string) domain.ModuleAPIVersion {
	switch api {
	case "v1":
		return domain.ModuleV1
	case "v2":
		return domain.ModuleV2
	default:
		return domain.ModuleV2
	}
}

func isCompatibleType(campaignType domain.ModuleType, registryType string) bool {
	switch registryType {
	case "abi":
		return campaignType == domain.Lib
	case "container":
		return campaignType == domain.Container
	case "grpc":
		return campaignType == domain.Grpc
	default:
		return false
	}
}

// ResolveModules resolves all registry modules in a slice
func (r *Resolver) ResolveModules(ctx context.Context, modules []*domain.Module) error {
	for _, mod := range modules {
		if err := r.ResolveModule(ctx, mod); err != nil {
			return err
		}
	}
	return nil
}

// EnsureReady downloads the module artifact if needed and sets the execution paths.
// Call this before executing a registry module.
func (r *Resolver) EnsureReady(ctx context.Context, mod *domain.Module) error {
	if mod.Registry == "" || mod.RegistryResolved == nil {
		return nil // Not a registry module or already ready
	}

	resolved, ok := mod.RegistryResolved.(*ResolvedModule)
	if !ok {
		return fmt.Errorf("invalid registry resolved type")
	}

	// Download if not already cached
	if err := r.client.EnsureDownloaded(ctx, resolved); err != nil {
		return fmt.Errorf("download module %s: %w", mod.ModuleID, err)
	}

	// Set execution paths now that artifact is downloaded
	switch resolved.Type {
	case "abi":
		if mod.ExecConfig.ABI != nil {
			mod.ExecConfig.ABI.LibraryPath = resolved.LocalPath
		}
	case "container":
		if mod.ExecConfig.Container != nil {
			mod.ExecConfig.Container.Image = resolved.LocalPath
		}
	}

	return nil
}
