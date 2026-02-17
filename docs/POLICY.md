# Kraken Safety Policy

This document describes the safety-by-default policy system in Kraken, including where policies are defined, validated, and enforced.

---

## Overview

Kraken implements a **safety-by-default** policy to protect OT (Operational Technology) environments from disruption during security assessments. The policy system:

1. **Blocks aggressive operations** unless explicitly permitted
2. **Requires bounded execution times** to prevent hung modules
3. **Controls connection behavior** (timeout, backoff, retries) for all conduit types

---

## Policy Definition

### Location: `kraken/internal/domain/policy.go`

```go
// Policy defines campaign-wide safety constraints.
type Policy struct {
    Safety SafetyPolicy `yaml:"safety,omitempty"`
    Runner RunnerPolicy `yaml:"runner,omitempty"`
}

// SafetyPolicy controls OT-safety enforcement.
type SafetyPolicy struct {
    // AllowAggressive permits tasks marked aggressive: true to run.
    // Default: false (aggressive tasks are rejected)
    AllowAggressive bool `yaml:"allow_aggressive,omitempty"`

    // RequireMaxDuration rejects tasks that don't specify max_duration.
    // Default: true
    RequireMaxDuration *bool `yaml:"require_max_duration,omitempty"`
}

// RunnerPolicy controls execution behavior.
type RunnerPolicy struct {
    // MaxParallelTargets bounds concurrent target processing.
    // Default: 1
    MaxParallelTargets int `yaml:"max_parallel_targets,omitempty"`

    // Defaults apply to all tasks unless overridden.
    Defaults ConnectionDefaults `yaml:"defaults,omitempty"`
}

// ConnectionDefaults control connection behavior for OT safety.
type ConnectionDefaults struct {
    // MaxConnectionsPerTarget bounds concurrent connections to one target.
    // Default: 1 (sequential - safest for OT)
    MaxConnectionsPerTarget int `yaml:"max_connections_per_target,omitempty"`

    // ConnectionTimeout is the dial timeout for new connections.
    // Default: 10s
    ConnectionTimeout time.Duration `yaml:"connection_timeout,omitempty"`

    // ConnectionBackoff is minimum delay between connection attempts.
    // Default: 100ms
    ConnectionBackoff time.Duration `yaml:"connection_backoff,omitempty"`

    // MaxReconnects limits retry attempts on connection failure.
    // Default: 3
    MaxReconnects int `yaml:"max_reconnects,omitempty"`
}
```

### Default Values

```go
// DefaultPolicy returns a policy with safe defaults.
func DefaultPolicy() Policy {
    requireMaxDuration := true
    return Policy{
        Safety: SafetyPolicy{
            AllowAggressive:    false,
            RequireMaxDuration: &requireMaxDuration,
        },
        Runner: RunnerPolicy{
            MaxParallelTargets: 1,
            Defaults: ConnectionDefaults{
                MaxConnectionsPerTarget: 1,
                ConnectionTimeout:       10 * time.Second,
                ConnectionBackoff:       100 * time.Millisecond,
                MaxReconnects:           3,
            },
        },
    }
}
```

---

## Policy Validation (Load Time)

### Location: `kraken/internal/adapter/yamlconfig/loader.go:167-195`

Policy validation happens during campaign loading, **before any execution starts**.

```go
// ValidatePolicy checks campaign policy constraints for OT safety.
func ValidatePolicy(campaign *domain.Campaign) error {
    policy := campaign.EffectivePolicy()

    for _, task := range campaign.Tasks {
        // Check aggressive tasks
        if task.Aggressive && !policy.Safety.AllowAggressive {
            return fmt.Errorf(
                "task %q is marked aggressive but policy.safety.allow_aggressive is false; "+
                    "set allow_aggressive: true to permit disruptive operations",
                task.ModuleID,
            )
        }

        // Check max_duration requirement
        if policy.Safety.RequiresMaxDuration() && task.MaxDuration == 0 {
            return fmt.Errorf(
                "task %q missing max_duration; all tasks must specify a timeout "+
                    "(or set policy.safety.require_max_duration: false)",
                task.ModuleID,
            )
        }
    }

    return nil
}
```

This function is called in `LoadCampaign()`:

```go
// In loader.go:166-169
// Validate safety policy
if err := ValidatePolicy(campaign); err != nil {
    return nil, err
}
```

---

## Policy Enforcement (Runtime)

### 1. Runner Extracts Policy

**Location: `kraken/internal/runner/runner.go:23-35`**

```go
func (r *Runner) Execute(ctx context.Context, campaign domain.Campaign, classified []domain.ClassifiedTarget) ([]domain.RunResult, error) {
    policy := campaign.EffectivePolicy()

    log := r.Log.WithFields(logrus.Fields{
        "max_parallel_targets": policy.Runner.MaxParallelTargets,
        "allow_aggressive":     policy.Safety.AllowAggressive,
        "require_max_duration": policy.Safety.RequiresMaxDuration(),
    })
    log.Info("Running campaign with safety policy")

    // ... uses policy.Runner.MaxParallelTargets for semaphore
    sem := make(chan struct{}, max(1, policy.Runner.MaxParallelTargets))
```

### 2. Connection Defaults Passed via Context

**Location: `kraken/internal/runner/runner.go:107-108`**

```go
func (r *Runner) runModuleStep(ctx context.Context, log *logrus.Entry, mod *domain.Module, target domain.Target, connDefaults domain.ConnectionDefaults) domain.RunResult {
    // ...
    ctx = context.WithValue(ctx, contextkeys.ConnectionDefaults, &connDefaults)
    rr, err := exec.Run(ctx, mod, mod.ExecConfig.Params, target, mod.MaxDuration)
```

### 3. Adapters Extract Defaults from Context

**Location: `kraken/internal/runner/adapter/native.go:70-77`**

```go
func (n *NativeBuiltinAdapter) dialOptionsFromContext(ctx context.Context) transport.DialOptions {
    if v := ctx.Value(contextkeys.ConnectionDefaults); v != nil {
        if defaults, ok := v.(*domain.ConnectionDefaults); ok {
            return transport.DialOptionsFromDefaults(defaults)
        }
    }
    return transport.DefaultDialOptions()
}
```

**Location: `kraken/internal/runner/adapter/abi.go:87-93`**

```go
func (a *ABIModuleAdapter) dialOptionsFromContext(ctx context.Context) transport.DialOptions {
    if v := ctx.Value(contextkeys.ConnectionDefaults); v != nil {
        if defaults, ok := v.(*domain.ConnectionDefaults); ok {
            return transport.DialOptionsFromDefaults(defaults)
        }
    }
    return transport.DefaultDialOptions()
}
```

---

## Conduit Policy Enforcement

### Location: `kraken/internal/transport/conduit.go:53-68`

All conduit types use `DialWithRetry()` which applies the policy settings:

```go
// DialWithRetry dials a conduit with retry logic for OT safety.
func DialWithRetry[T any](ctx context.Context, conduit cnd.Conduit[T], opts DialOptions) error {
    var lastErr error
    for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
        if attempt > 0 {
            // Apply backoff between retries
            select {
            case <-ctx.Done():
                return ctx.Err()
            case <-time.After(opts.Backoff):
            }
        }

        // Create timeout context for this dial attempt
        dialCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
        lastErr = conduit.Dial(dialCtx)
        cancel()

        if lastErr == nil {
            return nil
        }
    }
    return fmt.Errorf("dial failed after %d attempts: %w", opts.MaxRetries+1, lastErr)
}
```

### Conduit Types and Policy Application

| Conduit Kind | Transport Types | Where Built | Policy Applied |
|--------------|-----------------|-------------|----------------|
| **KindStream** | TCP, TLS | `BuildStreamConduit()` | `DialWithRetry()` with timeout/backoff/retries |
| **KindDatagram** | UDP, DTLS | `BuildDatagramConduit()` | `DialWithRetry()` with timeout/backoff/retries |
| **KindFrame** | Ethernet (EtherCAT) | `BuildEtherCATConduit()` | `DialWithRetry()` with timeout/backoff/retries |

### Stream Conduit (Native Adapter)

**Location: `kraken/internal/runner/adapter/native.go:80-94`**

```go
func (n *NativeBuiltinAdapter) buildNetworkResources(hp domain.HostPort, kind cnd.Kind, stack []domain.LayerHint, dialOpts transport.DialOptions) (native.Resources, error) {
    // ...
    switch kind {
    case cnd.KindStream:
        layerStack := stack
        opts := dialOpts
        res.StreamFactory = func(ctx context.Context) (interface{}, func(), error) {
            conduit, err := transport.BuildStreamConduit(addr, layerStack)
            if err != nil {
                return nil, nil, err
            }
            if err := transport.DialWithRetry(ctx, conduit, opts); err != nil {
                conduit.Close()
                return nil, nil, err
            }
            return conduit.Underlying(), func() { conduit.Close() }, nil
        }
```

### Frame Conduit (EtherCAT)

**Location: `kraken/internal/runner/adapter/native.go:119-132`**

```go
func (n *NativeBuiltinAdapter) buildEtherCATResources(slave domain.EtherCATSlave, kind cnd.Kind, dialOpts transport.DialOptions) (native.Resources, error) {
    // ...
    res.FrameFactory = func(ctx context.Context) (interface{}, func(), error) {
        conduit := datalink.Ethernet(iface, broadcast, datalink.EtherTypeEtherCAT)
        if err := transport.DialWithRetry(ctx, conduit, opts); err != nil {
            conduit.Close()
            return nil, nil, err
        }
        return conduit.Underlying(), func() { conduit.Close() }, nil
    }
```

### ABI Adapter Network Conduit

**Location: `kraken/internal/runner/adapter/abi.go:97-124`**

```go
func (a *ABIModuleAdapter) buildNetworkConduitFactory(addr string, kind cnd.Kind, stack []domain.LayerHint, dialOpts transport.DialOptions) contextkeys.ConduitFactoryFunc {
    return func(timeout time.Duration) (interface{}, func(), []string, error) {
        // ...
        switch kind {
        case cnd.KindStream:
            streamConduit, err := transport.BuildStreamConduit(addr, stack)
            if err != nil {
                return nil, nil, nil, err
            }
            if err := transport.DialWithRetry(dialCtx, streamConduit, dialOpts); err != nil {
                return nil, nil, nil, err
            }
            return streamConduit.Underlying(), func() { streamConduit.Close() }, layers, nil
        case cnd.KindDatagram:
            datagramConduit, err := transport.BuildDatagramConduit(addr, stack)
            if err != nil {
                return nil, nil, nil, err
            }
            if err := transport.DialWithRetry(dialCtx, datagramConduit, dialOpts); err != nil {
                return nil, nil, nil, err
            }
            return datagramConduit.Underlying(), func() { datagramConduit.Close() }, layers, nil
        }
    }
}
```

---

## Policy Flow Diagram

```
Campaign YAML
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Campaign.EffectivePolicy()  (domain/campaign.go:44)    │
│  └─ Merges user policy with DefaultPolicy()             │
└─────────────────────────────────────────────────────────┘
    │
    ├─► Safety validation at load time (loader.go:167)
    │   └─ ValidatePolicy() blocks:
    │      • aggressive tasks (if allow_aggressive: false)
    │      • tasks without max_duration (if require_max_duration: true)
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Runner.Execute()  (runner/runner.go:23-55)             │
│  └─ Extracts policy, logs safety settings               │
│  └─ Uses MaxParallelTargets for concurrency control     │
│  └─ Passes ConnectionDefaults to runForTarget()         │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  runModuleStep()  (runner/runner.go:91-117)             │
│  └─ Adds ConnectionDefaults to context                  │
│     ctx.WithValue(contextkeys.ConnectionDefaults, ...)  │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Adapter.dialOptionsFromContext(ctx)                    │
│  (native.go:70-77, abi.go:87-93)                        │
│  └─ Extracts ConnectionDefaults from context            │
│  └─ Converts to transport.DialOptions                   │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  transport.DialWithRetry(ctx, conduit, dialOpts)        │
│  (transport/conduit.go:53-68)                           │
│  └─ Applies: Timeout, Backoff, MaxRetries               │
│  └─ Works for ALL conduit types:                        │
│     • KindStream  (TCP, TLS)                            │
│     • KindDatagram (UDP, DTLS)                          │
│     • KindFrame   (Ethernet/EtherCAT)                   │
└─────────────────────────────────────────────────────────┘
```

---

## Campaign YAML Examples

### Minimal (uses all defaults)

```yaml
id: safe-campaign
tasks:
  - id: mqtt-check
    type: native
    max_duration: 30s  # Required by default policy
```

### Allow Aggressive Tasks

```yaml
id: fuzz-campaign
policy:
  safety:
    allow_aggressive: true
tasks:
  - id: mqtt-fuzzer
    type: cli
    aggressive: true
    max_duration: 300s
    exec:
      cli:
        command: /usr/bin/afl-fuzz
```

### Custom Connection Settings

```yaml
id: slow-network-campaign
policy:
  runner:
    max_parallel_targets: 4
    defaults:
      connection_timeout: 30s
      connection_backoff: 500ms
      max_reconnects: 5
      max_connections_per_target: 1
tasks:
  - id: slow-scan
    type: native
    max_duration: 120s
```

### Disable Duration Requirement (not recommended for OT)

```yaml
id: dev-campaign
policy:
  safety:
    require_max_duration: false
tasks:
  - id: interactive-test
    type: native
    # No max_duration - allowed because require_max_duration: false
```

---

## Summary Table

| Policy Setting | Default | Effect | Checked At |
|----------------|---------|--------|------------|
| `allow_aggressive` | `false` | Blocks tasks with `aggressive: true` | Campaign load |
| `require_max_duration` | `true` | Blocks tasks without `max_duration` | Campaign load |
| `max_parallel_targets` | `1` | Limits concurrent target processing | Runtime |
| `connection_timeout` | `10s` | Dial timeout per attempt | Runtime (all conduits) |
| `connection_backoff` | `100ms` | Delay between retry attempts | Runtime (all conduits) |
| `max_reconnects` | `3` | Maximum retry attempts | Runtime (all conduits) |
| `max_connections_per_target` | `1` | Concurrent connections per target | Runtime |

---

## Related Files

| File | Purpose |
|------|---------|
| `kraken/internal/domain/policy.go` | Policy structs and defaults |
| `kraken/internal/domain/policy_test.go` | Unit tests for policy merging |
| `kraken/internal/adapter/yamlconfig/loader.go` | Campaign loading and policy validation |
| `kraken/internal/runner/runner.go` | Runtime policy enforcement |
| `kraken/internal/runner/adapter/native.go` | Native adapter dial options |
| `kraken/internal/runner/adapter/abi.go` | ABI adapter dial options |
| `kraken/internal/transport/conduit.go` | `DialWithRetry()` implementation |
| `kraken/internal/runner/policy_integration_test.go` | Integration tests for policy enforcement |
