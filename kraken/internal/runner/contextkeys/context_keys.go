package contextkeys

import "time"

// contextKey is a typed key for storing runner-specific values in a context.Context.
type contextKey string

func (k contextKey) String() string {
	return "kraken runner context key " + string(k)
}

// ConduitFactoryFunc dials a new conduit for ABI v2 modules and returns the
// underlying transport handle, a cleanup function, and the stack layer names.
type ConduitFactoryFunc func(timeout time.Duration) (interface{}, func(), []string, error)

var (
	// OutDir stores the path where modules should write their outputs.
	OutDir contextKey = "out_dir"
	// ABIConfig stores the ABI execution configuration.
	ABIConfig contextKey = "abi_config"
	// ConduitFactory stores the factory for dialing additional conduits (ABI v2).
	ConduitFactory contextKey = "conduit_factory"
	// StackLayers stores the protocol stack layer names for the conduit.
	StackLayers contextKey = "stack_layers"
	// ConnectionDefaults stores the OT safety connection defaults from policy.
	ConnectionDefaults contextKey = "connection_defaults"
	// CampaignType stores the campaign type (network or fuzz).
	CampaignType contextKey = "campaign_type"
)
