package domain

// ABIConfig is the configuration for an ABI module.
type ABIConfig struct {
	LibraryPath string `yaml:"library"`
	Symbol      string `yaml:"symbol"`
}
