package transport

import (
	"crypto/tls"
	"strings"

	"github.com/pion/dtls/v3"
)

// BuildTLSConfig builds a TLS config from a map of parameters.
func BuildTLSConfig(params map[string]any) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if params == nil {
		return cfg
	}

	if serverName, ok := params["server_name"].(string); ok && serverName != "" {
		cfg.ServerName = serverName
	}

	if skipVerify, ok := params["skip_verify"].(bool); ok {
		cfg.InsecureSkipVerify = skipVerify
	}

	if minVersion, ok := params["min_version"].(string); ok {
		switch strings.ToUpper(minVersion) {
		case "TLS1.0", "TLS10":
			cfg.MinVersion = tls.VersionTLS10
		case "TLS1.1", "TLS11":
			cfg.MinVersion = tls.VersionTLS11
		case "TLS1.2", "TLS12":
			cfg.MinVersion = tls.VersionTLS12
		case "TLS1.3", "TLS13":
			cfg.MinVersion = tls.VersionTLS13
		}
	}

	return cfg
}

// BuildDTLSConfig builds a DTLS config from a map of parameters.
func BuildDTLSConfig(params map[string]any) *dtls.Config {
	cfg := &dtls.Config{}

	if params == nil {
		return cfg
	}

	if skipVerify, ok := params["skip_verify"].(bool); ok && skipVerify {
		cfg.InsecureSkipVerify = true
	}

	return cfg
}
