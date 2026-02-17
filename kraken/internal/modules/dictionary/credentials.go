package dictionary

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Credential represents a username/password combination with metadata.
type Credential struct {
	Username  string
	Password  string
	IsDefault bool
}

// NewCredential constructs a Credential entry.
func NewCredential(username, password string, isDefault bool) Credential {
	return Credential{
		Username:  strings.TrimSpace(username),
		Password:  strings.TrimSpace(password),
		IsDefault: isDefault,
	}
}

// ErrNoCredentials is returned when no credentials are available after parsing.
var ErrNoCredentials = errors.New("no credentials available for dictionary attack")

// LoadCredentials builds the credential set using defaults, inline params, or files.
// Supported params keys:
//   - credentials_file: path to a file containing "user:pass" entries
//   - credentials: list of "user:pass" strings or maps {username,password}
func LoadCredentials(params map[string]any, defaults []Credential) ([]Credential, error) {
	var creds []Credential
	if params != nil {
		if file, ok := params["credentials_file"].(string); ok && strings.TrimSpace(file) != "" {
			fromFile, err := loadFromFile(file)
			if err != nil {
				return nil, err
			}
			creds = append(creds, fromFile...)
		}

		if raw, ok := params["credentials"]; ok {
			creds = append(creds, parseParam(raw)...)
		}
	}

	if len(creds) == 0 {
		creds = append(creds, defaults...)
	}

	creds = deduplicate(creds)
	if len(creds) == 0 {
		return nil, ErrNoCredentials
	}

	return creds, nil
}

func loadFromFile(path string) ([]Credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}
	var creds []Credential
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, pass := splitCredential(line)
		if user == "" && pass == "" {
			continue
		}
		creds = append(creds, NewCredential(user, pass, false))
	}
	return creds, nil
}

func parseParam(raw any) []Credential {
	var creds []Credential
	switch v := raw.(type) {
	case []string:
		for _, entry := range v {
			user, pass := splitCredential(entry)
			if user != "" || pass != "" {
				creds = append(creds, NewCredential(user, pass, false))
			}
		}
	case []any:
		for _, entry := range v {
			switch c := entry.(type) {
			case string:
				user, pass := splitCredential(c)
				if user != "" || pass != "" {
					creds = append(creds, NewCredential(user, pass, false))
				}
			case map[string]any:
				user, _ := c["username"].(string)
				pass, _ := c["password"].(string)
				if strings.TrimSpace(user) != "" || strings.TrimSpace(pass) != "" {
					creds = append(creds, NewCredential(user, pass, false))
				}
			}
		}
	case map[string]any:
		// Allow single map definition
		user, _ := v["username"].(string)
		pass, _ := v["password"].(string)
		if strings.TrimSpace(user) != "" || strings.TrimSpace(pass) != "" {
			creds = append(creds, NewCredential(user, pass, false))
		}
	}
	return creds
}

func splitCredential(entry string) (string, string) {
	parts := strings.SplitN(entry, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(entry), ""
}

func deduplicate(creds []Credential) []Credential {
	seen := make(map[string]Credential)
	for _, cred := range creds {
		key := cred.Username + "\x00" + cred.Password
		if existing, ok := seen[key]; ok {
			if existing.IsDefault && !cred.IsDefault {
				seen[key] = cred
			}
			continue
		}
		seen[key] = cred
	}
	result := make([]Credential, 0, len(seen))
	for _, cred := range seen {
		result = append(result, cred)
	}
	return result
}
