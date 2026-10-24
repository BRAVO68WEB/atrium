package mgmtclient

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultServerURL = "http://127.0.0.1:8080"

type fileCreds struct {
	Server       string `yaml:"server"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Management   struct {
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
	} `yaml:"management"`
}

// Resolve fills empty credentials. Flags already copied onto the client win.
// Then environment variables, then --config. serverExplicit means --server was set.
func (c *Client) Resolve(serverExplicit bool) error {
	if c == nil {
		return fmt.Errorf("management client credentials required (--client-id and --client-secret, or management.* in config.yaml)")
	}
	if c.ClientID == "" {
		c.ClientID = strings.TrimSpace(os.Getenv("OAUTH_CLI_CLIENT_ID"))
	}
	if c.ClientSecret == "" {
		c.ClientSecret = os.Getenv("OAUTH_CLI_CLIENT_SECRET")
	}
	file, _ := readCredFile(c.ConfigPath)
	if !serverExplicit && (c.ServerURL == "" || c.ServerURL == defaultServerURL) {
		if env := strings.TrimSpace(os.Getenv("OAUTH_CLI_SERVER")); env != "" {
			c.ServerURL = env
		} else if file.Server != "" {
			c.ServerURL = file.Server
		}
	}
	if c.ClientID == "" {
		c.ClientID = firstNonEmpty(file.ClientID, file.Management.ClientID)
	}
	if c.ClientSecret == "" {
		c.ClientSecret = firstNonEmpty(file.ClientSecret, file.Management.ClientSecret)
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return fmt.Errorf("management client credentials required (--client-id and --client-secret, or management.* in config.yaml)")
	}
	if c.ServerURL == "" {
		c.ServerURL = defaultServerURL
	}
	return nil
}

func readCredFile(path string) (fileCreds, error) {
	var file fileCreds
	if path == "" {
		path = "config.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return file, err
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fileCreds{}, err
	}
	file.Server = strings.TrimSpace(file.Server)
	file.ClientID = strings.TrimSpace(file.ClientID)
	file.Management.ClientID = strings.TrimSpace(file.Management.ClientID)
	return file, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
