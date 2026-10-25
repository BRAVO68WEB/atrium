package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/hashalgo"
	"github.com/bravo68web/atrium/pkg/crypto"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

type initOptions struct {
	Dir      string
	Output   string
	WithMFA  bool
	Hash     string
	Force    bool
	HashAlgo string
}

type initResult struct {
	ConfigPath         string
	HasherMessage      string
	ManagementClientID string
}

func (r initResult) Format() string {
	return fmt.Sprintf(`%s
Configuration file written to: %s
Management client: %s
The client secret is in that file under management.client_secret.

Next:
  just run
  ./bin/atrium-cli user create --username "user" --password "pass" --email "user@example.com"
  ./bin/atrium-cli client create --name "App" --redirect-uri "https://example.com/cb"
`, r.HasherMessage, r.ConfigPath, r.ManagementClientID)
}

func initCmd() *cobra.Command {
	var outputPath string
	var withMFA bool
	var hashKind string
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize server configuration and password hasher",
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			result, err := runInit(initOptions{
				Dir:      wd,
				Output:   outputPath,
				WithMFA:  withMFA,
				Hash:     hashKind,
				Force:    force,
				HashAlgo: os.Getenv("HASH_ALGO"),
			})
			if err != nil {
				return err
			}
			fmt.Print(result.Format())
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: config.yaml)")
	cmd.Flags().BoolVar(&withMFA, "mfa", false, "Enable MFA in generated config")
	cmd.Flags().StringVar(&hashKind, "hash", "bcrypt", "Password hasher template: bcrypt or argon2id")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite the config file and the hasher file")

	return cmd
}

func runInit(opts initOptions) (initResult, error) {
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return initResult{}, err
	}

	out := opts.Output
	if out == "" {
		out = "config.yaml"
	}
	if !filepath.IsAbs(out) {
		out = filepath.Join(absDir, out)
	}

	if _, err := os.Stat(out); err == nil && !opts.Force {
		return initResult{}, fmt.Errorf("config file %s already exists (use --force to overwrite)", out)
	} else if err != nil && !os.IsNotExist(err) {
		return initResult{}, err
	}

	external, err := externalHasher(absDir, opts.HashAlgo)
	if err != nil {
		return initResult{}, err
	}
	message, err := hashalgo.Install(absDir, opts.Hash, external, opts.Force)
	if err != nil {
		return initResult{}, err
	}

	cfg := config.DefaultConfig()
	cfg.Security.HashAlgo = hashalgo.CanonicalRel
	if opts.WithMFA {
		cfg.Security.MFA.Enabled = true
		cfg.Security.MFA.Required = true
	}
	secret, err := crypto.GenerateToken()
	if err != nil {
		return initResult{}, err
	}
	cfg.Management.ClientID = uuid.NewString()
	cfg.Management.ClientSecret = secret
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return initResult{}, err
	}
	cfg.OIDC.PairwiseSalt = hex.EncodeToString(salt)
	if err := cfg.Save(out); err != nil {
		return initResult{}, fmt.Errorf("write config file: %w", err)
	}

	return initResult{ConfigPath: out, HasherMessage: message, ManagementClientID: cfg.Management.ClientID}, nil
}

func externalHasher(dir, envPath string) (string, error) {
	envPath = strings.TrimSpace(envPath)
	if envPath == "" {
		return "", nil
	}
	abs := envPath
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(dir, envPath)
	}
	abs = filepath.Clean(abs)
	canon := filepath.Clean(filepath.Join(dir, filepath.FromSlash(hashalgo.CanonicalRel)))
	if abs == canon {
		return "", nil
	}
	return abs, nil
}
