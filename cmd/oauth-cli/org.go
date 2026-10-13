package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func orgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "org",
		Short: "Organization management",
	}
	cmd.AddCommand(orgCreateCmd(), orgDomainCmd(), orgMemberCmd())
	return cmd
}

func orgCreateCmd() *cobra.Command {
	var name, slug, domain, logoURL string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"name": name, "slug": slug}
			if domain != "" {
				body["domains"] = []string{domain}
			}
			if logoURL != "" {
				body["logo_url"] = logoURL
			}
			return postOrg("/api/orgs", body)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Display name")
	cmd.Flags().StringVar(&slug, "slug", "", "URL slug")
	cmd.Flags().StringVar(&domain, "domain", "", "Email domain for autolookup")
	cmd.Flags().StringVar(&logoURL, "logo-url", "", "Absolute http or https logo")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("slug")
	return cmd
}

func orgDomainCmd() *cobra.Command {
	var orgID, domain string
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Add an email domain to an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			return postOrg("/api/orgs/"+orgID+"/domains", map[string]string{"domain": domain})
		},
	}
	cmd.Flags().StringVar(&orgID, "org", "", "Organization id or slug")
	cmd.Flags().StringVar(&domain, "domain", "", "Bare email domain")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

func orgMemberCmd() *cobra.Command {
	var orgID, userID, role string
	cmd := &cobra.Command{
		Use:   "member",
		Short: "Add a user to an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			return postOrg("/api/orgs/"+orgID+"/members", map[string]string{"user_id": userID, "role": role})
		},
	}
	cmd.Flags().StringVar(&orgID, "org", "", "Organization id or slug")
	cmd.Flags().StringVar(&userID, "user-id", "", "User id")
	cmd.Flags().StringVar(&role, "role", "member", "member or admin")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("user-id")
	return cmd
}

func postOrg(path string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := apiPost(serverURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("org request failed: %s", bytes.TrimSpace(body))
	}
	fmt.Println(string(body))
	return nil
}
