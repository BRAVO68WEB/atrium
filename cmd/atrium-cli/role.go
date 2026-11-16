package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func roleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Role and permission commands",
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a role",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			description, _ := cmd.Flags().GetString("description")
			body, _ := json.Marshal(map[string]string{"name": name, "description": description})
			resp, err := apiPost(serverURL+"/api/roles", "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var result map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("failed to create role: %v", result["error_description"])
			}
			fmt.Printf("Role created: %s (%s)\n", result["name"], result["id"])
			return nil
		},
	}
	createCmd.Flags().String("name", "", "Role name")
	createCmd.Flags().String("description", "", "Role description")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List roles",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/roles")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var roles []map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tNAME\tDESCRIPTION\n")
			for _, role := range roles {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", role["id"], role["name"], role["description"])
			}
			return w.Flush()
		},
	}

	scopesCmd := &cobra.Command{
		Use:   "scopes [role-id]",
		Short: "Replace the scopes on a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			grants, _ := cmd.Flags().GetStringArray("grant")
			scopes := make([]map[string]string, 0, len(grants))
			for _, grant := range grants {
				resource, scope, ok := strings.Cut(grant, "|")
				if !ok || strings.TrimSpace(resource) == "" || strings.TrimSpace(scope) == "" {
					return fmt.Errorf("grant must be resource|scope")
				}
				scopes = append(scopes, map[string]string{"resource": strings.TrimSpace(resource), "scope": strings.TrimSpace(scope)})
			}
			body, _ := json.Marshal(map[string]any{"scopes": scopes})
			resp, err := apiPut(serverURL+"/api/roles/"+args[0]+"/scopes", "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var result map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to set role scopes: %v", result["error_description"])
			}
			fmt.Printf("Updated scopes for %s\n", result["id"])
			return nil
		},
	}
	scopesCmd.Flags().StringArray("grant", nil, "Resource and scope as resource|scope. Repeat for each scope. Replaces the set.")

	cmd.AddCommand(createCmd, listCmd, scopesCmd)
	return cmd
}
