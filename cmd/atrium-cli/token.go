package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func tokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Token management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			userID, _ := cmd.Flags().GetString("user-id")

			url := serverURL + "/api/tokens?"
			if clientID != "" {
				url += "client_id=" + clientID + "&"
			}
			if userID != "" {
				url += "user_id=" + userID
			}

			resp, err := apiGet(url)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var tokens []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "TOKEN\tCLIENT ID\tUSER ID\tTYPE\tEXPIRES\n")
			for _, t := range tokens {
				token := t["token"].(string)
				if len(token) > 20 {
					token = token[:20] + "..."
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					token, t["client_id"], t["user_id"], t["token_type"], t["expires_at"])
			}
			_ = w.Flush()
			return nil
		},
	}

	listCmd.Flags().String("client-id", "", "Filter by client ID")
	listCmd.Flags().String("user-id", "", "Filter by user ID")

	refreshCmd := &cobra.Command{
		Use:   "refresh",
		Short: "Refresh token management",
	}
	refreshList := &cobra.Command{
		Use:   "list",
		Short: "List refresh tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			userID, _ := cmd.Flags().GetString("user-id")
			path := serverURL + "/api/refresh-tokens?"
			if clientID != "" {
				path += "client_id=" + clientID + "&"
			}
			if userID != "" {
				path += "user_id=" + userID
			}
			resp, err := apiGet(path)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var tokens []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tCLIENT ID\tUSER ID\tFAMILY\tEXPIRES\n")
			for _, t := range tokens {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t["id"], t["client_id"], t["user_id"], t["family_id"], t["expires_at"])
			}
			_ = w.Flush()
			return nil
		},
	}
	refreshList.Flags().String("client-id", "", "Filter by client ID")
	refreshList.Flags().String("user-id", "", "Filter by user ID")
	refreshRevoke := &cobra.Command{
		Use:   "revoke [id]",
		Short: "Revoke a refresh token by public id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiPost(serverURL+"/api/refresh-tokens/"+args[0]+"/revoke", "", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("revoke failed: %s", resp.Status)
			}
			fmt.Println("Refresh token revoked")
			return nil
		},
	}
	refreshCmd.AddCommand(refreshList, refreshRevoke)

	introspectCmd := &cobra.Command{
		Use:   "introspect [token]",
		Short: "Introspect a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := "token=" + args[0]
			resp, err := http.Post(serverURL+"/oauth/introspect",
				"application/x-www-form-urlencoded",
				bytes.NewBufferString(body))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				_, _ = fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			_ = w.Flush()
			return nil
		},
	}

	revokeCmd := &cobra.Command{
		Use:   "revoke [token]",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest("POST", serverURL+"/api/tokens/"+args[0]+"/revoke", nil)
			if err != nil {
				return err
			}

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Token revoked successfully\n")
			return nil
		},
	}

	cmd.AddCommand(listCmd, introspectCmd, revokeCmd, refreshCmd)
	return cmd
}
