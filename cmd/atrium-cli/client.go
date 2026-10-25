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

func clientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Client management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all clients",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/clients")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var clients []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tNAME\tGRANT TYPES\tAUTH METHOD\n")
			for _, c := range clients {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%v\t%s\n",
					c["id"], c["name"], c["grant_types"], c["token_endpoint_auth_method"])
			}
			_ = w.Flush()
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new client",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			redirectURIs, _ := cmd.Flags().GetStringSlice("redirect-uri")
			grantTypes, _ := cmd.Flags().GetStringSlice("grant-type")
			scopes, _ := cmd.Flags().GetStringSlice("scope")

			if name == "" {
				return fmt.Errorf("name is required")
			}

			dcrEnabled, _ := cmd.Flags().GetBool("dcr-enabled")
			cimdEnabled, _ := cmd.Flags().GetBool("cimd-enabled")
			body := map[string]interface{}{
				"name":          name,
				"redirect_uris": redirectURIs,
				"grant_types":   grantTypes,
				"scopes":        scopes,
				"dcr_enabled":   dcrEnabled,
				"cimd_enabled":  cimdEnabled,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/clients", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusCreated {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to create client: %v", errMsg)
			}

			fmt.Printf("Client created successfully!\n")
			fmt.Printf("Client ID: %s\n", result["id"])
			fmt.Printf("Client Secret: %s\n", result["secret"])
			return nil
		},
	}

	createCmd.Flags().StringP("name", "n", "", "Client name")
	createCmd.Flags().StringSliceP("redirect-uri", "r", []string{}, "Redirect URIs")
	createCmd.Flags().StringSliceP("grant-type", "g", []string{"authorization_code"}, "Grant types")
	createCmd.Flags().StringSliceP("scope", "s", []string{"openid"}, "Scopes")
	createCmd.Flags().Bool("dcr-enabled", false, "Allow this app when tenant dynamic registration is on")
	createCmd.Flags().Bool("cimd-enabled", false, "Allow this app when tenant client metadata documents are on")

	updateCmd := &cobra.Command{
		Use:   "update [client-id]",
		Short: "Update per-app DCR, CIMD, or forced DPoP flags",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/clients/" + args[0])
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var client map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to load client: %v", client["error_description"])
			}
			if cmd.Flags().Changed("dcr-enabled") {
				v, _ := cmd.Flags().GetBool("dcr-enabled")
				client["dcr_enabled"] = v
			}
			if cmd.Flags().Changed("cimd-enabled") {
				v, _ := cmd.Flags().GetBool("cimd-enabled")
				client["cimd_enabled"] = v
			}
			if cmd.Flags().Changed("dpop") {
				v, _ := cmd.Flags().GetBool("dpop")
				client["dpop_bound_access_tokens"] = v
			}
			delete(client, "secret")
			body, _ := json.Marshal(client)
			put, err := apiPut(serverURL+"/api/clients/"+args[0], "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			defer func() { _ = put.Body.Close() }()
			if put.StatusCode != http.StatusOK {
				var result map[string]any
				_ = json.NewDecoder(put.Body).Decode(&result)
				return fmt.Errorf("failed to update client: %v", result["error_description"])
			}
			fmt.Printf("Client %s updated\n", args[0])
			return nil
		},
	}
	updateCmd.Flags().Bool("dcr-enabled", false, "Allow this app when tenant dynamic registration is on")
	updateCmd.Flags().Bool("cimd-enabled", false, "Allow this app when tenant client metadata documents are on")
	updateCmd.Flags().Bool("dpop", false, "Require DPoP for every token from this app")

	getCmd := &cobra.Command{
		Use:   "get [client-id]",
		Short: "Get client details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/clients/" + args[0])
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

	deleteCmd := &cobra.Command{
		Use:   "delete [client-id]",
		Short: "Delete a client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest("DELETE", serverURL+"/api/clients/"+args[0], nil)
			if err != nil {
				return err
			}

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Client %s deleted successfully\n", args[0])
			return nil
		},
	}

	masterCmd := &cobra.Command{
		Use:   "master",
		Short: "Create a master client with all permissions",
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]interface{}{
				"name": "Master Client",
				"redirect_uris": []string{
					"https://localhost/Callback",
					"http://localhost:3000/callback",
					"http://localhost:8080/callback",
				},
				"grant_types": []string{
					"authorization_code",
					"client_credentials",
					"refresh_token",
					"password",
					"urn:ietf:params:oauth:grant-type:device_code",
					"urn:openid:params:grant-type:ciba",
					"urn:ietf:params:oauth:grant-type:token-exchange",
				},
				"scopes": []string{
					"openid", "profile", "email", "address", "phone", "offline_access",
					"read", "write", "admin",
				},
				"token_endpoint_auth_method":            "client_secret_basic",
				"dpop_bound_access_tokens":              false,
				"require_pushed_authorization_requests": false,
				"backchannel_token_delivery_mode":       "poll",
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/clients", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusCreated {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to create master client: %v", errMsg)
			}

			fmt.Println("╔══════════════════════════════════════════════════════════════╗")
			fmt.Println("║                    Master Client Created                     ║")
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Client ID:     %-44s ║\n", result["id"])
			fmt.Printf("║  Client Secret: %-44s ║\n", result["secret"])
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Println("║  Grant Types:                                               ║")
			fmt.Println("║    • authorization_code                                      ║")
			fmt.Println("║    • client_credentials                                      ║")
			fmt.Println("║    • refresh_token                                           ║")
			fmt.Println("║    • password                                                ║")
			fmt.Println("║    • device_code (RFC 8628)                                  ║")
			fmt.Println("║    • ciba                                                    ║")
			fmt.Println("║    • token_exchange (RFC 8693)                               ║")
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Println("║  Scopes: openid profile email address phone offline_access   ║")
			fmt.Println("║          read write admin                                    ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════╝")
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, getCmd, updateCmd, deleteCmd, masterCmd)
	return cmd
}
