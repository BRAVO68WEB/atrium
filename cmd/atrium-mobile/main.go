package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/bravo68web/atrium/internal/version"
)

var (
	serverURL string
	interval  int
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "atrium-mobile",
		Short:   "OAuth Mobile Polling CLI",
		Long:    "A CLI tool for polling and managing CIBA/PAR authorization requests",
		Version: version.Line(),
	}
	rootCmd.SetVersionTemplate("{{.Name}} {{.Version}}\n")

	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "OAuth server URL")
	rootCmd.PersistentFlags().StringVar(&mgmtClientID, "client-id", "", "Management client ID")
	rootCmd.PersistentFlags().StringVar(&mgmtClientSecret, "client-secret", "", "Management client secret")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "config.yaml", "Config file used for management credentials")
	rootCmd.PersistentFlags().IntVar(&interval, "interval", 5, "Polling interval in seconds")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		syncMgmt()
		mgmt.ServerExplicit = cmd.Flags().Changed("server")
		_ = mgmt.Resolve(mgmt.ServerExplicit)
		if mgmt.ServerURL != "" {
			serverURL = mgmt.ServerURL
		}
	}

	rootCmd.AddCommand(
		pollCmd(),
		listCmd(),
		approveCmd(),
		denyCmd(),
		statusCmd(),
	)

	return rootCmd
}

func pollCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "poll",
		Short: "Start polling for authorization requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Starting polling server at %s (interval: %ds)\n", serverURL, interval)
			fmt.Println("Press Ctrl+C to stop")

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)

			ticker := time.NewTicker(time.Duration(interval) * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-sigChan:
					fmt.Println("\nStopping poll...")
					return nil
				case <-ticker.C:
					if err := pollForRequests(); err != nil {
						fmt.Printf("Error polling: %v\n", err)
					}
				}
			}
		},
	}
}

func pollForRequests() error {
	resp, err := apiGet(serverURL + "/ciba/pending")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var requests []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&requests); err != nil {
		return err
	}

	if len(requests) == 0 {
		return nil
	}

	fmt.Printf("\n=== %d Pending Request(s) Found ===\n", len(requests))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "ID\tCLIENT\tMESSAGE\tSTATUS\tEXPIRES\n")
	for _, r := range requests {
		id := r["auth_req_id"].(string)
		if len(id) > 20 {
			id = id[:20] + "..."
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			id,
			r["client_id"],
			r["binding_message"],
			r["status"],
			r["expires_at"])
	}
	_ = w.Flush()

	fmt.Println("\nUse 'atrium-mobile approve <id>' or 'atrium-mobile deny <id>' to respond")
	return nil
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List pending authorization requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/ciba/pending")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var requests []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&requests); err != nil {
				return err
			}

			if len(requests) == 0 {
				fmt.Println("No pending requests")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tCLIENT\tMESSAGE\tSTATUS\tEXPIRES\n")
			for _, r := range requests {
				id := r["auth_req_id"].(string)
				if len(id) > 20 {
					id = id[:20] + "..."
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					id,
					r["client_id"],
					r["binding_message"],
					r["status"],
					r["expires_at"])
			}
			_ = w.Flush()
			return nil
		},
	}
}

func approveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve [auth-req-id]",
		Short: "Approve an authorization request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")

			url := fmt.Sprintf("%s/ciba/approve?auth_req_id=%s", serverURL, args[0])
			if userID != "" {
				url += "&user_id=" + userID
			}

			resp, err := apiPost(url, "application/json", nil)
			if err != nil {
				return fmt.Errorf("failed to approve request: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if errMsg, ok := result["error"]; ok {
				return fmt.Errorf("error: %s - %s", errMsg, result["error_description"])
			}

			fmt.Printf("Request approved successfully\n")
			return nil
		},
	}

	cmd.Flags().StringP("user-id", "u", "", "User ID to associate with the approval")
	return cmd
}

func denyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deny [auth-req-id]",
		Short: "Deny an authorization request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reason, _ := cmd.Flags().GetString("reason")

			url := fmt.Sprintf("%s/ciba/deny?auth_req_id=%s", serverURL, args[0])
			if reason != "" {
				url += "&reason=" + reason
			}

			resp, err := apiPost(url, "application/json", nil)
			if err != nil {
				return fmt.Errorf("failed to deny request: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if errMsg, ok := result["error"]; ok {
				return fmt.Errorf("error: %s - %s", errMsg, result["error_description"])
			}

			fmt.Printf("Request denied successfully\n")
			return nil
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check server status",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/health")
			if err != nil {
				return fmt.Errorf("server is not reachable: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			fmt.Printf("Server: %s\n", serverURL)
			fmt.Printf("Status: %s\n", result["status"])
			fmt.Printf("Time: %s\n", result["time"])
			return nil
		},
	}
}
