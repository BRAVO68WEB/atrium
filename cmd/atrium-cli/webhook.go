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

func webhookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "Webhook subscriptions",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List webhooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/webhooks")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var hooks []map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&hooks); err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tENABLED\tEVENTS\tURL\n")
			for _, hook := range hooks {
				_, _ = fmt.Fprintf(w, "%s\t%v\t%v\t%s\n", hook["id"], hook["enabled"], hook["events"], hook["url"])
			}
			return w.Flush()
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a webhook",
		RunE: func(cmd *cobra.Command, args []string) error {
			rawURL, _ := cmd.Flags().GetString("url")
			events, _ := cmd.Flags().GetStringSlice("event")
			secret, _ := cmd.Flags().GetString("secret")
			description, _ := cmd.Flags().GetString("description")
			if rawURL == "" || len(events) == 0 {
				return fmt.Errorf("--url and at least one --event are required")
			}
			body, _ := json.Marshal(map[string]any{
				"url": rawURL, "events": events, "secret": secret, "description": description,
			})
			resp, err := apiPost(serverURL+"/api/webhooks", "application/json", bytes.NewBuffer(body))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var result map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("create webhook: %v", result["error_description"])
			}
			fmt.Printf("Webhook ID: %s\n", result["id"])
			fmt.Printf("Secret: %s\n", result["secret"])
			fmt.Printf("Events: %s\n", strings.Join(events, ", "))
			return nil
		},
	}
	createCmd.Flags().String("url", "", "Receiver URL")
	createCmd.Flags().StringSlice("event", nil, "Event name (repeat for more). Use * for every event")
	createCmd.Flags().String("secret", "", "HMAC secret (generated when omitted)")
	createCmd.Flags().String("description", "", "Description")

	deleteCmd := &cobra.Command{
		Use:   "delete [id]",
		Short: "Delete a webhook",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest(http.MethodDelete, serverURL+"/api/webhooks/"+args[0], nil)
			if err != nil {
				return err
			}
			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("delete webhook: %s", resp.Status)
			}
			fmt.Println("Webhook deleted")
			return nil
		},
	}

	testCmd := &cobra.Command{
		Use:   "test [id]",
		Short: "Send a webhook.test delivery",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiPost(serverURL+"/api/webhooks/"+args[0]+"/test", "", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("test webhook: %s", resp.Status)
			}
			fmt.Println("Test delivery accepted")
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, deleteCmd, testCmd)
	return cmd
}
