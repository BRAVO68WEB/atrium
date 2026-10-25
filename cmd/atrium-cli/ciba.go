package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func cibaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ciba",
		Short: "CIBA request management commands",
	}

	pendingCmd := &cobra.Command{
		Use:   "pending",
		Short: "List pending CIBA requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/ciba/pending")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var requests []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&requests); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "AUTH REQ ID\tCLIENT ID\tBINDING MSG\tSTATUS\tEXPIRES\n")
			for _, r := range requests {
				authReqID := r["auth_req_id"].(string)
				if len(authReqID) > 20 {
					authReqID = authReqID[:20] + "..."
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					authReqID, r["client_id"], r["binding_message"], r["status"], r["expires_at"])
			}
			_ = w.Flush()
			return nil
		},
	}

	approveCmd := &cobra.Command{
		Use:   "approve [auth-req-id]",
		Short: "Approve a CIBA request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")

			url := fmt.Sprintf("%s/ciba/approve?auth_req_id=%s", serverURL, args[0])
			if userID != "" {
				url += "&user_id=" + userID
			}

			resp, err := apiPost(url, "", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			fmt.Printf("CIBA request approved: %s\n", result["status"])
			return nil
		},
	}

	approveCmd.Flags().StringP("user-id", "u", "", "User ID to associate with the approval")

	denyCmd := &cobra.Command{
		Use:   "deny [auth-req-id]",
		Short: "Deny a CIBA request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reason, _ := cmd.Flags().GetString("reason")

			url := fmt.Sprintf("%s/ciba/deny?auth_req_id=%s", serverURL, args[0])
			if reason != "" {
				url += "&reason=" + reason
			}

			resp, err := apiPost(url, "", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			fmt.Printf("CIBA request denied: %s\n", result["status"])
			return nil
		},
	}

	denyCmd.Flags().StringP("reason", "r", "", "Reason for denial")

	cmd.AddCommand(pendingCmd, approveCmd, denyCmd)
	return cmd
}
