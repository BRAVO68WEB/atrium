package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func analyticsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analytics",
		Short: "Login behavior analytics",
	}
	logins := &cobra.Command{
		Use:   "logins",
		Short: "Summarize login attempts by IP and day",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			window, _ := cmd.Flags().GetString("window")
			if window == "" {
				window = "720h"
			}
			path := serverURL + "/api/analytics/logins?window=" + window
			if userID != "" {
				path = serverURL + "/api/users/" + userID + "/login-analytics?window=" + window
			}
			resp, err := apiGet(path)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var report map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("analytics: %v", report["error_description"])
			}
			fmt.Printf("Window: %v\nAttempts: %v  Successes: %v  Failures: %v  Failure rate: %v\nUnique IPs: %v  New IPs: %v\n",
				report["window"], report["attempts"], report["successes"], report["failures"], report["failure_rate"], report["unique_ips"], report["new_ips"])
			rows, _ := report["by_ip"].([]any)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "\nIP\tATTEMPTS\tSUCCESS\tFAIL\tNEW\tLAST SEEN\n")
			for _, row := range rows {
				item, _ := row.(map[string]any)
				_, _ = fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\t%v\n", item["ip"], item["attempts"], item["successes"], item["failures"], item["new"], item["last_seen"])
			}
			return w.Flush()
		},
	}
	logins.Flags().String("user-id", "", "Limit the report to one user")
	logins.Flags().String("window", "720h", "Look-back duration, for example 24h or 168h")
	cmd.AddCommand(logins)
	return cmd
}
