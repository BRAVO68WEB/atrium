package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read the append-only audit log",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List audit events",
		RunE: func(cmd *cobra.Command, args []string) error {
			window, _ := cmd.Flags().GetString("window")
			action, _ := cmd.Flags().GetString("action")
			actorID, _ := cmd.Flags().GetString("actor-id")
			if window == "" {
				window = "720h"
			}
			path := serverURL + "/api/audit?window=" + window
			if action != "" {
				path += "&action=" + action
			}
			if actorID != "" {
				path += "&actor_id=" + actorID
			}
			resp, err := apiGet(path)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var rows []map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("audit list failed: %v", rows)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "TIME\tACTOR\tACTION\tTARGET")
			for _, row := range rows {
				_, _ = fmt.Fprintf(w, "%v\t%v\t%v\t%v\n", row["created_at"], row["actor_id"], row["action"], row["target_id"])
			}
			return w.Flush()
		},
	}
	list.Flags().String("window", "720h", "How far back to read, as a Go duration")
	list.Flags().String("action", "", "Filter by action, for example client.create")
	list.Flags().String("actor-id", "", "Filter by actor id")
	cmd.AddCommand(list)
	return cmd
}
