package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func backupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Download a backup of users, clients, and signing keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/backup")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			raw, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("backup failed: %s", resp.Status)
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, raw, "", "  "); err != nil {
				return fmt.Errorf("backup response: %w", err)
			}
			pretty.WriteByte('\n')
			output, _ := cmd.Flags().GetString("output")
			if output == "" {
				fmt.Print(pretty.String())
				return nil
			}
			return os.WriteFile(output, pretty.Bytes(), 0o600)
		},
	}
	cmd.Flags().StringP("output", "o", "", "Write the backup to this file instead of stdout")
	return cmd
}

func restoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore [file]",
		Short: "Restore a backup onto this server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			endpoint := serverURL + "/api/restore"
			query := ""
			if dry, _ := cmd.Flags().GetBool("dry-run"); dry {
				query = "dry_run=true"
			}
			if force, _ := cmd.Flags().GetBool("force"); force {
				if query != "" {
					query += "&"
				}
				query += "force=true"
			}
			if query != "" {
				endpoint += "?" + query
			}
			resp, err := apiPost(endpoint, "application/json", bytes.NewReader(raw))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if resp.StatusCode == http.StatusConflict {
				return fmt.Errorf("restore refused: the server already has users or clients")
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("restore failed: %s", resp.Status)
			}
			var result struct {
				DryRun        bool     `json:"dry_run"`
				Users         int      `json:"users"`
				Clients       int      `json:"clients"`
				Organizations int      `json:"organizations"`
				Consents      int      `json:"consents"`
				SigningKeys   int      `json:"signing_keys"`
				Warnings      []string `json:"warnings"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return fmt.Errorf("restore response: %w", err)
			}
			fmt.Printf("users: %d\nclients: %d\norganizations: %d\nconsents: %d\nsigning_keys: %d\n",
				result.Users, result.Clients, result.Organizations, result.Consents, result.SigningKeys)
			for _, warning := range result.Warnings {
				fmt.Printf("warning: %s\n", warning)
			}
			if result.DryRun {
				fmt.Println("dry run: nothing was written")
			}
			return nil
		},
	}
	cmd.Flags().Bool("dry-run", false, "Validate the file and print counts without writing")
	cmd.Flags().Bool("force", false, "Restore onto a server that already has users or clients")
	return cmd
}
