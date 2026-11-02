package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func userCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "User management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all users",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/users")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var users []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tUSERNAME\tEMAIL\n")
			for _, u := range users {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
					u["id"], u["username"], u["email"])
			}
			_ = w.Flush()
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new user",
		RunE: func(cmd *cobra.Command, args []string) error {
			username, _ := cmd.Flags().GetString("username")
			password, _ := cmd.Flags().GetString("password")
			email, _ := cmd.Flags().GetString("email")

			if username == "" || password == "" {
				return fmt.Errorf("username and password are required")
			}

			body := map[string]interface{}{
				"username": username,
				"password": password,
				"email":    email,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/users", "application/json", bytes.NewBuffer(jsonBody))
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
				return fmt.Errorf("failed to create user: %v", errMsg)
			}

			fmt.Printf("User created successfully!\n")
			fmt.Printf("User ID: %s\n", result["id"])
			fmt.Printf("Username: %s\n", result["username"])
			return nil
		},
	}

	createCmd.Flags().StringP("username", "u", "", "Username")
	createCmd.Flags().StringP("password", "p", "", "Password")
	createCmd.Flags().StringP("email", "e", "", "Email")

	getCmd := &cobra.Command{
		Use:   "get [user-id]",
		Short: "Get user details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/users/" + args[0])
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

	passwordCmd := &cobra.Command{
		Use:   "password [user-id]",
		Short: "Set a user's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, _ := cmd.Flags().GetString("password")
			if password == "" {
				return fmt.Errorf("password is required")
			}
			body, _ := json.Marshal(map[string]string{"password": password})
			resp, err := apiPost(serverURL+"/api/users/"+args[0]+"/password", "application/json", bytes.NewBuffer(body))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("set password failed: %s", resp.Status)
			}
			fmt.Println("Password updated")
			return nil
		},
	}
	passwordCmd.Flags().StringP("password", "p", "", "New password")

	disableCmd := &cobra.Command{
		Use:   "disable [user-id]",
		Short: "Disable a user",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return patchUserDisabled(args[0], true) },
	}
	enableCmd := &cobra.Command{
		Use:   "enable [user-id]",
		Short: "Enable a user",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return patchUserDisabled(args[0], false) },
	}

	importCmd := &cobra.Command{
		Use:   "import [file]",
		Short: "Import users from a JSON file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return importUsers(cmd, args[0])
		},
	}
	importCmd.Flags().String("mode", "", "create or upsert; overrides the file")
	importCmd.Flags().Bool("dry-run", false, "Check the file and write nothing")
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export users as an import document",
		RunE: func(cmd *cobra.Command, args []string) error {
			return exportUsers(cmd)
		},
	}
	exportCmd.Flags().StringP("output", "o", "", "Write the document to this file")
	exportCmd.Flags().Bool("include-secrets", false, "Include password hashes and TOTP secrets")

	roleAssign := &cobra.Command{
		Use:   "role [user-id]",
		Short: "Grant or remove a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			roleID, _ := cmd.Flags().GetString("role")
			orgID, _ := cmd.Flags().GetString("org-id")
			remove, _ := cmd.Flags().GetBool("remove")
			if roleID == "" {
				return fmt.Errorf("role is required")
			}
			body, _ := json.Marshal(map[string]string{"role_id": roleID, "org_id": orgID})
			endpoint := serverURL + "/api/users/" + args[0] + "/roles"
			var resp *http.Response
			var err error
			if remove {
				resp, err = apiDelete(endpoint, "application/json", bytes.NewReader(body))
			} else {
				resp, err = apiPost(endpoint, "application/json", bytes.NewReader(body))
			}
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
				var result map[string]any
				_ = json.NewDecoder(resp.Body).Decode(&result)
				return fmt.Errorf("failed to update role: %v", result["error_description"])
			}
			if remove {
				fmt.Println("Role removed")
				return nil
			}
			fmt.Println("Role granted")
			return nil
		},
	}
	roleAssign.Flags().String("role", "", "Role id")
	roleAssign.Flags().String("org-id", "", "Organization id or slug. Empty grants the role on every token.")
	roleAssign.Flags().Bool("remove", false, "Remove the grant")

	scopeAssign := &cobra.Command{
		Use:   "scope [user-id]",
		Short: "Grant or remove one resource scope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resource, _ := cmd.Flags().GetString("resource")
			scope, _ := cmd.Flags().GetString("scope")
			orgID, _ := cmd.Flags().GetString("org-id")
			remove, _ := cmd.Flags().GetBool("remove")
			if resource == "" || scope == "" {
				return fmt.Errorf("resource and scope are required")
			}
			body, _ := json.Marshal(map[string]string{"resource": resource, "scope": scope, "org_id": orgID})
			endpoint := serverURL + "/api/users/" + args[0] + "/scopes"
			var resp *http.Response
			var err error
			if remove {
				resp, err = apiDelete(endpoint, "application/json", bytes.NewReader(body))
			} else {
				resp, err = apiPost(endpoint, "application/json", bytes.NewReader(body))
			}
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
				var result map[string]any
				_ = json.NewDecoder(resp.Body).Decode(&result)
				return fmt.Errorf("failed to update scope: %v", result["error_description"])
			}
			if remove {
				fmt.Println("Scope removed")
				return nil
			}
			fmt.Println("Scope granted")
			return nil
		},
	}
	scopeAssign.Flags().String("resource", "", "Resource URI")
	scopeAssign.Flags().String("scope", "", "Scope name")
	scopeAssign.Flags().String("org-id", "", "Organization id or slug. Empty grants the scope on every token.")
	scopeAssign.Flags().Bool("remove", false, "Remove the grant")

	cmd.AddCommand(listCmd, createCmd, getCmd, passwordCmd, disableCmd, enableCmd, importCmd, exportCmd, roleAssign, scopeAssign)
	return cmd
}

func patchUserDisabled(userID string, disabled bool) error {
	body, _ := json.Marshal(map[string]bool{"disabled": disabled})
	req, err := http.NewRequest(http.MethodPatch, serverURL+"/api/users/"+userID, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := withManagement(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update user failed: %s", resp.Status)
	}
	if disabled {
		fmt.Println("User disabled")
	} else {
		fmt.Println("User enabled")
	}
	return nil
}

func importUsers(cmd *cobra.Command, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("import file: %w", err)
	}
	if mode, _ := cmd.Flags().GetString("mode"); mode != "" {
		doc["mode"] = mode
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	endpoint := serverURL + "/api/users/import"
	if dry, _ := cmd.Flags().GetBool("dry-run"); dry {
		endpoint += "?dry_run=true"
	}
	resp, err := apiPost(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var result importResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("import response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("import failed: %s", resp.Status)
	}
	fmt.Printf("created: %d\nupdated: %d\nerrors: %d\n", result.Created, result.Updated, len(result.Errors))
	for _, row := range result.Errors {
		fmt.Printf("%d %s: %s\n", row.Index, row.Username, row.Error)
	}
	if len(result.Errors) > 0 {
		return fmt.Errorf("import failed for %d users", len(result.Errors))
	}
	return nil
}

func exportUsers(cmd *cobra.Command) error {
	endpoint := serverURL + "/api/users/export"
	if secrets, _ := cmd.Flags().GetBool("include-secrets"); secrets {
		endpoint += "?include_secrets=true"
	}
	resp, err := apiGet(endpoint)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("export failed: %s", resp.Status)
	}
	output, _ := cmd.Flags().GetString("output")
	if output == "" {
		fmt.Println(string(raw))
		return nil
	}
	return os.WriteFile(output, raw, 0o600)
}

type importResult struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Errors  []struct {
		Index    int    `json:"index"`
		Username string `json:"username"`
		Error    string `json:"error"`
	} `json:"errors"`
}
