package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"

	"github.com/bravo68web/oauth-impl/internal/oobcode"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

var (
	serverURL string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "oauth-cli",
		Short: "OAuth Implementation Server Management CLI",
		Long:  "A CLI tool for managing the OAuth Implementation Server",
	}

	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "OAuth server URL")
	rootCmd.PersistentFlags().StringVar(&mgmtClientID, "client-id", "", "Management client ID")
	rootCmd.PersistentFlags().StringVar(&mgmtClientSecret, "client-secret", "", "Management client secret")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "config.yaml", "Config file used for management credentials")

	rootCmd.AddCommand(
		initCmd(),
		serverCmd(),
		clientCmd(),
		userCmd(),
		tokenCmd(),
		cibaCmd(),
		flowCmd(),
		mfaCmd(),
		scopeCmd(),
		resourceCmd(),
		consentCmd(),
		webhookCmd(),
		analyticsCmd(),
		auditCmd(),
		keysCmd(),
		orgCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Server management commands",
	}

	statusCmd := &cobra.Command{
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

			fmt.Printf("Server Status: %s\n", result["status"])
			fmt.Printf("Time: %s\n", result["time"])
			return nil
		},
	}

	discoveryCmd := &cobra.Command{
		Use:   "discovery",
		Short: "Show OIDC discovery information",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/.well-known/openid-configuration")
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

	cmd.AddCommand(statusCmd, discoveryCmd)
	return cmd
}

func flowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flow",
		Short: "OAuth flow testing commands",
	}

	clientCredsCmd := &cobra.Command{
		Use:   "client-credentials",
		Short: "Test client credentials flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			clientSecret, _ := cmd.Flags().GetString("client-secret")
			scope, _ := cmd.Flags().GetString("scope")

			if clientID == "" || clientSecret == "" {
				return fmt.Errorf("client-id and client-secret are required")
			}

			body := fmt.Sprintf("grant_type=client_credentials&scope=%s", scope)
			req, err := http.NewRequest("POST", serverURL+"/oauth/token", bytes.NewBufferString(body))
			if err != nil {
				return err
			}
			req.SetBasicAuth(clientID, clientSecret)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if errMsg, ok := result["error"]; ok {
				fmt.Printf("Error: %s - %s\n", errMsg, result["error_description"])
				return nil
			}

			fmt.Printf("Access Token: %s\n", result["access_token"])
			fmt.Printf("Token Type: %s\n", result["token_type"])
			fmt.Printf("Expires In: %v\n", result["expires_in"])
			fmt.Printf("Scope: %s\n", result["scope"])
			return nil
		},
	}

	clientCredsCmd.Flags().String("client-id", "", "Client ID")
	clientCredsCmd.Flags().String("client-secret", "", "Client Secret")
	clientCredsCmd.Flags().String("scope", "openid", "Scopes")

	deviceCmd := &cobra.Command{
		Use:   "device",
		Short: "Test device authorization flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			clientSecret, _ := cmd.Flags().GetString("client-secret")
			scope, _ := cmd.Flags().GetString("scope")

			if clientID == "" || clientSecret == "" {
				return fmt.Errorf("client-id and client-secret are required")
			}

			body := fmt.Sprintf("scope=%s", scope)
			req, err := http.NewRequest("POST", serverURL+"/oauth/device", bytes.NewBufferString(body))
			if err != nil {
				return err
			}
			req.SetBasicAuth(clientID, clientSecret)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			fmt.Printf("Device Code: %s\n", result["device_code"])
			fmt.Printf("User Code: %s\n", result["user_code"])
			fmt.Printf("Verification URI: %s\n", result["verification_uri"])
			fmt.Printf("Expires In: %v seconds\n", result["expires_in"])
			return nil
		},
	}

	deviceCmd.Flags().String("client-id", "", "Client ID")
	deviceCmd.Flags().String("client-secret", "", "Client Secret")
	deviceCmd.Flags().String("scope", "openid", "Scopes")

	pasteCmd := &cobra.Command{
		Use:   "paste",
		Short: "Print an authorize URL and exchange a pasted code",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			clientSecret, _ := cmd.Flags().GetString("client-secret")
			scope, _ := cmd.Flags().GetString("scope")
			redirectURI, _ := cmd.Flags().GetString("redirect-uri")
			combined, _ := cmd.Flags().GetBool("combined")
			if clientID == "" {
				return fmt.Errorf("client-id is required")
			}
			if !combined {
				if parsed, err := url.Parse(redirectURI); err == nil && parsed.Path == "/oauth/oob" {
					combined = true
				}
			}
			verifier, err := crypto.GenerateCodeVerifier()
			if err != nil {
				return err
			}
			state, err := crypto.GenerateToken()
			if err != nil {
				return err
			}
			query := url.Values{}
			query.Set("client_id", clientID)
			query.Set("response_type", "code")
			query.Set("redirect_uri", redirectURI)
			query.Set("scope", scope)
			query.Set("state", state)
			query.Set("code_challenge", crypto.GenerateCodeChallenge(verifier))
			query.Set("code_challenge_method", "S256")
			fmt.Printf("Open this URL and sign in:\n%s\n\n", serverURL+"/oauth/authorize?"+query.Encode())
			fmt.Fprint(os.Stderr, "Paste the authorization code: ")
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return err
			}
			code, err := oobcode.FromPaste(line, state, combined)
			if err != nil {
				return err
			}
			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("redirect_uri", redirectURI)
			form.Set("code_verifier", verifier)
			if clientSecret == "" {
				form.Set("client_id", clientID)
			}
			req, err := http.NewRequest(http.MethodPost, serverURL+"/oauth/token", strings.NewReader(form.Encode()))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if clientSecret != "" {
				req.SetBasicAuth(clientID, clientSecret)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var result map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}
			if errMsg, ok := result["error"]; ok {
				return fmt.Errorf("%s: %v", errMsg, result["error_description"])
			}
			fmt.Printf("Access Token: %s\n", result["access_token"])
			fmt.Printf("Token Type: %s\n", result["token_type"])
			fmt.Printf("Expires In: %v\n", result["expires_in"])
			if result["refresh_token"] != nil {
				fmt.Printf("Refresh Token: %s\n", result["refresh_token"])
			}
			fmt.Printf("Scope: %s\n", result["scope"])
			return nil
		},
	}
	pasteCmd.Flags().String("client-id", "", "Client ID")
	pasteCmd.Flags().String("client-secret", "", "Client secret, omit for a public client")
	pasteCmd.Flags().String("scope", "openid", "Scopes")
	pasteCmd.Flags().String("redirect-uri", "urn:ietf:wg:oauth:2.0:oob", "Redirect URI registered on the client")
	pasteCmd.Flags().Bool("combined", false, "Unwrap a draft-richer-oauth-oob-authcode combined code")

	cmd.AddCommand(clientCredsCmd, deviceCmd, pasteCmd)
	return cmd
}

func mfaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mfa",
		Short: "MFA management commands",
	}

	enableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable MFA for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			showSecret, _ := cmd.Flags().GetBool("show-secret")

			if userID == "" {
				return fmt.Errorf("user-id is required")
			}

			resp, err := apiPostForm(serverURL+"/api/users/"+userID+"/mfa/enable", nil)
			if err != nil {
				return fmt.Errorf("failed to enable MFA: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if showSecret {
				fmt.Printf("MFA Secret: %s\n", result["secret"])
				fmt.Printf("Add this to your authenticator manually, then run:\n")
				fmt.Printf("  oauth-cli mfa verify --user-id %s\n", userID)
			} else {
				qrURI, _ := result["qr_uri"].(string)
				qrBase64, _ := result["qr_base64"].(string)
				secret, _ := result["secret"].(string)

				fmt.Println("┌─────────────────────────────────────────────┐")
				fmt.Println("│  Scan this QR code with your authenticator  │")
				fmt.Println("└─────────────────────────────────────────────┘")
				fmt.Println()

				if qrBase64 != "" {
					qrBytes, err := base64.StdEncoding.DecodeString(qrBase64)
					if err == nil {
						qr, err := qrcode.New(qrURI, qrcode.Medium)
						if err == nil {
							_ = qrBytes
							fmt.Println(qr.ToSmallString(false))
						}
					}
				}

				fmt.Println()
				fmt.Printf("Secret: %s\n", secret)
				fmt.Printf("Issuer: OAuthImplServer\n")
				fmt.Println()
				fmt.Printf("Enter code to verify: ")

				var code string
				_, _ = fmt.Scanln(&code)

				if code != "" {
					verifyResp, err := apiPost(
						serverURL+"/api/users/"+userID+"/mfa/verify",
						"application/json",
						bytes.NewBufferString(fmt.Sprintf(`{"code":"%s"}`, code)),
					)
					if err != nil {
						return fmt.Errorf("failed to verify MFA: %w", err)
					}
					defer func() { _ = verifyResp.Body.Close() }()

					var verifyResult map[string]interface{}
					if err := json.NewDecoder(verifyResp.Body).Decode(&verifyResult); err != nil {
						return fmt.Errorf("failed to decode response: %w", err)
					}

					if verifyResp.StatusCode == http.StatusOK {
						fmt.Println("✅ MFA verified and enabled successfully")
					} else {
						errMsg := verifyResult["error_description"]
						if errMsg == nil {
							errMsg = verifyResult["error"]
						}
						fmt.Printf("❌ MFA verification failed: %v\n", errMsg)
					}
				}
			}

			return nil
		},
	}

	enableCmd.Flags().String("user-id", "", "User ID")
	enableCmd.Flags().Bool("show-secret", false, "Show secret text instead of QR code")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify MFA code for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			code, _ := cmd.Flags().GetString("code")

			if userID == "" || code == "" {
				return fmt.Errorf("user-id and code are required")
			}

			data := map[string]string{
				"code": code,
			}

			jsonData, _ := json.Marshal(data)
			resp, err := apiPost(serverURL+"/api/users/"+userID+"/mfa/verify",
				"application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				return fmt.Errorf("failed to verify MFA: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode == http.StatusOK {
				fmt.Println("✅ MFA verified and enabled successfully")
			} else {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("MFA verification failed: %v", errMsg)
			}

			return nil
		},
	}

	verifyCmd.Flags().String("user-id", "", "User ID")
	verifyCmd.Flags().String("code", "", "TOTP code")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check MFA status for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			if userID == "" {
				return fmt.Errorf("user-id is required")
			}

			resp, err := apiGet(serverURL + "/api/users/" + userID + "/mfa/status")
			if err != nil {
				return fmt.Errorf("failed to check MFA status: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusOK {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to check MFA status: %v", errMsg)
			}

			fmt.Printf("User ID: %s\n", result["user_id"])
			fmt.Printf("MFA Enabled: %v\n", result["mfa_enabled"])
			return nil
		},
	}

	statusCmd.Flags().String("user-id", "", "User ID")

	cmd.AddCommand(enableCmd, verifyCmd, statusCmd)
	return cmd
}

func scopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Scope management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all scopes",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/scopes")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var scopes []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&scopes); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "NAME\tDESCRIPTION\tRESOURCE SERVER\tDEFAULT\n")
			for _, s := range scopes {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%v\n",
					s["name"], s["description"], s["resource_server"], s["is_default"])
			}
			_ = w.Flush()
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			description, _ := cmd.Flags().GetString("description")
			resourceServer, _ := cmd.Flags().GetString("resource-server")
			isDefault, _ := cmd.Flags().GetBool("default")

			if name == "" {
				return fmt.Errorf("name is required")
			}

			body := map[string]interface{}{
				"name":            name,
				"description":     description,
				"resource_server": resourceServer,
				"is_default":      isDefault,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/scopes", "application/json", bytes.NewBuffer(jsonBody))
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
				return fmt.Errorf("failed to create scope: %v", errMsg)
			}

			fmt.Printf("Scope created: %s\n", result["name"])
			return nil
		},
	}

	createCmd.Flags().StringP("name", "n", "", "Scope name")
	createCmd.Flags().StringP("description", "d", "", "Scope description")
	createCmd.Flags().String("resource-server", "", "Resource server URI")
	createCmd.Flags().Bool("default", false, "Is default scope")

	deleteCmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a scope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest("DELETE", serverURL+"/api/scopes/"+args[0], nil)
			if err != nil {
				return err
			}

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Scope deleted: %s\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, deleteCmd)
	return cmd
}

func resourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resource",
		Short: "Resource server management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all resource servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/resources")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var resources []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&resources); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "URI\tNAME\tDESCRIPTION\tSCOPES\n")
			for _, r := range resources {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%v\n",
					r["uri"], r["name"], r["description"], r["scopes"])
			}
			_ = w.Flush()
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Register a resource server",
		RunE: func(cmd *cobra.Command, args []string) error {
			uri, _ := cmd.Flags().GetString("uri")
			name, _ := cmd.Flags().GetString("name")
			description, _ := cmd.Flags().GetString("description")
			scopes, _ := cmd.Flags().GetStringSlice("scopes")

			if uri == "" || name == "" {
				return fmt.Errorf("uri and name are required")
			}

			body := map[string]interface{}{
				"uri":         uri,
				"name":        name,
				"description": description,
				"scopes":      scopes,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/resources", "application/json", bytes.NewBuffer(jsonBody))
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
				return fmt.Errorf("failed to create resource: %v", errMsg)
			}

			fmt.Printf("Resource registered: %s\n", result["uri"])
			return nil
		},
	}

	createCmd.Flags().StringP("uri", "u", "", "Resource URI (e.g., https://api.example.com)")
	createCmd.Flags().StringP("name", "n", "", "Resource name")
	createCmd.Flags().StringP("description", "d", "", "Resource description")
	createCmd.Flags().StringSliceP("scopes", "s", []string{}, "Allowed scopes")

	deleteCmd := &cobra.Command{
		Use:   "delete [uri]",
		Short: "Delete a resource server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest("DELETE", serverURL+"/api/resources/"+args[0], nil)
			if err != nil {
				return err
			}

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Resource deleted: %s\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, deleteCmd)
	return cmd
}

func consentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "consent",
		Short: "Consent management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List consents for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			if userID == "" {
				return fmt.Errorf("user-id is required")
			}

			resp, err := apiGet(serverURL + "/api/consents?user_id=" + userID)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var consents []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&consents); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "CLIENT ID\tSCOPES\tGRANTED AT\n")
			for _, c := range consents {
				_, _ = fmt.Fprintf(w, "%s\t%v\t%s\n",
					c["client_id"], c["scopes"], c["granted_at"])
			}
			_ = w.Flush()
			return nil
		},
	}

	listCmd.Flags().String("user-id", "", "User ID")

	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Remove a user's consent and that client's tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			clientID, _ := cmd.Flags().GetString("client-id")

			if userID == "" || clientID == "" {
				return fmt.Errorf("user-id and client-id are required")
			}

			req, err := http.NewRequest("DELETE", serverURL+"/api/consents?user_id="+userID+"&client_id="+clientID, nil)
			if err != nil {
				return err
			}

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Consent revoked for user %s and client %s\n", userID, clientID)
			return nil
		},
	}

	revokeCmd.Flags().String("user-id", "", "User ID")
	revokeCmd.Flags().String("client-id", "", "Client ID")

	cmd.AddCommand(listCmd, revokeCmd)
	return cmd
}

func keysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Key generation commands for OAuch conformance",
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate DPoP and client signing keys for OAuch",
		RunE: func(cmd *cobra.Command, args []string) error {
			outputDir, _ := cmd.Flags().GetString("output")
			dpopOnly, _ := cmd.Flags().GetBool("dpop-only")
			clientOnly, _ := cmd.Flags().GetBool("client-only")

			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			generateAll := !dpopOnly && !clientOnly

			if generateAll || dpopOnly {
				if err := generateDPoPKey(outputDir); err != nil {
					return fmt.Errorf("failed to generate DPoP key: %w", err)
				}
			}

			if generateAll || clientOnly {
				if err := generateClientKey(outputDir); err != nil {
					return fmt.Errorf("failed to generate client key: %w", err)
				}
			}

			if generateAll {
				if err := generateOAuchConfig(outputDir); err != nil {
					return fmt.Errorf("failed to generate OAuch config: %w", err)
				}
			}

			fmt.Printf("Keys generated in: %s\n", outputDir)
			fmt.Println()
			fmt.Println("Files:")
			if generateAll || dpopOnly {
				fmt.Printf("  DPoP Private Key:  %s/dpop-private.jwk\n", outputDir)
				fmt.Printf("  DPoP Public Key:   %s/dpop-public.jwk\n", outputDir)
				fmt.Printf("  DPoP Private PEM:  %s/dpop-private.pem\n", outputDir)
			}
			if generateAll || clientOnly {
				fmt.Printf("  Client Private:    %s/client-private.jwk\n", outputDir)
				fmt.Printf("  Client Public:     %s/client-public.jwk\n", outputDir)
				fmt.Printf("  Client Private PEM:%s/client-private.pem\n", outputDir)
				fmt.Printf("  Client JWKS:       %s/client-jwks.json\n", outputDir)
			}
			if generateAll {
				fmt.Printf("  OAuch Config:      %s/oauch-config.json\n", outputDir)
				fmt.Println()
				fmt.Println("Paste the contents of oauch-config.json into your OAuch site settings.")
			}
			return nil
		},
	}

	generateCmd.Flags().StringP("output", "o", "./keys", "Output directory")
	generateCmd.Flags().Bool("dpop-only", false, "Generate only DPoP key")
	generateCmd.Flags().Bool("client-only", false, "Generate only client signing key")

	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the active signing keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiPost(serverURL+"/api/keys/rotate", "application/json", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var result map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("key rotation failed: %v", result["error_description"])
			}
			fmt.Printf("Signing keys rotated: %v\n", result["kids"])
			return nil
		},
	}

	cmd.AddCommand(generateCmd, rotateCmd)
	return cmd
}

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	D   string `json:"d,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	E   string `json:"e,omitempty"`
	N   string `json:"n,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	Dp  string `json:"dp,omitempty"`
	Dq  string `json:"dq,omitempty"`
	Qi  string `json:"qi,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type jwks struct {
	Keys []jwkKey `json:"keys"`
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateDPoPKey(dir string) error {
	fmt.Println("Generating DPoP EC P-256 key...")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Use ECDH API to get key bytes (non-deprecated in Go 1.26)
	ecdhKey, _ := key.ECDH()
	pubBytes := ecdhKey.PublicKey().Bytes()
	x := b64(pubBytes[1:33])
	y := b64(pubBytes[33:65])

	privBytes := ecdhKey.Bytes()
	d := b64(privBytes)

	privJWK := jwkKey{
		Kty: "EC",
		Crv: "P-256",
		D:   d,
		X:   x,
		Y:   y,
		Kid: "dpop-key-1",
		Use: "sig",
		Alg: "ES256",
	}

	pubJWK := jwkKey{
		Kty: "EC",
		Crv: "P-256",
		X:   x,
		Y:   y,
		Kid: "dpop-key-1",
		Use: "sig",
		Alg: "ES256",
	}

	privJSON, _ := json.MarshalIndent(privJWK, "", "  ")
	pubJSON, _ := json.MarshalIndent(pubJWK, "", "  ")

	if err := os.WriteFile(dir+"/dpop-private.jwk", privJSON, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/dpop-public.jwk", pubJSON, 0644); err != nil {
		return err
	}

	privPEM, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(dir+"/dpop-private.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privPEM}), 0600); err != nil {
		return err
	}

	fmt.Println("  ✓ DPoP key generated")
	return nil
}

func generateClientKey(dir string) error {
	fmt.Println("Generating Client RSA 2048 key...")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privJWK := jwkKey{
		Kty: "RSA",
		E:   b64(big.NewInt(int64(key.E)).Bytes()),
		N:   b64(key.N.Bytes()),
		D:   b64(key.D.Bytes()),
		P:   b64(key.Primes[0].Bytes()),
		Q:   b64(key.Primes[1].Bytes()),
		Dp:  b64(key.Precomputed.Dp.Bytes()),
		Dq:  b64(key.Precomputed.Dq.Bytes()),
		Qi:  b64(key.Precomputed.Qinv.Bytes()),
		Kid: "client-key-1",
		Use: "sig",
		Alg: "RS256",
	}

	pubJWK := jwkKey{
		Kty: "RSA",
		E:   b64(big.NewInt(int64(key.E)).Bytes()),
		N:   b64(key.N.Bytes()),
		Kid: "client-key-1",
		Use: "sig",
		Alg: "RS256",
	}

	privJSON, _ := json.MarshalIndent(privJWK, "", "  ")
	pubJSON, _ := json.MarshalIndent(pubJWK, "", "  ")

	if err := os.WriteFile(dir+"/client-private.jwk", privJSON, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/client-public.jwk", pubJSON, 0644); err != nil {
		return err
	}

	privPEM := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(dir+"/client-private.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privPEM}), 0600); err != nil {
		return err
	}

	jwksJSON, _ := json.MarshalIndent(jwks{Keys: []jwkKey{pubJWK}}, "", "  ")
	if err := os.WriteFile(dir+"/client-jwks.json", jwksJSON, 0644); err != nil {
		return err
	}

	fmt.Println("  ✓ Client signing key generated")
	return nil
}

func generateOAuchConfig(dir string) error {
	dpopBytes, err := os.ReadFile(dir + "/dpop-private.jwk")
	if err != nil {
		return err
	}
	clientBytes, err := os.ReadFile(dir + "/client-private.jwk")
	if err != nil {
		return err
	}

	var dpopKey, clientKey map[string]interface{}
	_ = json.Unmarshal(dpopBytes, &dpopKey)
	_ = json.Unmarshal(clientBytes, &clientKey)

	config := map[string]interface{}{
		"DPoPSigningKey":                dpopKey,
		"RequestSigningKey":             clientKey,
		"ClientAuthenticationMechanism": 3,
	}

	configJSON, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(dir+"/oauch-config.json", configJSON, 0644)
}
