package route

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/controller"
	"github.com/bravo68web/atrium/internal/handlers/oauth"
)

func MountAccountAPI(api chi.Router, account *controller.AccountController, userMW func(http.Handler) http.Handler) {
	api.Post("/account/register", account.HandleRegister)
	api.Post("/account/password/forgot", account.HandleForgot)
	api.Post("/account/password/reset", account.HandleReset)
	api.Post("/account/email/verify", account.HandleVerifyEmail)

	api.Group(func(me chi.Router) {
		me.Use(userMW)
		me.Get("/me", account.HandleMe)
		me.Patch("/me", account.HandlePatchMe)
		me.Post("/me/password", account.HandleChangePassword)
		me.Post("/me/email/send", account.HandleResend)
		me.Get("/me/sessions", account.HandleListSessions)
		me.Delete("/me/sessions/{sid}", account.HandleRevokeSession)
		me.Get("/me/refresh-tokens", account.HandleListRefresh)
		me.Delete("/me/refresh-tokens/{id}", account.HandleRevokeRefresh)
		me.Get("/me/activity", account.HandleActivity)
		me.Get("/me/login-analytics", account.HandleLoginAnalytics)
		me.Get("/me/consents", account.HandleListMyConsents)
		me.Delete("/me/consents/{clientID}", account.HandleRevokeMyConsent)
	})
}

func MountManagementExtras(api chi.Router, mgmt *controller.ManagementController) {
	api.Patch("/users/{userID}", mgmt.HandlePatchUser)
	api.Post("/users/{userID}/password", mgmt.HandleSetPassword)
	api.Post("/users/{userID}/password/reset-email", mgmt.HandleResetEmail)
	api.Post("/users/{userID}/migration-notice", mgmt.HandleMigrationNotice)
	api.Post("/users/{userID}/push/revoke", mgmt.HandleRevokeUserDevices)
	api.Post("/users/{userID}/push/enroll", mgmt.HandleEnrollUserDevice)
	api.Get("/users/{userID}/sessions", mgmt.HandleListUserSessions)
	api.Delete("/users/{userID}/sessions/{sid}", mgmt.HandleRevokeUserSession)
	api.Get("/users/{userID}/activity", mgmt.HandleUserActivity)
	api.Get("/users/{userID}/login-analytics", mgmt.HandleUserLoginAnalytics)
	api.Post("/users/{userID}/roles", mgmt.HandleAssignUserRole)
	api.Delete("/users/{userID}/roles", mgmt.HandleRemoveUserRole)
	api.Post("/users/{userID}/scopes", mgmt.HandleAssignUserScope)
	api.Delete("/users/{userID}/scopes", mgmt.HandleRemoveUserScope)
	api.Get("/users/{userID}/access", mgmt.HandleUserAccess)
	api.Get("/analytics/logins", mgmt.HandleGlobalLoginAnalytics)
	api.Get("/refresh-tokens", mgmt.HandleListRefreshTokens)
	api.Post("/refresh-tokens/{id}/revoke", mgmt.HandleRevokeRefreshToken)
	api.Get("/webhooks", mgmt.HandleListWebhooks)
	api.Post("/webhooks", mgmt.HandleCreateWebhook)
	api.Get("/webhooks/{id}", mgmt.HandleGetWebhook)
	api.Patch("/webhooks/{id}", mgmt.HandleUpdateWebhook)
	api.Delete("/webhooks/{id}", mgmt.HandleDeleteWebhook)
	api.Post("/webhooks/{id}/test", mgmt.HandleTestWebhook)
	api.Get("/audit", mgmt.HandleListAudit)
	api.Get("/keys", mgmt.HandleListKeys)
	api.Post("/keys/rotate", mgmt.HandleRotateKeys)
	api.Get("/orgs", mgmt.HandleListOrgs)
	api.Post("/orgs", mgmt.HandleCreateOrg)
	api.Get("/orgs/{orgID}", mgmt.HandleGetOrg)
	api.Patch("/orgs/{orgID}", mgmt.HandleUpdateOrg)
	api.Post("/orgs/{orgID}/domains", mgmt.HandleAddOrgDomain)
	api.Get("/orgs/{orgID}/members", mgmt.HandleListOrgMembers)
	api.Post("/orgs/{orgID}/members", mgmt.HandleAddOrgMember)
}

func MountOrgSelector(r chi.Router, web *controller.WebController) {
	r.Get("/organization", web.HandleOrgSelectPage)
	r.Post("/organization", web.HandleOrgSelect)
}

func MountBrowserExtras(r chi.Router, account *controller.AccountController, oauthHandler *oauth.Handler) {
	r.Get("/forgot", account.HandleForgotPage)
	r.Post("/forgot", account.HandleForgotSubmit)
	r.Get("/reset", account.HandleResetPage)
	r.Post("/reset", account.HandleResetSubmit)
	r.Get("/verify-email", account.HandleVerifyPage)
	r.Get("/profile", account.HandleProfile)
	r.Post("/profile/consents", account.HandleProfileRevoke)
	r.Post("/profile/password", account.HandleProfilePassword)
	r.Post("/profile/email", account.HandleProfileEmail)
	r.Post("/profile/mfa", account.HandleProfileMFA)
	r.Post("/profile/sessions", account.HandleProfileSession)
	r.Get("/oauth/logout", oauthHandler.HandleLogout)
	r.Post("/oauth/logout", oauthHandler.HandleLogout)
}
