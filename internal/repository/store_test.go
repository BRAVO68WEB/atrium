package repository

import (
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/testpg"
)

type rowStore struct {
	clients *ClientRepository
	users   *UserRepository
	tokens  *TokenRepository
	devices *DeviceCodeRepository
	ciba    *CIBARepository
}

func setupTestDB(t *testing.T) *rowStore {
	t.Helper()
	db := testpg.Open(t)
	return &rowStore{
		clients: NewClientRepository(db),
		users:   NewUserRepository(db),
		tokens:  NewTokenRepository(db),
		devices: NewDeviceCodeRepository(db),
		ciba:    NewCIBARepository(db),
	}
}

func TestCreateAndGetClient(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:                      "test-client-1",
		Secret:                  "test-secret-1",
		Name:                    "Test Client",
		RedirectURIs:            []string{"https://example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
		CreatedAt:               time.Now(),
		UpdatedAt:               time.Now(),
	}

	err := db.clients.Create(client)
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	found, err := db.clients.GetByID("test-client-1")
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}

	if found.ID != client.ID {
		t.Errorf("Expected ID %q, got %q", client.ID, found.ID)
	}
	if found.Name != client.Name {
		t.Errorf("Expected Name %q, got %q", client.Name, found.Name)
	}
}

func TestListClients(t *testing.T) {
	db := setupTestDB(t)

	client1 := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Client 1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	client2 := &models.Client{
		ID:        "client-2",
		Secret:    "secret-2",
		Name:      "Client 2",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := db.clients.Create(client1); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}
	if err := db.clients.Create(client2); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	clients, err := db.clients.List()
	if err != nil {
		t.Fatalf("ListClients failed: %v", err)
	}

	if len(clients) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(clients))
	}
}

func TestUpdateClient(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Original Name",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := db.clients.Create(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	client.Name = "Updated Name"
	err := db.clients.Update(client)
	if err != nil {
		t.Fatalf("UpdateClient failed: %v", err)
	}

	found, _ := db.clients.GetByID("client-1")
	if found.Name != "Updated Name" {
		t.Errorf("Expected Name %q, got %q", "Updated Name", found.Name)
	}
}

func TestDeleteClient(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Test Client",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := db.clients.Create(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	err := db.clients.Delete("client-1")
	if err != nil {
		t.Fatalf("DeleteClient failed: %v", err)
	}

	_, err = db.clients.GetByID("client-1")
	if err == nil {
		t.Error("GetClient should fail after deletion")
	}
}

func TestCreateAndGetUser(t *testing.T) {
	db := setupTestDB(t)

	user := &models.User{
		ID:           "user-1",
		Username:     "testuser",
		PasswordHash: "hashed_password",
		Email:        "test@example.com",
		PhoneNumber:  "+1234567890",
		CreatedAt:    time.Now(),
	}

	err := db.users.Create(user)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	found, err := db.users.GetByID("user-1")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if found.Username != user.Username {
		t.Errorf("Expected Username %q, got %q", user.Username, found.Username)
	}
	if found.Email != user.Email {
		t.Errorf("Expected Email %q, got %q", user.Email, found.Email)
	}
}

func TestGetUserByUsername(t *testing.T) {
	db := setupTestDB(t)

	user := &models.User{
		ID:           "user-1",
		Username:     "testuser",
		PasswordHash: "hashed_password",
		Email:        "test@example.com",
		CreatedAt:    time.Now(),
	}

	if err := db.users.Create(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	found, err := db.users.GetByUsername("testuser")
	if err != nil {
		t.Fatalf("GetUserByUsername failed: %v", err)
	}

	if found.ID != user.ID {
		t.Errorf("Expected ID %q, got %q", user.ID, found.ID)
	}
}

func TestSaveAndGetAccessToken(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Test Client",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.clients.Create(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	token := &models.AccessToken{
		Token:     "test-token-1",
		ClientID:  "client-1",
		UserID:    "user-1",
		Scopes:    []string{"openid", "profile"},
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := db.tokens.SaveAccessToken(token)
	if err != nil {
		t.Fatalf("SaveAccessToken failed: %v", err)
	}

	found, err := db.tokens.GetAccessToken("test-token-1")
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}

	if found.TokenType != "Bearer" {
		t.Errorf("Expected TokenType %q, got %q", "Bearer", found.TokenType)
	}
}

func TestRevokeAccessToken(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Test Client",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.clients.Create(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	token := &models.AccessToken{
		Token:     "test-token-1",
		ClientID:  "client-1",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := db.tokens.SaveAccessToken(token); err != nil {
		t.Fatalf("SaveAccessToken failed: %v", err)
	}

	err := db.tokens.RevokeAccessToken("test-token-1")
	if err != nil {
		t.Fatalf("RevokeAccessToken failed: %v", err)
	}

	found, _ := db.tokens.GetAccessToken("test-token-1")
	if !found.Revoked {
		t.Error("Token should be revoked")
	}
}

func TestSaveAndGetRefreshToken(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Test Client",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.clients.Create(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	token := &models.RefreshToken{
		Token:       "refresh-token-1",
		AccessToken: "access-token-1",
		ClientID:    "client-1",
		UserID:      "user-1",
		Scopes:      []string{"openid"},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	err := db.tokens.SaveRefreshToken(token)
	if err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	found, err := db.tokens.GetRefreshToken("refresh-token-1")
	if err != nil {
		t.Fatalf("GetRefreshToken failed: %v", err)
	}

	if found.AccessToken != "access-token-1" {
		t.Errorf("Expected AccessToken %q, got %q", "access-token-1", found.AccessToken)
	}
}

func TestSaveAndGetDeviceCode(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Test Client",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.clients.Create(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	dc := &models.DeviceCode{
		DeviceCode: "device-code-1",
		UserCode:   "ABCD-EFGH",
		ClientID:   "client-1",
		Scopes:     []string{"openid"},
		Status:     "pending",
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		Interval:   5,
	}

	err := db.devices.Save(dc)
	if err != nil {
		t.Fatalf("SaveDeviceCode failed: %v", err)
	}

	found, err := db.devices.GetByDeviceCode("device-code-1")
	if err != nil {
		t.Fatalf("GetDeviceCode failed: %v", err)
	}

	if found.UserCode != "ABCD-EFGH" {
		t.Errorf("Expected UserCode %q, got %q", "ABCD-EFGH", found.UserCode)
	}
}

func TestSaveAndGetCIBARequest(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Test Client",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.clients.Create(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	user := &models.User{
		ID:           "user-1",
		Username:     "testuser",
		PasswordHash: "hashed",
		CreatedAt:    time.Now(),
	}
	if err := db.users.Create(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	req := &models.CIBARequest{
		AuthReqID:      "auth-req-1",
		ClientID:       "client-1",
		UserID:         "user-1",
		BindingMessage: "Test message",
		Status:         "pending",
		DeliveryMode:   "poll",
		ExpiresAt:      time.Now().Add(2 * time.Minute),
		Interval:       5,
	}

	err := db.ciba.Save(req)
	if err != nil {
		t.Fatalf("SaveCIBARequest failed: %v", err)
	}

	found, err := db.ciba.GetByID("auth-req-1")
	if err != nil {
		t.Fatalf("GetCIBARequest failed: %v", err)
	}

	if found.BindingMessage != "Test message" {
		t.Errorf("Expected BindingMessage %q, got %q", "Test message", found.BindingMessage)
	}
}

func TestGetPendingCIBARequests(t *testing.T) {
	db := setupTestDB(t)

	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Test Client",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.clients.Create(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	user := &models.User{
		ID:           "user-1",
		Username:     "testuser",
		PasswordHash: "hashed",
		CreatedAt:    time.Now(),
	}
	if err := db.users.Create(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	req1 := &models.CIBARequest{
		AuthReqID: "req-1",
		ClientID:  "client-1",
		UserID:    "user-1",
		Status:    "pending",
		ExpiresAt: time.Now().Add(2 * time.Minute),
	}

	req2 := &models.CIBARequest{
		AuthReqID: "req-2",
		ClientID:  "client-1",
		UserID:    "user-1",
		Status:    "approved",
		ExpiresAt: time.Now().Add(2 * time.Minute),
	}

	if err := db.ciba.Save(req1); err != nil {
		t.Fatalf("SaveCIBARequest failed: %v", err)
	}
	if err := db.ciba.Save(req2); err != nil {
		t.Fatalf("SaveCIBARequest failed: %v", err)
	}

	pending, err := db.ciba.GetPending()
	if err != nil {
		t.Fatalf("GetPendingCIBARequests failed: %v", err)
	}

	if len(pending) != 1 {
		t.Errorf("Expected 1 pending request, got %d", len(pending))
	}
}

func TestAccessTokenKeepsStoredFields(t *testing.T) {
	db := setupTestDB(t)
	client := &models.Client{
		ID:        "client-1",
		Secret:    "secret-1",
		Name:      "Test Client",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.clients.Create(client); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	token := &models.AccessToken{
		Token:     "test-token-fields",
		ClientID:  "client-1",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(time.Hour),
		Resource:  "https://api.example",
		IssuedAt:  issued,
		JTI:       "jti-1",
		OrgID:     "org-1",
		Act:       "actor-1",
	}
	if err := db.tokens.SaveAccessToken(token); err != nil {
		t.Fatal(err)
	}
	found, err := db.tokens.GetAccessToken("test-token-fields")
	if err != nil {
		t.Fatal(err)
	}
	if found.Resource != token.Resource || found.JTI != token.JTI || found.OrgID != token.OrgID || found.Act != token.Act {
		t.Fatalf("token = %+v", found)
	}
	if !found.IssuedAt.Equal(issued) {
		t.Fatalf("iat = %s", found.IssuedAt)
	}
}
