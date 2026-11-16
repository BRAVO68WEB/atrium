package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestMergeMetadataKeepsUntouchedKeys(t *testing.T) {
	h := scriptHasher{
		hashFn:   func(password string) (string, error) { return "hashed:" + password, nil },
		verifyFn: func(encoded, password string) error { return nil },
	}
	svc, repo := newTestUserService(t, h)
	user, err := svc.InsertUser(NewUser{
		Username:     "ada",
		Password:     "correct horse",
		Email:        "ada@example.com",
		Attributes:   map[string]string{"plan": "team", "region": "us"},
		UserMetadata: map[string]string{"locale": "en"},
	})
	if err != nil {
		t.Fatal(err)
	}

	seat := "1"
	if err := svc.MergeAttributes(user, map[string]*string{"plan": nil, "seat": &seat}); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.GetByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Attributes["region"] != "us" || stored.Attributes["seat"] != "1" {
		t.Fatalf("attributes %#v", stored.Attributes)
	}
	if _, ok := stored.Attributes["plan"]; ok {
		t.Fatalf("plan still set %#v", stored.Attributes)
	}
	if stored.UserMetadata["locale"] != "en" {
		t.Fatalf("user metadata %#v", stored.UserMetadata)
	}

	patch, set, err := ParseMetadataPatch([]byte(`{"locale":null,"theme":"dark"}`))
	if err != nil || !set {
		t.Fatalf("patch %v %v", set, err)
	}
	if err := svc.MergeUserMetadata(stored, patch); err != nil {
		t.Fatal(err)
	}
	stored, err = repo.GetByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stored.UserMetadata["locale"]; ok || stored.UserMetadata["theme"] != "dark" {
		t.Fatalf("user metadata %#v", stored.UserMetadata)
	}

	tooMany := map[string]string{}
	for i := 0; i < maxMetadataKeys+1; i++ {
		tooMany[fmt.Sprintf("k%02d", i)] = "v"
	}
	if err := svc.SetAttributes(user.ID, tooMany); !errors.Is(err, ErrMetadataLimit) {
		t.Fatalf("keys err %v", err)
	}
	if err := svc.SetUserMetadata(user.ID, map[string]string{"blob": strings.Repeat("a", maxMetadataBytes)}); !errors.Is(err, ErrMetadataLimit) {
		t.Fatalf("bytes err %v", err)
	}
	if _, _, err := ParseMetadataPatch([]byte(`{"plan":1}`)); !errors.Is(err, ErrMetadataValue) {
		t.Fatalf("value err %v", err)
	}

	result, err := svc.ImportUsers(ImportDocument{
		Mode: "upsert",
		Users: []ImportUser{{
			Username:     "ada",
			Email:        "ada@example.com",
			Attributes:   map[string]string{"plan": "solo"},
			UserMetadata: map[string]string{"theme": "light"},
		}},
	}, false, nil)
	if err != nil || len(result.Errors) != 0 || result.Updated != 1 {
		t.Fatalf("import %#v %v", result, err)
	}
	exported, err := svc.ExportUsers(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	var row ImportUser
	for _, item := range exported.Users {
		if item.Username == "ada" {
			row = item
		}
	}
	if row.Attributes["plan"] != "solo" || len(row.Attributes) != 1 {
		t.Fatalf("exported attributes %#v", row.Attributes)
	}
	if row.UserMetadata["theme"] != "light" || len(row.UserMetadata) != 1 {
		t.Fatalf("exported user metadata %#v", row.UserMetadata)
	}
}
