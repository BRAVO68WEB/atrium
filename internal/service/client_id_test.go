package service

import "testing"

func TestCreateClientRejectsABadID(t *testing.T) {
	svc := NewClientService(nil)
	_, err := svc.CreateClient(CreateClientInput{Name: "Field Notes", ID: "has space"})
	if err == nil || err.Error() != "client id is invalid" {
		t.Fatalf("err %v", err)
	}
}
