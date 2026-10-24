package oidc

import (
	"log"
	"time"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

// StartRotation retires signing keys on a fixed interval. A zero interval does nothing.
func StartRotation(ks *KeySet, interval, retain time.Duration) {
	defer telemetry.Step("oidc.StartRotation")()
	if ks == nil || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := ks.Rotate(retain); err != nil {
				log.Printf("signing key rotation: %v", err)
			}
		}
	}()
}
