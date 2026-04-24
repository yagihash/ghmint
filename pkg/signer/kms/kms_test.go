package kms

import (
	"context"
	"errors"
	"testing"
)

// TestSignRS256_AfterClose verifies that calling SignRS256 on a closed
// signer returns ErrSignerClosed instead of panicking on a nil client.
func TestSignRS256_AfterClose(t *testing.T) {
	s := &KMSSigner{keyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"}
	// client is nil; this mirrors the state after a successful Close().

	if err := s.Close(); err != nil {
		t.Fatalf("Close on already-nil client: %v", err)
	}
	// Idempotent.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	_, err := s.SignRS256(context.Background(), []byte("data"))
	if err == nil {
		t.Fatal("expected error after close, got nil")
	}
	if !errors.Is(err, ErrSignerClosed) {
		t.Errorf("expected ErrSignerClosed, got %v", err)
	}
}
