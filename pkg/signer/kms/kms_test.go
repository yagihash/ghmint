package kms

import (
	"context"
	"errors"
	"sync"
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

// TestSignRS256_ConcurrentClose verifies that concurrent Close and SignRS256
// do not cause a data race. Run with -race to detect violations.
func TestSignRS256_ConcurrentClose(t *testing.T) {
	s := &KMSSigner{keyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"}

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.Close()
		}()
		go func() {
			defer wg.Done()
			s.SignRS256(context.Background(), []byte("data"))
		}()
	}
	wg.Wait()
}
