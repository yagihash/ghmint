package kms

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"sync"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ErrSignerClosed is returned by SignRS256 when Close has already been called.
var ErrSignerClosed = errors.New("kms signer: closed")

// crc32cTable is the Castagnoli table used for the integrity checksums Cloud KMS
// expects on AsymmetricSign requests and returns on responses.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

type KMSSigner struct {
	mu      sync.Mutex
	client  *kms.KeyManagementClient
	keyName string
}

func NewKMSSigner(ctx context.Context, keyName string) (*KMSSigner, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create kms client: %w", err)
	}
	return &KMSSigner{client: client, keyName: keyName}, nil
}

// Close releases resources held by the underlying KMS client. Safe to call
// more than once; subsequent calls after a successful close return nil.
// Safe to call concurrently with SignRS256.
func (s *KMSSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		return nil
	}
	err := s.client.Close()
	s.client = nil
	return err
}

func (s *KMSSigner) SignRS256(ctx context.Context, data []byte) ([]byte, error) {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return nil, ErrSignerClosed
	}
	h := sha256.Sum256(data)
	resp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: h[:],
			},
		},
		// Send the digest checksum so KMS can confirm the request was not
		// corrupted in transit (reflected back via VerifiedDigestCrc32C).
		DigestCrc32C: wrapperspb.Int64(int64(crc32.Checksum(h[:], crc32cTable))),
	})
	if err != nil {
		return nil, fmt.Errorf("kms asymmetric sign: %w", err)
	}

	// Integrity verification recommended by Cloud KMS: detect data corruption
	// in transit on both the request and the response before trusting the signature.
	if !resp.VerifiedDigestCrc32C {
		return nil, errors.New("kms asymmetric sign: request digest corrupted in transit")
	}
	if resp.Name != s.keyName {
		return nil, fmt.Errorf("kms asymmetric sign: response key name mismatch (got %q, want %q)", resp.Name, s.keyName)
	}
	if resp.SignatureCrc32C == nil || int64(crc32.Checksum(resp.Signature, crc32cTable)) != resp.SignatureCrc32C.Value {
		return nil, errors.New("kms asymmetric sign: response signature corrupted in transit")
	}
	return resp.Signature, nil
}
