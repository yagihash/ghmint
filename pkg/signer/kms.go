package signer

import (
	"context"
	"crypto/sha256"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// KMSSigner implements Signer using Google Cloud KMS (RSA_SIGN_PKCS1_2048_SHA256).
type KMSSigner struct {
	client  *kms.KeyManagementClient
	keyName string // projects/.../locations/.../keyRings/.../cryptoKeyVersions/...
}

func NewKMSSigner(ctx context.Context, keyName string) (*KMSSigner, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create kms client: %w", err)
	}
	return &KMSSigner{client: client, keyName: keyName}, nil
}

func (s *KMSSigner) SignRS256(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	resp, err := s.client.AsymmetricSign(context.Background(), &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: h[:],
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("kms asymmetric sign: %w", err)
	}
	return resp.Signature, nil
}
