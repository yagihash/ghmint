package oidc

import (
	"context"

	coreidoidc "github.com/coreos/go-oidc/v3/oidc"
)

const GitHubIssuer = "https://token.actions.githubusercontent.com"

type Verifier struct {
	v *coreidoidc.IDTokenVerifier
}

func New(ctx context.Context, audience string) (*Verifier, error) {
	provider, err := coreidoidc.NewProvider(ctx, GitHubIssuer)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		v: provider.Verifier(&coreidoidc.Config{ClientID: audience}),
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, rawToken string) error {
	_, err := v.v.Verify(ctx, rawToken)
	return err
}
