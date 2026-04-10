package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	coreidoidc "github.com/coreos/go-oidc/v3/oidc"
)

type Verifier struct {
	audience  string
	mu        sync.Mutex
	providers map[string]*coreidoidc.Provider
}

func New(audience string) *Verifier {
	return &Verifier{
		audience:  audience,
		providers: make(map[string]*coreidoidc.Provider),
	}
}

type jwtHeader struct {
	Alg string `json:"alg"`
}

// preVerifyClaims holds only the claims needed to discover the OIDC provider
// before signature verification.
type preVerifyClaims struct {
	Iss string `json:"iss"`
}

// postVerifyClaims holds claims extracted from the verified token.
type postVerifyClaims struct {
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
}

// parseUnsafe decodes the JWT header and payload without verifying the signature.
func parseUnsafe(rawToken string) (jwtHeader, preVerifyClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return jwtHeader{}, preVerifyClaims{}, errors.New("malformed jwt: expected 3 parts")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return jwtHeader{}, preVerifyClaims{}, fmt.Errorf("malformed jwt header: %w", err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtHeader{}, preVerifyClaims{}, fmt.Errorf("malformed jwt claims: %w", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return jwtHeader{}, preVerifyClaims{}, fmt.Errorf("malformed jwt header json: %w", err)
	}
	var claims preVerifyClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return jwtHeader{}, preVerifyClaims{}, fmt.Errorf("malformed jwt claims json: %w", err)
	}

	return header, claims, nil
}

func (v *Verifier) provider(ctx context.Context, issuer string) (*coreidoidc.Provider, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if p, ok := v.providers[issuer]; ok {
		return p, nil
	}

	p, err := coreidoidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider for issuer %q: %w", issuer, err)
	}

	v.providers[issuer] = p
	return p, nil
}

// Claims holds the verified token claims returned by Verify.
type Claims struct {
	Repository      string
	RepositoryOwner string
}

func (v *Verifier) Verify(ctx context.Context, rawToken string) (Claims, error) {
	header, pre, err := parseUnsafe(rawToken)
	if err != nil {
		return Claims{}, err
	}

	if strings.EqualFold(header.Alg, "none") {
		return Claims{}, errors.New("jwt alg must not be none")
	}

	p, err := v.provider(ctx, pre.Iss)
	if err != nil {
		return Claims{}, err
	}

	idToken, err := p.Verifier(&coreidoidc.Config{ClientID: v.audience}).Verify(ctx, rawToken)
	if err != nil {
		return Claims{}, err
	}

	// TODO: 開発中の暫定チェック。ポリシー評価が実装されたら削除する。
	if idToken.Issuer != "https://token.actions.githubusercontent.com" {
		return Claims{}, fmt.Errorf("issuer %q is not allowed", idToken.Issuer)
	}

	var post postVerifyClaims
	if err := idToken.Claims(&post); err != nil {
		return Claims{}, fmt.Errorf("failed to parse verified claims: %w", err)
	}
	if post.RepositoryOwner != "yagihash" {
		return Claims{}, fmt.Errorf("repository_owner %q is not allowed", post.RepositoryOwner)
	}

	return Claims{Repository: post.Repository, RepositoryOwner: post.RepositoryOwner}, nil
}
