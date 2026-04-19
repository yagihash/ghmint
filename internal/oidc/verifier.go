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
	audience       string
	allowedIssuers []string // nil or empty means all issuers are allowed
	mu             sync.Mutex
	providers      map[string]*coreidoidc.Provider
}

// New creates a new Verifier. allowedIssuers restricts which OIDC issuers are
// accepted; pass nil or an empty slice to allow any issuer.
func New(audience string, allowedIssuers []string) *Verifier {
	return &Verifier{
		audience:       audience,
		allowedIssuers: allowedIssuers,
		providers:      make(map[string]*coreidoidc.Provider),
	}
}

type jwtHeader struct {
	Alg string `json:"alg"`
}

type preVerifyClaims struct {
	Iss string `json:"iss"`
}

type postVerifyClaims struct {
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
}

type rawClaims map[string]interface{}

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
	Raw             map[string]interface{}
}

func (v *Verifier) Verify(ctx context.Context, rawToken string) (Claims, error) {
	header, pre, err := parseUnsafe(rawToken)
	if err != nil {
		return Claims{}, err
	}

	if strings.EqualFold(header.Alg, "none") {
		return Claims{}, errors.New("jwt alg must not be none")
	}

	if len(v.allowedIssuers) > 0 {
		allowed := false
		for _, iss := range v.allowedIssuers {
			if iss == pre.Iss {
				allowed = true
				break
			}
		}
		if !allowed {
			return Claims{}, fmt.Errorf("issuer %q is not in the allowed issuers list", pre.Iss)
		}
	}

	p, err := v.provider(ctx, pre.Iss)
	if err != nil {
		return Claims{}, err
	}

	idToken, err := p.Verifier(&coreidoidc.Config{ClientID: v.audience}).Verify(ctx, rawToken)
	if err != nil {
		return Claims{}, err
	}

	var post postVerifyClaims
	if err := idToken.Claims(&post); err != nil {
		return Claims{}, fmt.Errorf("failed to parse verified claims: %w", err)
	}

	var raw rawClaims
	if err := idToken.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("failed to parse raw claims: %w", err)
	}

	return Claims{Repository: post.Repository, RepositoryOwner: post.RepositoryOwner, Raw: raw}, nil
}
