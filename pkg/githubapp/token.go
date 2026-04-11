package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type TokenIssuer struct {
	appID      string
	privateKey *rsa.PrivateKey
}

func New(appID string, privateKeyPath string) (*TokenIssuer, error) {
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", privateKeyPath)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &TokenIssuer{
		appID:      appID,
		privateKey: key,
	}, nil
}

func (t *TokenIssuer) Issue(ctx context.Context, owner string) (string, error) {
	jwt, err := t.signJWT()
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	installationID, err := t.getInstallationID(ctx, jwt, owner)
	if err != nil {
		return "", fmt.Errorf("get installation id: %w", err)
	}

	return t.requestInstallationToken(ctx, jwt, installationID)
}

func (t *TokenIssuer) signJWT() (string, error) {
	now := time.Now()

	headerJSON, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": "RS256"})
	payloadJSON, _ := json.Marshal(map[string]any{
		"iss": t.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(600 * time.Second).Unix(),
	})

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, t.privateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (t *TokenIssuer) getInstallationID(ctx context.Context, jwt, owner string) (int64, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/installation", owner)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("github api returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	return result.ID, nil
}

func (t *TokenIssuer) requestInstallationToken(ctx context.Context, jwt string, installationID int64) (string, error) {
	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errBody struct {
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&errBody)
		return "", fmt.Errorf("github api returned %d: %s", resp.StatusCode, errBody.Message)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if result.Token == "" {
		return "", fmt.Errorf("empty token in response")
	}

	return result.Token, nil
}
