package rego_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/yagihash/ghmint/pkg/policystore"
	"github.com/yagihash/ghmint/pkg/verifier"
	"github.com/yagihash/ghmint/pkg/verifier/rego"
)

type staticPolicyStore struct {
	content []byte
	err     error
}

func (s *staticPolicyStore) Fetch(_ context.Context, _, _ string) ([]byte, error) {
	return s.content, s.err
}

const issuer = "https://a.example"

func claims(iss string) map[string]any {
	return map[string]any{"iss": iss}
}

func policy(body string) []byte {
	return []byte("package ghmint\n\n" + body)
}

func assertDenialError(t *testing.T, err error) {
	t.Helper()
	if _, ok := errors.AsType[*verifier.DenialError](err); !ok {
		t.Fatalf("expected *verifier.DenialError, got %T: %v", err, err)
	}
}

func TestVerify_IssuerUndefined(t *testing.T) {
	store := &staticPolicyStore{content: policy(`permissions := {"contents": "read"}
allow := true`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_IssuerMismatch(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {"contents": "read"}
allow := true`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims("https://other.example"), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_AllowUndefined(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {"contents": "read"}`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_AllowFalse(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {"contents": "read"}
allow := false`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_AllowWrongType(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {"contents": "read"}
allow := "yes"`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_PermissionsUndefined(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
allow := true`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

const basePolicy = `issuer := "https://a.example"
permissions := {"contents": "read"}
allow := true`

func TestVerify_Success_ReposUndefined_OrgRepo(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy)}
	v := rego.New(store)
	res, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Permissions["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", res.Permissions)
	}
	if len(res.Repositories) != 1 || res.Repositories[0] != "org/repo" {
		t.Errorf("expected res.Repositories=[org/repo], got %v", res.Repositories)
	}
}

func TestVerify_Success_ReposUndefined_OrgOnly(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy)}
	v := rego.New(store)
	res, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Permissions["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", res.Permissions)
	}
	if len(res.Repositories) != 1 || res.Repositories[0] != "org/.github" {
		t.Errorf("expected res.Repositories=[org/.github], got %v", res.Repositories)
	}
}

func TestVerify_Success_ReposEmpty(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + "\nrepositories := []")}
	v := rego.New(store)
	res, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Permissions["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", res.Permissions)
	}
	if res.Repositories != nil {
		t.Errorf("expected res.Repositories=nil, got %v", res.Repositories)
	}
}

func TestVerify_Success_ReposList(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + `
repositories := ["org/a"]`)}
	v := rego.New(store)
	res, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Permissions["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", res.Permissions)
	}
	if len(res.Repositories) != 1 || res.Repositories[0] != "org/a" {
		t.Errorf("expected res.Repositories=[org/a], got %v", res.Repositories)
	}
}

func TestVerify_ReposOwnerMismatch(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + `
repositories := ["other/a"]`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	assertDenialError(t, err)
}

func TestVerify_ReposOwnerMismatch_Mixed(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + `
repositories := ["org/a", "other/b"]`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	assertDenialError(t, err)
}

func TestVerify_ReposDefinedWithOrgRepoScope(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + `
repositories := ["org/a"]`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_PolicyFetchError(t *testing.T) {
	store := &staticPolicyStore{err: errors.New("network error")}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_PolicyFetchError_Upstream(t *testing.T) {
	store := &staticPolicyStore{err: fmt.Errorf("github api unavailable: %w", policystore.ErrUpstream)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	denialErr, ok := errors.AsType[*verifier.DenialError](err)
	if !ok {
		t.Fatalf("expected *verifier.DenialError, got %T: %v", err, err)
	}
	if !denialErr.Upstream {
		t.Error("expected Upstream=true for an ErrUpstream-wrapped fetch failure")
	}
}

func TestVerify_PolicyFetchError_NotUpstream(t *testing.T) {
	store := &staticPolicyStore{err: errors.New("github api returned 404: not found")}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	denialErr, ok := errors.AsType[*verifier.DenialError](err)
	if !ok {
		t.Fatalf("expected *verifier.DenialError, got %T: %v", err, err)
	}
	if denialErr.Upstream {
		t.Error("expected Upstream=false for a plain fetch failure")
	}
}

func TestVerify_PermissionsEmpty(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {}
allow := true`)}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_ReposOwnerCaseInsensitive(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + `
repositories := ["Org/a"]`)}
	v := rego.New(store)
	res, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Repositories) != 1 || res.Repositories[0] != "Org/a" {
		t.Errorf("expected res.Repositories=[Org/a], got %v", res.Repositories)
	}
}

func TestVerify_AllowWithEqualityInBody(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {"contents": "read"}
allow if {
	input.sub = "repo:org/app:refs/heads/main"
}`)}
	v := rego.New(store)
	cl := map[string]any{"iss": issuer, "sub": "repo:org/app:refs/heads/main"}
	_, err := v.Verify(context.Background(), cl, "org/repo", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerify_RegoBadSyntax(t *testing.T) {
	store := &staticPolicyStore{content: []byte("this is not valid rego {")}
	v := rego.New(store)
	_, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_App(t *testing.T) {
	tests := []struct {
		name    string
		extra   string
		wantApp string
		wantErr bool
	}{
		{"omitted defaults to default", "", "default", false},
		{"explicit name", "\napp := \"extra\"", "extra", false},
		{"unknown names pass through for the caller to check", "\napp := \"whatever\"", "whatever", false},
		{"wrong type", "\napp := 1", "", true},
		{"empty string", "\napp := \"\"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := rego.New(&staticPolicyStore{content: policy(basePolicy + tt.extra)})
			res, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
			if tt.wantErr {
				assertDenialError(t, err)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.App != tt.wantApp {
				t.Errorf("App = %q, want %q", res.App, tt.wantApp)
			}
		})
	}
}
