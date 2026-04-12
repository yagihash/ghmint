package verifier_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yagihash/mini-gh-sts/pkg/policyerrors"
	"github.com/yagihash/mini-gh-sts/pkg/verifier"
)

type staticPolicyStore struct {
	content []byte
	err     error
}

func (s *staticPolicyStore) Fetch(_ context.Context, _, _ string) ([]byte, error) {
	return s.content, s.err
}

const issuer = "https://a.example"

func claims(iss string) map[string]interface{} {
	return map[string]interface{}{"iss": iss}
}

func policy(body string) []byte {
	return []byte("package mini_gh_sts\n\n" + body)
}

func assertDenialError(t *testing.T, err error) {
	t.Helper()
	var de *policyerrors.DenialError
	if !errors.As(err, &de) {
		t.Fatalf("expected *policyerrors.DenialError, got %T: %v", err, err)
	}
}

func TestVerify_IssuerUndefined(t *testing.T) {
	store := &staticPolicyStore{content: policy(`permissions := {"contents": "read"}
allow := true`)}
	v := verifier.New(store)
	_, _, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_IssuerMismatch(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {"contents": "read"}
allow := true`)}
	v := verifier.New(store)
	_, _, err := v.Verify(context.Background(), claims("https://other.example"), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_AllowUndefined(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {"contents": "read"}`)}
	v := verifier.New(store)
	_, _, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_AllowFalse(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
permissions := {"contents": "read"}
allow := false`)}
	v := verifier.New(store)
	_, _, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_PermissionsUndefined(t *testing.T) {
	store := &staticPolicyStore{content: policy(`issuer := "https://a.example"
allow := true`)}
	v := verifier.New(store)
	_, _, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

const basePolicy = `issuer := "https://a.example"
permissions := {"contents": "read"}
allow := true`

func TestVerify_Success_ReposUndefined_OrgRepo(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy)}
	v := verifier.New(store)
	perms, repos, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perms["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", perms)
	}
	if len(repos) != 1 || repos[0] != "org/repo" {
		t.Errorf("expected repos=[org/repo], got %v", repos)
	}
}

func TestVerify_Success_ReposUndefined_OrgOnly(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy)}
	v := verifier.New(store)
	perms, repos, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perms["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", perms)
	}
	if len(repos) != 1 || repos[0] != "org/.github" {
		t.Errorf("expected repos=[org/.github], got %v", repos)
	}
}

func TestVerify_Success_ReposEmpty(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + "\nrepositories := []")}
	v := verifier.New(store)
	perms, repos, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perms["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", perms)
	}
	if repos != nil {
		t.Errorf("expected repos=nil, got %v", repos)
	}
}

func TestVerify_Success_ReposList(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + `
repositories := ["org/a"]`)}
	v := verifier.New(store)
	perms, repos, err := v.Verify(context.Background(), claims(issuer), "org", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perms["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", perms)
	}
	if len(repos) != 1 || repos[0] != "org/a" {
		t.Errorf("expected repos=[org/a], got %v", repos)
	}
}

func TestVerify_ReposDefinedWithOrgRepoScope(t *testing.T) {
	store := &staticPolicyStore{content: policy(basePolicy + `
repositories := ["org/a"]`)}
	v := verifier.New(store)
	_, _, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_PolicyFetchError(t *testing.T) {
	store := &staticPolicyStore{err: errors.New("network error")}
	v := verifier.New(store)
	_, _, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}

func TestVerify_RegoBadSyntax(t *testing.T) {
	store := &staticPolicyStore{content: []byte("this is not valid rego {")}
	v := verifier.New(store)
	_, _, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
	assertDenialError(t, err)
}
