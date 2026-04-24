package webhook

import (
	"strings"
	"testing"
)

func TestValidateRegoFile(t *testing.T) {
	validPolicy := `package ghmint

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

allow if {
	input.repository == "yagihash/app"
}`

	t.Run("valid policy", func(t *testing.T) {
		result := validateRegoFile("policy.rego", []byte(validPolicy), true)
		if len(result.Errors) != 0 {
			t.Errorf("expected no errors, got %v", result.Errors)
		}
	})

	t.Run("syntax error", func(t *testing.T) {
		bad := `package ghmint
issuer := "x"
permissions := {`
		result := validateRegoFile("policy.rego", []byte(bad), false)
		if len(result.Errors) == 0 {
			t.Error("expected syntax error")
		}
	})

	t.Run("wrong package name", func(t *testing.T) {
		bad := strings.ReplaceAll(validPolicy, "package ghmint", "package other")
		result := validateRegoFile("policy.rego", []byte(bad), false)
		if !containsError(result, "package must be") {
			t.Errorf("expected package error, got %v", result.Errors)
		}
	})

	t.Run("missing issuer", func(t *testing.T) {
		bad := strings.ReplaceAll(validPolicy, `issuer := "https://token.actions.githubusercontent.com"`, "")
		result := validateRegoFile("policy.rego", []byte(bad), false)
		if !containsError(result, `"issuer"`) {
			t.Errorf("expected missing issuer error, got %v", result.Errors)
		}
	})

	t.Run("missing allow", func(t *testing.T) {
		bad := `package ghmint
issuer := "https://token.actions.githubusercontent.com"
permissions := {"contents": "read"}
`
		result := validateRegoFile("policy.rego", []byte(bad), false)
		if !containsError(result, `"allow"`) {
			t.Errorf("expected missing allow error, got %v", result.Errors)
		}
	})

	t.Run("missing permissions", func(t *testing.T) {
		bad := `package ghmint
issuer := "https://token.actions.githubusercontent.com"
allow if { true }
`
		result := validateRegoFile("policy.rego", []byte(bad), false)
		if !containsError(result, `"permissions"`) {
			t.Errorf("expected missing permissions error, got %v", result.Errors)
		}
	})

	t.Run("unknown permission key", func(t *testing.T) {
		bad := strings.ReplaceAll(validPolicy, `{"contents": "read"}`, `{"nonexistent": "read"}`)
		result := validateRegoFile("policy.rego", []byte(bad), false)
		if !containsError(result, "nonexistent") {
			t.Errorf("expected unknown permission error, got %v", result.Errors)
		}
	})

	t.Run("invalid permission value", func(t *testing.T) {
		bad := strings.ReplaceAll(validPolicy, `{"contents": "read"}`, `{"contents": "invalid"}`)
		result := validateRegoFile("policy.rego", []byte(bad), false)
		if !containsError(result, "must be one of") {
			t.Errorf("expected invalid permission value error, got %v", result.Errors)
		}
	})

	t.Run("repositories defined in org/repo scope repo", func(t *testing.T) {
		bad := validPolicy + "\nrepositories := []"
		result := validateRegoFile("policy.rego", []byte(bad), true)
		if !containsError(result, "repositories must not be defined") {
			t.Errorf("expected repositories error, got %v", result.Errors)
		}
	})

	t.Run("repositories defined in .github repo is allowed", func(t *testing.T) {
		policy := validPolicy + "\nrepositories := []"
		result := validateRegoFile("policy.rego", []byte(policy), false)
		if containsError(result, "repositories") {
			t.Errorf("expected no repositories error for .github repo, got %v", result.Errors)
		}
	})

	t.Run("multiple valid permissions", func(t *testing.T) {
		policy := strings.ReplaceAll(validPolicy, `{"contents": "read"}`, `{"contents": "read", "issues": "write", "pull_requests": "read"}`)
		result := validateRegoFile("policy.rego", []byte(policy), false)
		if len(result.Errors) != 0 {
			t.Errorf("expected no errors, got %v", result.Errors)
		}
	})
}

func containsError(r ValidationResult, substr string) bool {
	for _, e := range r.Errors {
		if strings.Contains(e.Message, substr) {
			return true
		}
	}
	return false
}
