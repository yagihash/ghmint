//go:generate go run ../../tools/gen-permissions

package webhook

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	oparego "github.com/open-policy-agent/opa/v1/rego"
	"github.com/yagihash/ghmint/internal/regocaps"
)

// ValidationResult holds errors and warnings from static Rego validation.
type ValidationResult struct {
	Errors   []Finding
	Warnings []Finding
}

func (r ValidationResult) hasErrors() bool {
	return len(r.Errors) > 0
}

// Finding is a single validation issue with an optional source line number.
type Finding struct {
	Line    int
	Message string
}

// validateRegoFile performs static validation of a Rego policy file.
// isOrgRepo must be true when the file lives in a repository other than ".github",
// indicating callers will invoke this policy with org/repo scope.
func validateRegoFile(filename string, content []byte, isOrgRepo bool) ValidationResult {
	var result ValidationResult

	module, err := ast.ParseModule(filename, string(content))
	if err != nil {
		if errs, ok := err.(ast.Errors); ok {
			for _, e := range errs {
				line := 0
				if e.Location != nil {
					line = e.Location.Row
				}
				result.Errors = append(result.Errors, Finding{Line: line, Message: e.Message})
			}
		} else {
			result.Errors = append(result.Errors, Finding{Message: err.Error()})
		}
		return result
	}

	if module.Package.Path.String() != "data.ghmint" {
		result.Errors = append(result.Errors, Finding{
			Line:    module.Package.Loc().Row,
			Message: fmt.Sprintf(`package must be "ghmint", got %q`, module.Package.Path.String()),
		})
	}

	ruleLines := map[string]int{}
	for _, rule := range module.Rules {
		name := string(rule.Head.Name)
		if _, exists := ruleLines[name]; !exists {
			ruleLines[name] = rule.Loc().Row
		}
	}

	for _, required := range []string{"issuer", "allow", "permissions"} {
		if _, ok := ruleLines[required]; !ok {
			result.Errors = append(result.Errors, Finding{
				Message: fmt.Sprintf("required rule %q is not defined", required),
			})
		}
	}

	// repositories must not be defined when the policy lives in a non-.github repository,
	// because such policies are always invoked with org/repo scope.
	if isOrgRepo {
		if line, ok := ruleLines["repositories"]; ok {
			result.Errors = append(result.Errors, Finding{
				Line:    line,
				Message: `repositories must not be defined when the policy file is not in a ".github" repository (org/repo scope)`,
			})
		}
	}

	if _, hasPerm := ruleLines["permissions"]; hasPerm {
		result = validatePermissionsKV(filename, content, ruleLines["permissions"], result)
	}

	return result
}

func validatePermissionsKV(filename string, content []byte, permLine int, result ValidationResult) ValidationResult {
	evalCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Evaluate with empty input to extract the static permissions object.
	// If permissions depends on input (e.g. a conditional rule), evaluation returns undefined
	// and key-value validation is skipped with a warning. This is a known limitation of static
	// analysis: the runtime Rego evaluator in pkg/verifier/rego is the authoritative check.
	rs, err := oparego.New(
		oparego.Query("data.ghmint.permissions"),
		oparego.Module(filename, string(content)),
		oparego.Input(map[string]interface{}{}),
		oparego.Capabilities(regocaps.SafeCapabilities()),
	).Eval(evalCtx)
	if err != nil {
		result.Warnings = append(result.Warnings, Finding{
			Line:    permLine,
			Message: fmt.Sprintf("could not evaluate permissions for key-value validation: %v", err),
		})
		return result
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		result.Warnings = append(result.Warnings, Finding{
			Line:    permLine,
			Message: "permissions could not be statically evaluated (possibly input-dependent); key-value validation skipped",
		})
		return result
	}

	perms, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		result.Errors = append(result.Errors, Finding{
			Line:    permLine,
			Message: fmt.Sprintf("permissions must be an object, got %T", rs[0].Expressions[0].Value),
		})
		return result
	}

	for k, v := range perms {
		allowed, known := validPermissions[k]
		if !known {
			result.Errors = append(result.Errors, Finding{
				Line:    permLine,
				Message: fmt.Sprintf("unknown GitHub App permission %q", k),
			})
			continue
		}
		val, isStr := v.(string)
		if !isStr {
			result.Errors = append(result.Errors, Finding{
				Line:    permLine,
				Message: fmt.Sprintf("permissions[%q]: value must be a string", k),
			})
			continue
		}
		if !slices.Contains(allowed, val) {
			result.Errors = append(result.Errors, Finding{
				Line:    permLine,
				Message: fmt.Sprintf("permissions[%q]: value must be one of %v, got %q", k, allowed, val),
			})
		}
	}
	return result
}
