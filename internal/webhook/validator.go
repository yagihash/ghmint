//go:generate go run ../../tools/gen-permissions

package webhook

import (
	"context"
	"fmt"
	"regexp"
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
// apps lists the registered App names that the "app" rule may select.
func validateRegoFile(filename string, content []byte, isOrgRepo bool, apps []string) ValidationResult {
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

	// Compile with the same restricted capabilities as the runtime evaluator so that
	// disallowed built-ins (and other compile errors) are rejected before merge.
	if findings := compileFindings(filename, module); len(findings) > 0 {
		result.Errors = append(result.Errors, findings...)
		return result
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

	if line, hasApp := ruleLines["app"]; hasApp {
		result = validateApp(filename, content, line, apps, result)
	}

	return result
}

// validateApp checks that the "app" rule names a registered GitHub App.
// Like validatePermissionsKV it evaluates with empty input, so an input-dependent
// app is only warned about; the runtime check in the STS is authoritative.
func validateApp(filename string, content []byte, appLine int, apps []string, result ValidationResult) ValidationResult {
	evalCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rs, err := oparego.New(
		oparego.Query("data.ghmint.app"),
		oparego.Module(filename, string(content)),
		oparego.Input(map[string]any{}),
		oparego.Capabilities(regocaps.SafeCapabilities()),
	).Eval(evalCtx)
	if err != nil {
		result.Warnings = append(result.Warnings, Finding{
			Line:    appLine,
			Message: fmt.Sprintf("could not evaluate app for validation: %v", err),
		})
		return result
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		result.Warnings = append(result.Warnings, Finding{
			Line:    appLine,
			Message: "app could not be statically evaluated (possibly input-dependent); registered-name validation skipped",
		})
		return result
	}

	name, ok := rs[0].Expressions[0].Value.(string)
	if !ok {
		result.Errors = append(result.Errors, Finding{
			Line:    appLine,
			Message: fmt.Sprintf("app must be a string, got %T", rs[0].Expressions[0].Value),
		})
		return result
	}
	if !slices.Contains(apps, name) {
		result.Errors = append(result.Errors, Finding{
			Line:    appLine,
			Message: fmt.Sprintf("app %q is not a registered GitHub App (registered: %v)", name, apps),
		})
	}
	return result
}

var undefinedFunctionRe = regexp.MustCompile(`^undefined function (\S+)$`)

// compileFindings compiles the module under regocaps.SafeCapabilities and converts compile
// errors into findings. A call to a built-in that exists in OPA but is excluded by ghmint is
// reported explicitly, since the list of allowed built-ins is not secret.
func compileFindings(filename string, module *ast.Module) []Finding {
	compiler := ast.NewCompiler().WithCapabilities(regocaps.SafeCapabilities())
	compiler.Compile(map[string]*ast.Module{filename: module})
	if !compiler.Failed() {
		return nil
	}

	all := map[string]bool{}
	for _, b := range ast.CapabilitiesForThisVersion().Builtins {
		all[b.Name] = true
	}

	var findings []Finding
	for _, e := range compiler.Errors {
		line := 0
		if e.Location != nil {
			line = e.Location.Row
		}
		msg := e.Message
		if m := undefinedFunctionRe.FindStringSubmatch(msg); m != nil && all[m[1]] {
			msg = fmt.Sprintf("built-in function %q is not allowed in ghmint policies", m[1])
		}
		findings = append(findings, Finding{Line: line, Message: msg})
	}
	return findings
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
		oparego.Input(map[string]any{}),
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

	perms, ok := rs[0].Expressions[0].Value.(map[string]any)
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
