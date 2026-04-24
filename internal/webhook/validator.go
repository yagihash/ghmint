//go:generate go run ../../tools/gen-permissions

package webhook

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	oparego "github.com/open-policy-agent/opa/v1/rego"
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

// allowedBuiltins mirrors pkg/verifier/rego to apply the same safe-capabilities policy
// when evaluating policies for validation.
var allowedBuiltins = map[string]bool{
	"eq": true, "neq": true, "lt": true, "gt": true, "lte": true, "gte": true,
	"plus": true, "minus": true, "mul": true, "div": true, "rem": true,
	"abs": true, "ceil": true, "floor": true, "round": true, "numbers.range": true,
	"count": true, "sum": true, "product": true, "max": true, "min": true,
	"all": true, "any": true, "sort": true,
	"concat": true, "contains": true, "endswith": true, "startswith": true,
	"lower": true, "upper": true, "split": true, "trim": true,
	"trim_left": true, "trim_right": true, "trim_prefix": true, "trim_suffix": true,
	"replace": true, "indexof": true, "indexof_n": true,
	"substring": true, "format_int": true, "sprintf": true,
	"strings.count": true, "strings.replace_n": true, "strings.reverse": true,
	"strings.any_prefix_match": true, "strings.any_suffix_match": true,
	"regex.match": true, "regex.is_valid": true, "regex.split": true,
	"regex.find_n": true, "regex.replace": true, "regex.template_match": true,
	"glob.match": true, "glob.quote_meta": true,
	"array.concat": true, "array.slice": true, "array.reverse": true,
	"intersection": true, "union": true, "difference": true,
	"object.get": true, "object.keys": true, "object.values": true,
	"object.union": true, "object.union_n": true,
	"object.remove": true, "object.filter": true, "object.subset": true,
	"json.marshal": true, "json.unmarshal": true, "json.is_valid": true,
	"json.filter": true, "json.remove": true,
	"base64.encode": true, "base64.decode": true,
	"base64url.encode": true, "base64url.decode": true,
	"is_number": true, "is_string": true, "is_boolean": true,
	"is_array": true, "is_set": true, "is_object": true, "is_null": true,
	"type_name": true,
	"time.now_ns": true, "time.parse_rfc3339_ns": true, "time.parse_ns": true,
	"time.format": true, "time.date": true, "time.clock": true,
	"time.weekday": true, "time.add_date": true, "time.diff": true,
	"assign": true, "unify": true, "equal": true, "internal.print": true,
}

func safeCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	safe := caps.Builtins[:0]
	for _, b := range caps.Builtins {
		if allowedBuiltins[b.Name] {
			safe = append(safe, b)
		}
	}
	caps.Builtins = safe
	return caps
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

	rs, err := oparego.New(
		oparego.Query("data.ghmint.permissions"),
		oparego.Module(filename, string(content)),
		oparego.Input(map[string]interface{}{}),
		oparego.Capabilities(safeCapabilities()),
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
			Message: "permissions could not be statically evaluated; key-value validation skipped",
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
