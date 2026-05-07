package regocaps

import "github.com/open-policy-agent/opa/v1/ast"

// allowedBuiltins lists OPA built-in functions that policies may use.
// Side-effectful built-ins (http.send, net.lookup_ip_addr, opa.runtime, etc.) are intentionally absent.
var allowedBuiltins = map[string]bool{
	// Comparison
	"eq": true, "neq": true, "lt": true, "gt": true, "lte": true, "gte": true,
	// Arithmetic
	"plus": true, "minus": true, "mul": true, "div": true, "rem": true,
	"abs": true, "ceil": true, "floor": true, "round": true, "numbers.range": true,
	// Aggregates
	"count": true, "sum": true, "product": true, "max": true, "min": true,
	"all": true, "any": true, "sort": true,
	// String
	"concat": true, "contains": true, "endswith": true, "startswith": true,
	"lower": true, "upper": true, "split": true, "trim": true,
	"trim_left": true, "trim_right": true, "trim_prefix": true, "trim_suffix": true,
	"replace": true, "indexof": true, "indexof_n": true,
	"substring": true, "format_int": true, "sprintf": true,
	"strings.count": true, "strings.replace_n": true, "strings.reverse": true,
	"strings.any_prefix_match": true, "strings.any_suffix_match": true,
	// Regex / Glob
	"regex.match": true, "regex.is_valid": true, "regex.split": true,
	"regex.find_n": true, "regex.replace": true, "regex.template_match": true,
	"glob.match": true, "glob.quote_meta": true,
	// Array / Set / Object
	"array.concat": true, "array.slice": true, "array.reverse": true,
	"intersection": true, "union": true, "difference": true,
	"object.get": true, "object.keys": true, "object.values": true,
	"object.union": true, "object.union_n": true,
	"object.remove": true, "object.filter": true, "object.subset": true,
	// JSON / Encoding
	"json.marshal": true, "json.unmarshal": true, "json.is_valid": true,
	"json.filter": true, "json.remove": true,
	"base64.encode": true, "base64.decode": true,
	"base64url.encode": true, "base64url.decode": true,
	// Types
	"is_number": true, "is_string": true, "is_boolean": true,
	"is_array": true, "is_set": true, "is_object": true, "is_null": true,
	"type_name": true,
	// Time (read-only)
	"time.now_ns": true, "time.parse_rfc3339_ns": true, "time.parse_ns": true,
	"time.format": true, "time.date": true, "time.clock": true,
	"time.weekday": true, "time.add_date": true, "time.diff": true,
	// OPA internals required for evaluation
	"assign": true, "unify": true, "equal": true, "internal.print": true,
}

// SafeCapabilities returns OPA capabilities restricted to the side-effect-free built-ins above.
// Both the policy evaluator (pkg/verifier/rego) and the static validator (internal/webhook) must
// use this function to ensure the capability set is identical at validation time and at runtime.
func SafeCapabilities() *ast.Capabilities {
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
