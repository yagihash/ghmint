package oidc

import "testing"

func FuzzParseUnsafe(f *testing.F) {
	seeds := []string{
		"",
		".",
		"..",
		"a.b.c",
		"!.!.!",
		"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.sig",
		"eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseUnsafe panicked on %q: %v", raw, r)
			}
		}()
		_, _, _ = parseUnsafe(raw)
	})
}
