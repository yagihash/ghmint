package config

import (
	"os"
	"testing"
)

func unsetenv(t *testing.T, key string) {
	t.Helper()
	prev, existed := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("Unsetenv(%q): %v", key, err)
	}
	t.Cleanup(func() {
		if existed {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestKMSKeyName(t *testing.T) {
	c := &Config{
		KMSProjectID:  "my-project",
		KMSLocation:   "global",
		KMSKeyRingID:  "my-keyring",
		KMSKeyID:      "my-key",
		KMSKeyVersion: "1",
	}

	want := "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1"
	if got := c.KMSKeyName(); got != want {
		t.Errorf("KMSKeyName() = %q, want %q", got, want)
	}
}

func TestLoad(t *testing.T) {
	baseEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("STS_AUDIENCE", "sts.example.com")
		t.Setenv("STS_APP_ID", "123456")
		t.Setenv("STS_ALLOWED_ISSUERS", "https://token.actions.githubusercontent.com")
		t.Setenv("STS_KMS_PROJECT_ID", "my-project")
		t.Setenv("STS_KMS_LOCATION", "global")
		t.Setenv("STS_KMS_KEYRING_ID", "my-keyring")
		t.Setenv("STS_KMS_KEY_ID", "my-key")
		t.Setenv("STS_KMS_KEY_VERSION", "1")
	}

	t.Run("all required fields set", func(t *testing.T) {
		baseEnv(t)

		c, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if c.Audience != "sts.example.com" {
			t.Errorf("Hostname = %q, want %q", c.Audience, "sts.example.com")
		}
		if c.AppID != "123456" {
			t.Errorf("AppID = %q, want %q", c.AppID, "123456")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		baseEnv(t)
		unsetenv(t, "STS_PORT")
		unsetenv(t, "STS_DEBUG")

		c, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if c.Port != 8080 {
			t.Errorf("Port = %d, want 8080", c.Port)
		}
		if c.Debug != false {
			t.Errorf("Debug = %v, want false", c.Debug)
		}
	})

	t.Run("missing required field returns error", func(t *testing.T) {
		baseEnv(t)
		unsetenv(t, "STS_AUDIENCE")

		if _, err := Load(); err == nil {
			t.Error("Load() expected error, got nil")
		}
	})

	t.Run("default allowed issuers applied when unset", func(t *testing.T) {
		baseEnv(t)
		unsetenv(t, "STS_ALLOWED_ISSUERS")

		c, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if len(c.AllowedIssuers) != 1 || c.AllowedIssuers[0] != "https://token.actions.githubusercontent.com" {
			t.Errorf("AllowedIssuers = %v, want [https://token.actions.githubusercontent.com]", c.AllowedIssuers)
		}
	})

	t.Run("empty allowed issuers returns error", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("STS_ALLOWED_ISSUERS", "")

		if _, err := Load(); err == nil {
			t.Error("Load() expected error for empty STS_ALLOWED_ISSUERS, got nil")
		}
	})
}

func TestLoad_Apps(t *testing.T) {
	baseEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("STS_AUDIENCE", "sts.example.com")
		t.Setenv("STS_APP_ID", "123456")
		t.Setenv("STS_KMS_PROJECT_ID", "my-project")
		t.Setenv("STS_KMS_LOCATION", "global")
		t.Setenv("STS_KMS_KEYRING_ID", "my-keyring")
		t.Setenv("STS_KMS_KEY_ID", "my-key")
		t.Setenv("STS_KMS_KEY_VERSION", "1")
	}
	extraEnv := func(t *testing.T, prefix, id string) {
		t.Helper()
		t.Setenv(prefix+"_ID", id)
		t.Setenv(prefix+"_KMS_PROJECT_ID", "p2")
		t.Setenv(prefix+"_KMS_LOCATION", "asia")
		t.Setenv(prefix+"_KMS_KEYRING_ID", "kr2")
		t.Setenv(prefix+"_KMS_KEY_ID", "k2")
		t.Setenv(prefix+"_KMS_KEY_VERSION", "3")
	}

	t.Run("legacy variables only yield the default app", func(t *testing.T) {
		baseEnv(t)
		unsetenv(t, "STS_APPS")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if len(c.Apps) != 1 {
			t.Fatalf("Apps = %+v, want only default", c.Apps)
		}
		a := c.Apps[0]
		if a.Name != "default" || a.AppID != "123456" ||
			a.KMSKeyName() != "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1" {
			t.Errorf("unexpected default app: %+v", a)
		}
		if got := c.AppNames(); len(got) != 1 || got[0] != "default" {
			t.Errorf("AppNames() = %v", got)
		}
	})

	t.Run("extra apps", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("STS_APPS", "release, my-bot")
		extraEnv(t, "STS_APP_RELEASE", "222")
		extraEnv(t, "STS_APP_MY_BOT", "333")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if got := c.AppNames(); len(got) != 3 || got[0] != "default" || got[1] != "release" || got[2] != "my-bot" {
			t.Fatalf("AppNames() = %v", got)
		}
		if c.Apps[1].AppID != "222" || c.Apps[2].AppID != "333" {
			t.Errorf("unexpected app ids: %+v", c.Apps)
		}
		want := "projects/p2/locations/asia/keyRings/kr2/cryptoKeys/k2/cryptoKeyVersions/3"
		if got := c.Apps[1].KMSKeyName(); got != want {
			t.Errorf("KMSKeyName() = %q, want %q", got, want)
		}
	})

	errCases := []struct {
		name string
		apps string
		prep func(t *testing.T)
	}{
		{"default is reserved", "default", nil},
		{"invalid name", "Bad_Name", nil},
		{"duplicate name", "a,a", func(t *testing.T) { extraEnv(t, "STS_APP_A", "1") }},
		{"names colliding on env prefix", "a-b,a_b", nil},
		{"missing variables", "ghost", nil},
		{"non-integer key version", "x", func(t *testing.T) {
			extraEnv(t, "STS_APP_X", "1")
			t.Setenv("STS_APP_X_KMS_KEY_VERSION", "latest")
		}},
	}
	for _, tt := range errCases {
		t.Run(tt.name, func(t *testing.T) {
			baseEnv(t)
			t.Setenv("STS_APPS", tt.apps)
			if tt.prep != nil {
				tt.prep(t)
			}
			if _, err := Load(); err == nil {
				t.Error("expected error")
			}
		})
	}

	t.Run("unprefixed APPS is ignored", func(t *testing.T) {
		baseEnv(t)
		unsetenv(t, "STS_APPS")
		t.Setenv("APPS", "foo,bar")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if len(c.Apps) != 1 {
			t.Errorf("Apps = %+v, want only default", c.Apps)
		}
	})

	t.Run("bare variables do not leak into an app", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("STS_APPS", "leaky")
		t.Setenv("ID", "999")
		t.Setenv("KMS_LOCATION", "global")
		if _, err := Load(); err == nil {
			t.Error("expected error: STS_APP_LEAKY_* are unset")
		}
	})
}
