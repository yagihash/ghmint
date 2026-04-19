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
	t.Run("all required fields set", func(t *testing.T) {
		t.Setenv("STS_HOSTNAME", "sts.example.com")
		t.Setenv("STS_APP_ID", "123456")
		t.Setenv("STS_KMS_PROJECT_ID", "my-project")
		t.Setenv("STS_KMS_LOCATION", "global")
		t.Setenv("STS_KMS_KEYRING_ID", "my-keyring")
		t.Setenv("STS_KMS_KEY_ID", "my-key")
		t.Setenv("STS_KMS_KEY_VERSION", "1")

		c, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if c.Hostname != "sts.example.com" {
			t.Errorf("Hostname = %q, want %q", c.Hostname, "sts.example.com")
		}
		if c.AppID != "123456" {
			t.Errorf("AppID = %q, want %q", c.AppID, "123456")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		t.Setenv("STS_HOSTNAME", "sts.example.com")
		t.Setenv("STS_APP_ID", "123456")
		t.Setenv("STS_KMS_PROJECT_ID", "my-project")
		t.Setenv("STS_KMS_LOCATION", "global")
		t.Setenv("STS_KMS_KEYRING_ID", "my-keyring")
		t.Setenv("STS_KMS_KEY_ID", "my-key")
		t.Setenv("STS_KMS_KEY_VERSION", "1")
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
		unsetenv(t, "STS_HOSTNAME")
		t.Setenv("STS_APP_ID", "123456")
		t.Setenv("STS_KMS_PROJECT_ID", "my-project")
		t.Setenv("STS_KMS_LOCATION", "global")
		t.Setenv("STS_KMS_KEYRING_ID", "my-keyring")
		t.Setenv("STS_KMS_KEY_ID", "my-key")
		t.Setenv("STS_KMS_KEY_VERSION", "1")

		if _, err := Load(); err == nil {
			t.Error("Load() expected error, got nil")
		}
	})
}
