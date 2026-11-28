package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"github.com/yagihash/ghmint/pkg/verifier"
)

// appNameRe is the allowed form of an additional App name. It maps cleanly to
// environment variable names (upper-cased, "-" -> "_").
var appNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// AppConfig describes one GitHub App and the KMS key that signs its JWTs.
type AppConfig struct {
	Name          string
	AppID         string
	KMSProjectID  string
	KMSLocation   string
	KMSKeyRingID  string
	KMSKeyID      string
	KMSKeyVersion string
}

// KMSKeyName returns the full Cloud KMS crypto key version resource name.
func (a AppConfig) KMSKeyName() string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		a.KMSProjectID, a.KMSLocation, a.KMSKeyRingID, a.KMSKeyID, a.KMSKeyVersion,
	)
}

type Config struct {
	Port           int      `envconfig:"PORT" default:"8080"`
	Debug          bool     `envconfig:"DEBUG" default:"false"`
	Audience       string   `envconfig:"AUDIENCE" required:"true"`
	AppID          string   `envconfig:"APP_ID" required:"true"`
	AllowedIssuers []string `envconfig:"ALLOWED_ISSUERS" default:"https://token.actions.githubusercontent.com"`
	WebhookSecret  string   `envconfig:"WEBHOOK_SECRET"`
	// ExtraApps lists the names of additional GitHub Apps from STS_APPS
	// (comma-separated). Each name N is configured by STS_APP_<N>_ID and
	// STS_APP_<N>_KMS_*. It is read in Load with os.LookupEnv, not envconfig,
	// which would fall back to an unprefixed APPS variable.
	ExtraApps []string `ignored:"true"`

	KMSProjectID  string `envconfig:"KMS_PROJECT_ID" required:"true"`
	KMSLocation   string `envconfig:"KMS_LOCATION" required:"true"`
	KMSKeyRingID  string `envconfig:"KMS_KEYRING_ID" required:"true"`
	KMSKeyID      string `envconfig:"KMS_KEY_ID" required:"true"`
	KMSKeyVersion string `envconfig:"KMS_KEY_VERSION" required:"true"`

	// Apps is derived by Load: the "default" App (STS_APP_ID, STS_KMS_*)
	// followed by the extra Apps listed in STS_APPS, in that order.
	Apps []AppConfig `ignored:"true"`
}

// AppNames returns the names of all registered Apps, "default" first.
func (c *Config) AppNames() []string {
	names := make([]string, 0, len(c.Apps))
	for _, a := range c.Apps {
		names = append(names, a.Name)
	}
	return names
}

// KMSKeyName returns the full Cloud KMS crypto key version resource name.
func (c *Config) KMSKeyName() string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		c.KMSProjectID, c.KMSLocation, c.KMSKeyRingID, c.KMSKeyID, c.KMSKeyVersion,
	)
}

func Load() (*Config, error) {
	var c Config
	if err := envconfig.Process("STS", &c); err != nil {
		return nil, err
	}

	if _, err := strconv.Atoi(c.KMSKeyVersion); err != nil {
		return nil, fmt.Errorf("STS_KMS_KEY_VERSION must be an integer: %w", err)
	}
	if v := os.Getenv("STS_APPS"); strings.TrimSpace(v) != "" {
		c.ExtraApps = strings.Split(v, ",")
	}
	apps, err := loadApps(&c)
	if err != nil {
		return nil, err
	}
	c.Apps = apps
	if strings.ContainsAny(c.Audience, "/:") {
		return nil, fmt.Errorf("STS_AUDIENCE must be a plain hostname without scheme (got %q)", c.Audience)
	}
	if len(c.AllowedIssuers) == 0 {
		return nil, fmt.Errorf("STS_ALLOWED_ISSUERS must not be empty: specify at least one OIDC issuer URL")
	}

	return &c, nil
}

// loadApps builds the App list: the legacy STS_APP_ID/STS_KMS_* pair is the
// "default" App, and each name in STS_APPS adds one more.
//
// Per-App variables are read with os.LookupEnv rather than envconfig because
// envconfig falls back to the unprefixed key (e.g. a bare ID), which would
// let an unrelated variable leak into an App's settings.
func loadApps(c *Config) ([]AppConfig, error) {
	apps := []AppConfig{{
		Name:          verifier.DefaultApp,
		AppID:         c.AppID,
		KMSProjectID:  c.KMSProjectID,
		KMSLocation:   c.KMSLocation,
		KMSKeyRingID:  c.KMSKeyRingID,
		KMSKeyID:      c.KMSKeyID,
		KMSKeyVersion: c.KMSKeyVersion,
	}}

	seenName := map[string]bool{verifier.DefaultApp: true}
	seenEnv := map[string]string{}
	for _, name := range c.ExtraApps {
		name = strings.TrimSpace(name)
		if name == verifier.DefaultApp {
			return nil, fmt.Errorf("STS_APPS must not contain %q: it is configured by STS_APP_ID and STS_KMS_*", name)
		}
		if !appNameRe.MatchString(name) {
			return nil, fmt.Errorf("STS_APPS: invalid app name %q (must match %s)", name, appNameRe)
		}
		if seenName[name] {
			return nil, fmt.Errorf("STS_APPS: duplicate app name %q", name)
		}
		seenName[name] = true

		prefix := "STS_APP_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
		if other, ok := seenEnv[prefix]; ok {
			return nil, fmt.Errorf("STS_APPS: app names %q and %q map to the same variables (%s*)", other, name, prefix)
		}
		seenEnv[prefix] = name

		a := AppConfig{Name: name}
		var missing []string
		for _, f := range []struct {
			suffix string
			dst    *string
		}{
			{"ID", &a.AppID},
			{"KMS_PROJECT_ID", &a.KMSProjectID},
			{"KMS_LOCATION", &a.KMSLocation},
			{"KMS_KEYRING_ID", &a.KMSKeyRingID},
			{"KMS_KEY_ID", &a.KMSKeyID},
			{"KMS_KEY_VERSION", &a.KMSKeyVersion},
		} {
			v, ok := os.LookupEnv(prefix + f.suffix)
			if !ok || v == "" {
				missing = append(missing, prefix+f.suffix)
				continue
			}
			*f.dst = v
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("app %q: required variables not set: %s", name, strings.Join(missing, ", "))
		}
		if _, err := strconv.Atoi(a.KMSKeyVersion); err != nil {
			return nil, fmt.Errorf("%sKMS_KEY_VERSION must be an integer: %w", prefix, err)
		}
		apps = append(apps, a)
	}
	return apps, nil
}
