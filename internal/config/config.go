package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Port           int      `envconfig:"STS_PORT" default:"8080"`
	Debug          bool     `envconfig:"STS_DEBUG" default:"false"`
	Audience       string   `envconfig:"STS_AUDIENCE" required:"true"`
	AppID          string   `envconfig:"STS_APP_ID" required:"true"`
	AllowedIssuers []string `envconfig:"STS_ALLOWED_ISSUERS"`

	KMSProjectID  string `envconfig:"STS_KMS_PROJECT_ID" required:"true"`
	KMSLocation   string `envconfig:"STS_KMS_LOCATION" required:"true"`
	KMSKeyRingID  string `envconfig:"STS_KMS_KEYRING_ID" required:"true"`
	KMSKeyID      string `envconfig:"STS_KMS_KEY_ID" required:"true"`
	KMSKeyVersion string `envconfig:"STS_KMS_KEY_VERSION" required:"true"`
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
	if err := envconfig.Process("", &c); err != nil {
		return nil, err
	}

	if _, err := strconv.Atoi(c.KMSKeyVersion); err != nil {
		return nil, fmt.Errorf("STS_KMS_KEY_VERSION must be an integer: %w", err)
	}
	if strings.ContainsAny(c.Audience, "/:") {
		return nil, fmt.Errorf("STS_AUDIENCE must be a plain hostname without scheme (got %q)", c.Audience)
	}

	return &c, nil
}
