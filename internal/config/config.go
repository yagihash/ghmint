package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Port     int    `envconfig:"PORT" default:"8080"`
	Debug    bool   `envconfig:"DEBUG" default:"false"`
	Hostname string `envconfig:"HOSTNAME" required:"true"`
	AppID    string `envconfig:"APP_ID" required:"true"`

	KMSProjectID string `envconfig:"KMS_PROJECT_ID" required:"true"`
	KMSLocation  string `envconfig:"KMS_LOCATION" required:"true"`
	KMSKeyRingID string `envconfig:"KMS_KEYRING_ID" required:"true"`
	KMSKeyID     string `envconfig:"KMS_KEY_ID" required:"true"`
	KMSVersion   string `envconfig:"KMS_VERSION" required:"true"`
}

// KMSKeyName returns the full Cloud KMS crypto key version resource name.
func (c *Config) KMSKeyName() string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		c.KMSProjectID, c.KMSLocation, c.KMSKeyRingID, c.KMSKeyID, c.KMSVersion,
	)
}

func Load() (*Config, error) {
	var c Config
	if err := envconfig.Process("STS", &c); err != nil {
		return nil, err
	}

	return &c, nil
}
