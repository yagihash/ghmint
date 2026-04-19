package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Port           int      `envconfig:"PORT" default:"8080"`
	Debug          bool     `envconfig:"DEBUG" default:"false"`
	Hostname       string   `envconfig:"HOSTNAME"`
	AppID          string   `envconfig:"APP_ID"`
	AllowedIssuers []string `envconfig:"ALLOWED_ISSUERS"`

	KMSProjectID  string `envconfig:"KMS_PROJECT_ID"`
	KMSLocation   string `envconfig:"KMS_LOCATION"`
	KMSKeyRingID  string `envconfig:"KMS_KEYRING_ID"`
	KMSKeyID      string `envconfig:"KMS_KEY_ID"`
	KMSKeyVersion string `envconfig:"KMS_KEY_VERSION"`
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

	var errs []error
	if c.Hostname == "" {
		errs = append(errs, errors.New("STS_HOSTNAME is required"))
	}
	if c.AppID == "" {
		errs = append(errs, errors.New("STS_APP_ID is required"))
	}
	if c.KMSProjectID == "" {
		errs = append(errs, errors.New("STS_KMS_PROJECT_ID is required"))
	}
	if c.KMSLocation == "" {
		errs = append(errs, errors.New("STS_KMS_LOCATION is required"))
	}
	if c.KMSKeyRingID == "" {
		errs = append(errs, errors.New("STS_KMS_KEYRING_ID is required"))
	}
	if c.KMSKeyID == "" {
		errs = append(errs, errors.New("STS_KMS_KEY_ID is required"))
	}
	if c.KMSKeyVersion == "" {
		errs = append(errs, errors.New("STS_KMS_KEY_VERSION is required"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	if _, err := strconv.Atoi(c.KMSKeyVersion); err != nil {
		return nil, fmt.Errorf("STS_KMS_KEY_VERSION must be an integer: %w", err)
	}
	if strings.ContainsAny(c.Hostname, "/:") {
		return nil, fmt.Errorf("STS_HOSTNAME must be a plain hostname without scheme (got %q)", c.Hostname)
	}

	return &c, nil
}
