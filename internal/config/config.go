package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port           int    `envconfig:"PORT" default:"8080"`
	Debug          bool   `envconfig:"DEBUG" default:"false"`
	Hostname       string `envconfig:"HOSTNAME" required:"true"`
	AppID          string `envconfig:"GH_APP_ID" required:"true"`
	PrivateKeyPath string `envconfig:"GH_PRIVATE_KEY_PATH" required:"true"`
}

func Load() (*Config, error) {
	var c Config
	if err := envconfig.Process("", &c); err != nil {
		return nil, err
	}

	return &c, nil
}
