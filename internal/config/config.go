package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port           int    `envconfig:"PORT" default:"8080"`
	Debug          bool   `envconfig:"DEBUG" default:"false"`
	Hostname       string `envconfig:"HOSTNAME" required:"true"`
	AppID          string `envconfig:"APP_ID" required:"true"`
	PrivateKeyPath string `envconfig:"PRIVATE_KEY_PATH" default:""`
}

func Load() (*Config, error) {
	var c Config
	if err := envconfig.Process("STS", &c); err != nil {
		return nil, err
	}

	return &c, nil
}
