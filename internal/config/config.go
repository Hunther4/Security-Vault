package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	APIURL    string `mapstructure:"api_url"`
	APIKey    string `mapstructure:"api_key"`
	OutputDir string `mapstructure:"output_dir"`
}

func Defaults() *Config {
	return &Config{
		APIURL:    "http://localhost:8000",
		APIKey:    "",
		OutputDir: ".",
	}
}

func Load(cfgPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigName("vault")
	v.SetConfigType("yaml")

	// Only load explicit config file path if provided
	if cfgPath != "" {
		v.SetConfigFile(cfgPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("config error: %w", err)
		}
	}

	// Env vars always work: VAULT_API_URL, VAULT_API_KEY, VAULT_OUTPUT_DIR
	v.SetEnvPrefix("VAULT")
	v.AutomaticEnv()

	// Defaults
	v.SetDefault("api_url", "http://localhost:8000")
	v.SetDefault("output_dir", ".")

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return cfg, nil
}

func InitConfig() error {
	cfg := Defaults()

	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(configDir, "security-vault")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	path := filepath.Join(dir, "vault.yaml")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config already exists: %s", path)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf(`# Security-Vault CLI configuration
api_url: %s
api_key: ""
output_dir: "."
`, cfg.APIURL))
	return err
}
