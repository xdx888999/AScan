package config

import (
	"errors"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

type ruleCfg struct {
	Severity string `yaml:"severity"`
	Enabled  *bool  `yaml:"enabled"`
}

type Config struct {
	Rules  map[string]ruleCfg `yaml:"rules"`
	Ignore []string           `yaml:"ignore"`
}

// Load 读取配置；文件不存在时返回空配置（默认全部启用、无忽略）。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Enabled(ruleID string) bool {
	if c == nil || c.Rules == nil {
		return true
	}
	rc, ok := c.Rules[ruleID]
	if !ok || rc.Enabled == nil {
		return true
	}
	return *rc.Enabled
}

// SeverityOverride 返回配置里指定的严重度字符串（info/warn/high/critical）。
func (c *Config) SeverityOverride(ruleID string) (string, bool) {
	if c == nil || c.Rules == nil {
		return "", false
	}
	rc, ok := c.Rules[ruleID]
	if !ok || rc.Severity == "" {
		return "", false
	}
	return rc.Severity, true
}

func (c *Config) Ignored() []string {
	if c == nil {
		return nil
	}
	return c.Ignore
}
