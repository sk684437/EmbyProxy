package storage

import (
	"context"
	"encoding/json"
)

const admin2FAConfigKey = "admin:2fa"

// Admin2FAConfig stores the encrypted TOTP secret envelope.
type Admin2FAConfig struct {
	Version      int    `json:"version"`
	Salt         string `json:"salt"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	EnrolledAt   int64  `json:"enrolledAt"`
	LastUsedStep uint64 `json:"lastUsedStep,omitempty"`
}

func (s *Store) GetAdmin2FAConfig(ctx context.Context) (Admin2FAConfig, bool, error) {
	if s == nil {
		return Admin2FAConfig{}, false, nil
	}
	value, ok, err := s.KV().Get(ctx, admin2FAConfigKey)
	if err != nil || !ok {
		return Admin2FAConfig{}, ok, err
	}
	var cfg Admin2FAConfig
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		return Admin2FAConfig{}, true, err
	}
	return cfg, true, nil
}

func (s *Store) SaveAdmin2FAConfig(ctx context.Context, cfg Admin2FAConfig) error {
	return s.KV().Put(ctx, admin2FAConfigKey, cfg)
}

func (s *Store) DeleteAdmin2FAConfig(ctx context.Context) error {
	if s == nil {
		return nil
	}
	return s.KV().Delete(ctx, admin2FAConfigKey)
}
