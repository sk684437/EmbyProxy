package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"
	"strings"
	"time"

	"embyproxy/internal/storage"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

const (
	twoFactorIssuer            = "EmbyProxy"
	twoFactorSetupTTL          = 10 * time.Minute
	twoFactorEnvelopeV1        = 1
	twoFactorAAD               = "embyproxy:admin:2fa:v1"
	twoFactorSaltSize          = 16
	twoFactorSecretBytes       = 20
	twoFactorPeriod            = 30
	twoFactorSkew              = 1
	twoFactorArgonIterations   = 2
	twoFactorArgonMemoryKiB    = 32 * 1024
	twoFactorArgonParallelism  = 2
	twoFactorEncryptionKeySize = 32
)

type TwoFactorStatus struct {
	Configured        bool  `json:"configured"`
	Enforced          bool  `json:"enforced"`
	EmergencyDisabled bool  `json:"emergencyDisabled"`
	EnrolledAt        int64 `json:"enrolledAt,omitempty"`
}

type TwoFactorSetup struct {
	SetupID       string `json:"setupId"`
	QRCodeDataURL string `json:"qrCodeDataUrl"`
	ManualKey     string `json:"manualKey"`
	Issuer        string `json:"issuer"`
	AccountName   string `json:"accountName"`
	ExpiresAt     int64  `json:"expiresAt"`
}

type pendingSetup struct {
	SessionKey string
	Secret     string
	ExpiresAt  time.Time
}

func (c *Checker) Login(r *http.Request, token, code string) (Session, TwoFactorStatus, Result) {
	if res := c.verifyAdminCredential(r, token); !res.OK {
		return Session{}, TwoFactorStatus{EmergencyDisabled: c.cfg.Admin2FADisabled}, res
	}
	c.authStateMu.RLock()
	defer c.authStateMu.RUnlock()
	status, err := c.twoFactorStatusLocked(r.Context())
	if err != nil {
		return Session{}, status, Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
	}
	if status.Enforced {
		if res := c.verifyStoredTOTP(r, code); !res.OK {
			return Session{}, status, res
		}
	}
	session, err := c.createSession()
	if err != nil {
		return Session{}, status, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	return session, status, Result{OK: true, UID: "admin", Role: "admin", SessionKey: session.Key, AuthMethod: "session"}
}

func (c *Checker) TwoFactorStatus(ctx context.Context) (TwoFactorStatus, error) {
	c.authStateMu.RLock()
	defer c.authStateMu.RUnlock()
	return c.twoFactorStatusLocked(ctx)
}

func (c *Checker) twoFactorStatusLocked(ctx context.Context) (TwoFactorStatus, error) {
	status := TwoFactorStatus{EmergencyDisabled: c.cfg.Admin2FADisabled}
	if c.store == nil {
		return status, nil
	}
	cfg, configured, err := c.store.GetAdmin2FAConfig(ctx)
	status.Configured = configured
	if configured {
		status.EnrolledAt = cfg.EnrolledAt
	}
	if err != nil {
		if c.cfg.Admin2FADisabled {
			status.Configured = true
			return status, nil
		}
		return status, err
	}
	status.Enforced = configured && !c.cfg.Admin2FADisabled
	return status, nil
}

func (c *Checker) BeginTwoFactorSetup(r *http.Request, sessionKey, token, currentCode, accountName string) (TwoFactorSetup, Result) {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return TwoFactorSetup{}, Result{Status: http.StatusUnauthorized, Error: ErrorSessionRequired}
	}
	if res := c.verifyAdminCredential(r, token); !res.OK {
		return TwoFactorSetup{}, res
	}
	c.authStateMu.RLock()
	defer c.authStateMu.RUnlock()
	if _, ok := c.activeSessionFamily(sessionKey); !ok {
		return TwoFactorSetup{}, Result{Status: http.StatusUnauthorized, Error: ErrorSessionRequired}
	}
	configured := false
	if c.store != nil {
		var err error
		_, configured, err = c.store.GetAdmin2FAConfig(r.Context())
		if err != nil && !c.cfg.Admin2FADisabled {
			return TwoFactorSetup{}, Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
		}
	}
	if configured && !c.cfg.Admin2FADisabled {
		if res := c.verifyStoredTOTP(r, currentCode); !res.OK {
			return TwoFactorSetup{}, res
		}
	}
	accountName = normalizeAccountName(accountName)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      twoFactorIssuer,
		AccountName: accountName,
		Period:      twoFactorPeriod,
		SecretSize:  twoFactorSecretBytes,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return TwoFactorSetup{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	image, err := key.Image(256, 256)
	if err != nil {
		return TwoFactorSetup{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	var imageBuffer bytes.Buffer
	if err := png.Encode(&imageBuffer, image); err != nil {
		return TwoFactorSetup{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	setupID, err := randomURLToken(24)
	if err != nil {
		return TwoFactorSetup{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	expiresAt := c.currentTime().Add(twoFactorSetupTTL)
	c.mu.Lock()
	c.cleanupSetupsLocked(c.currentTime())
	// Keep concurrent setup attempts independently confirmable. A stale request
	// can finish after the client has already displayed a newer setup.
	c.setups[setupID] = pendingSetup{SessionKey: sessionKey, Secret: key.Secret(), ExpiresAt: expiresAt}
	c.mu.Unlock()
	return TwoFactorSetup{
		SetupID:       setupID,
		QRCodeDataURL: "data:image/png;base64," + base64.StdEncoding.EncodeToString(imageBuffer.Bytes()),
		ManualKey:     key.Secret(),
		Issuer:        twoFactorIssuer,
		AccountName:   accountName,
		ExpiresAt:     expiresAt.UnixMilli(),
	}, Result{OK: true, UID: "admin", Role: "admin", SessionKey: sessionKey, AuthMethod: "session"}
}

func (c *Checker) ConfirmTwoFactorSetup(r *http.Request, sessionKey, setupID, code string) (Session, TwoFactorStatus, Result) {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusUnauthorized, Error: ErrorSessionRequired}
	}
	c.authStateMu.Lock()
	defer c.authStateMu.Unlock()
	sessionFamily, ok := c.activeSessionFamily(sessionKey)
	if !ok {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusUnauthorized, Error: ErrorSessionRequired}
	}
	c.totpMu.Lock()
	defer c.totpMu.Unlock()
	now := c.currentTime()
	c.mu.Lock()
	c.cleanupSetupsLocked(now)
	setup, ok := c.setups[strings.TrimSpace(setupID)]
	c.mu.Unlock()
	if !ok || setup.SessionKey != sessionKey || !now.Before(setup.ExpiresAt) {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusBadRequest, Error: ErrorSetupExpired}
	}
	step, res := c.validateTOTPCode(r, setup.Secret, code)
	if !res.OK {
		return Session{}, TwoFactorStatus{}, res
	}
	session, err := c.newSession()
	if err != nil {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	enrolledAt := now.UnixMilli()
	envelope, err := encryptTOTPSecret(c.cfg.AdminToken, setup.Secret, enrolledAt)
	if err != nil || c.store == nil {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	envelope.LastUsedStep = step
	if err := c.store.SaveAdmin2FAConfig(r.Context(), envelope); err != nil {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	c.clearFailure(&c.totpFails, c.ClientIP(r))
	c.replaceAllSessionsWith(session, sessionFamily)
	status := TwoFactorStatus{
		Configured:        true,
		Enforced:          !c.cfg.Admin2FADisabled,
		EmergencyDisabled: c.cfg.Admin2FADisabled,
		EnrolledAt:        enrolledAt,
	}
	return session, status, Result{OK: true, UID: "admin", Role: "admin", SessionKey: session.Key, AuthMethod: "session"}
}

func (c *Checker) DisableTwoFactor(r *http.Request, sessionKey, token, currentCode string) (Session, TwoFactorStatus, Result) {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusUnauthorized, Error: ErrorSessionRequired}
	}
	if res := c.verifyAdminCredential(r, token); !res.OK {
		return Session{}, TwoFactorStatus{}, res
	}
	c.authStateMu.Lock()
	defer c.authStateMu.Unlock()
	sessionFamily, ok := c.activeSessionFamily(sessionKey)
	if !ok {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusUnauthorized, Error: ErrorSessionRequired}
	}
	configured := false
	if c.store != nil {
		var err error
		_, configured, err = c.store.GetAdmin2FAConfig(r.Context())
		if err != nil && !c.cfg.Admin2FADisabled {
			return Session{}, TwoFactorStatus{}, Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
		}
	}
	if configured && !c.cfg.Admin2FADisabled {
		if res := c.verifyStoredTOTP(r, currentCode); !res.OK {
			return Session{}, TwoFactorStatus{}, res
		}
	}
	session, err := c.newSession()
	if err != nil || c.store == nil {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	if err := c.store.DeleteAdmin2FAConfig(r.Context()); err != nil {
		return Session{}, TwoFactorStatus{}, Result{Status: http.StatusInternalServerError, Error: "INTERNAL_ERROR"}
	}
	c.replaceAllSessionsWith(session, sessionFamily)
	status := TwoFactorStatus{EmergencyDisabled: c.cfg.Admin2FADisabled}
	return session, status, Result{OK: true, UID: "admin", Role: "admin", SessionKey: session.Key, AuthMethod: "session"}
}

func (c *Checker) verifyAdminCredential(r *http.Request, token string) Result {
	admin := strings.TrimSpace(c.cfg.AdminToken)
	if errText := ValidateAdminToken(admin); errText != "" {
		return Result{Status: http.StatusInternalServerError, Error: errText}
	}
	failureKey := c.ClientIP(r)
	if SafeEqual(strings.TrimSpace(token), admin) {
		if !c.clearFailureIfAllowed(&c.tokenFails, failureKey, adminTokenFailureLimit, authFailureWindow) {
			return Result{Status: http.StatusTooManyRequests, Error: ErrorTooManyRequests}
		}
		return Result{OK: true, UID: "admin", Role: "admin"}
	}
	if c.recordFailure(&c.tokenFails, failureKey, adminTokenFailureLimit, authFailureWindow) {
		return Result{Status: http.StatusTooManyRequests, Error: ErrorTooManyRequests}
	}
	return Result{Status: http.StatusUnauthorized, Error: ErrorInvalidCredentials}
}

func (c *Checker) verifyStoredTOTP(r *http.Request, code string) Result {
	if c.store == nil {
		return Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
	}
	failureKey := c.ClientIP(r)
	if c.failureLimited(&c.totpFails, failureKey, totpFailureLimit, authFailureWindow) {
		return Result{Status: http.StatusTooManyRequests, Error: ErrorTooManyRequests}
	}
	code = normalizeTOTPCode(code)
	if code == "" {
		return Result{Status: http.StatusUnauthorized, Error: ErrorTOTPRequired}
	}
	if !validTOTPCodeFormat(code) {
		return c.invalidTOTPResultForKey(failureKey)
	}
	c.totpMu.Lock()
	defer c.totpMu.Unlock()
	if c.failureLimited(&c.totpFails, failureKey, totpFailureLimit, authFailureWindow) {
		return Result{Status: http.StatusTooManyRequests, Error: ErrorTooManyRequests}
	}

	cfg, configured, err := c.store.GetAdmin2FAConfig(r.Context())
	if err != nil || !configured {
		return Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
	}
	secret, err := decryptTOTPSecret(c.cfg.AdminToken, cfg)
	if err != nil {
		return Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
	}
	step, valid, err := matchTOTPAt(secret, code, c.currentTime())
	if err != nil {
		return Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
	}
	if !valid {
		return c.invalidTOTPResultForKey(failureKey)
	}
	if cfg.LastUsedStep > 0 && step <= cfg.LastUsedStep {
		return c.invalidTOTPResultForKey(failureKey)
	}
	cfg.LastUsedStep = step
	if err := c.store.SaveAdmin2FAConfig(r.Context(), cfg); err != nil {
		return Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
	}
	c.clearFailure(&c.totpFails, failureKey)
	return Result{OK: true, UID: "admin", Role: "admin"}
}

func (c *Checker) validateTOTPCode(r *http.Request, secret, code string) (uint64, Result) {
	code = normalizeTOTPCode(code)
	if code == "" {
		return 0, Result{Status: http.StatusUnauthorized, Error: ErrorTOTPRequired}
	}
	failureKey := c.ClientIP(r)
	if !validTOTPCodeFormat(code) {
		return 0, c.invalidTOTPResultForKey(failureKey)
	}
	step, valid, err := matchTOTPAt(secret, code, c.currentTime())
	if err != nil {
		return 0, Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}
	}
	if valid {
		return step, Result{OK: true, UID: "admin", Role: "admin"}
	}
	return 0, c.invalidTOTPResultForKey(failureKey)
}

func (c *Checker) invalidTOTPResultForKey(key string) Result {
	if c.recordFailure(&c.totpFails, key, totpFailureLimit, authFailureWindow) {
		return Result{Status: http.StatusTooManyRequests, Error: ErrorTooManyRequests}
	}
	return Result{Status: http.StatusUnauthorized, Error: ErrorInvalidCredentials}
}

func matchTOTPAt(secret, code string, now time.Time) (uint64, bool, error) {
	counter := now.UTC().Unix() / int64(twoFactorPeriod)
	counters := []int64{counter}
	for offset := int64(1); offset <= int64(twoFactorSkew); offset++ {
		counters = append(counters, counter+offset)
		if counter >= offset {
			counters = append(counters, counter-offset)
		}
	}
	for _, candidate := range counters {
		valid, err := hotp.ValidateCustom(code, uint64(candidate), secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false, err
		}
		if valid {
			return uint64(candidate), true, nil
		}
	}
	return 0, false, nil
}

func normalizeTOTPCode(code string) string {
	return strings.Join(strings.Fields(code), "")
}

func validTOTPCodeFormat(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func normalizeAccountName(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", ""))
	if value == "" {
		return "admin"
	}
	if len(value) > 160 {
		value = value[:160]
	}
	return "admin@" + value
}

func (c *Checker) cleanupSetupsLocked(now time.Time) {
	for setupID, setup := range c.setups {
		if !now.Before(setup.ExpiresAt) {
			delete(c.setups, setupID)
		}
	}
}

func encryptTOTPSecret(adminToken, secret string, enrolledAt int64) (storage.Admin2FAConfig, error) {
	salt := make([]byte, twoFactorSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return storage.Admin2FAConfig{}, err
	}
	key := deriveTOTPEncryptionKey(adminToken, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return storage.Admin2FAConfig{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return storage.Admin2FAConfig{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return storage.Admin2FAConfig{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), []byte(twoFactorAAD))
	return storage.Admin2FAConfig{
		Version:    twoFactorEnvelopeV1,
		Salt:       base64.RawStdEncoding.EncodeToString(salt),
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
		EnrolledAt: enrolledAt,
	}, nil
}

func decryptTOTPSecret(adminToken string, cfg storage.Admin2FAConfig) (string, error) {
	if cfg.Version != twoFactorEnvelopeV1 {
		return "", fmt.Errorf("unsupported 2fa envelope version")
	}
	salt, err := base64.RawStdEncoding.DecodeString(cfg.Salt)
	if err != nil || len(salt) != twoFactorSaltSize {
		return "", fmt.Errorf("invalid 2fa salt")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(cfg.Nonce)
	if err != nil {
		return "", fmt.Errorf("invalid 2fa nonce")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(cfg.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return "", fmt.Errorf("invalid 2fa ciphertext")
	}
	key := deriveTOTPEncryptionKey(adminToken, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(nonce) != gcm.NonceSize() {
		return "", fmt.Errorf("invalid 2fa nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(twoFactorAAD))
	if err != nil {
		return "", fmt.Errorf("decrypt 2fa secret: %w", err)
	}
	secret := strings.TrimSpace(string(plain))
	if secret == "" {
		return "", fmt.Errorf("empty 2fa secret")
	}
	return secret, nil
}

func deriveTOTPEncryptionKey(adminToken string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(strings.TrimSpace(adminToken)),
		salt,
		twoFactorArgonIterations,
		twoFactorArgonMemoryKiB,
		twoFactorArgonParallelism,
		twoFactorEncryptionKeySize,
	)
}
