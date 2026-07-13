package auth

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const testTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestValidateTOTPAtAllowsOnePeriodSkew(t *testing.T) {
	code, err := totp.GenerateCodeCustom(testTOTPSecret, time.Unix(59, 0).UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("code = %q, want RFC-compatible 287082", code)
	}
	for _, second := range []int64{59, 89} {
		_, ok, err := matchTOTPAt(testTOTPSecret, code, time.Unix(second, 0))
		if err != nil || !ok {
			t.Fatalf("validate at %d = %v, %v; want true", second, ok, err)
		}
	}
	_, ok, err := matchTOTPAt(testTOTPSecret, code, time.Unix(119, 0))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("code outside one-period skew was accepted")
	}
}

func TestTOTPSecretEncryptionRoundTripAndWrongToken(t *testing.T) {
	envelope, err := encryptTOTPSecret("strong-admin-token", testTOTPSecret, 1234)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Ciphertext == "" || envelope.Ciphertext == testTOTPSecret {
		t.Fatalf("ciphertext = %q", envelope.Ciphertext)
	}
	secret, err := decryptTOTPSecret("strong-admin-token", envelope)
	if err != nil {
		t.Fatal(err)
	}
	if secret != testTOTPSecret {
		t.Fatalf("secret = %q, want %q", secret, testTOTPSecret)
	}
	if _, err := decryptTOTPSecret("different-admin-token", envelope); err == nil {
		t.Fatal("decrypt with wrong admin token unexpectedly succeeded")
	}
}

func TestTOTPEncryptionKeyDerivationIsStable(t *testing.T) {
	salt := []byte("0123456789abcdef")
	got := hex.EncodeToString(deriveTOTPEncryptionKey("strong-admin-token", salt))
	const want = "957da4ed01eca403fada5de96d6add695b35e90fc4727d5bf28a05f5366a72ec"
	if got != want {
		t.Fatalf("derived key = %q, want %q", got, want)
	}
}

func TestSessionCookieAndAbsoluteExpiry(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	checker := NewChecker(config.Config{AdminToken: "strong-admin-token"}, nil)
	checker.now = func() time.Time { return now }
	req := newAuthRequest(http.MethodPost, "/admin/auth/login")
	session, _, res := checker.Login(req, "strong-admin-token", "")
	if !res.OK {
		t.Fatalf("Login() = %+v", res)
	}
	recorder := httptest.NewRecorder()
	SetSessionCookie(recorder, req, session)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies len = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/admin" || cookie.MaxAge != int(SessionTTL/time.Second) {
		t.Fatalf("cookie = %+v", cookie)
	}
	protected := newAuthRequest(http.MethodPost, "/admin/api")
	protected.AddCookie(cookie)
	if got := checker.Check(protected); !got.OK || got.AuthMethod != "session" {
		t.Fatalf("Check() before expiry = %+v", got)
	}
	now = now.Add(SessionTTL)
	if got := checker.Check(protected); got.OK || got.Status != http.StatusUnauthorized {
		t.Fatalf("Check() at expiry = %+v", got)
	}
}

func TestLogoutOnlyRevokesCurrentSessionFamily(t *testing.T) {
	checker := NewChecker(config.Config{AdminToken: "strong-admin-token"}, nil)
	first, _, firstLogin := checker.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), "strong-admin-token", "")
	if !firstLogin.OK {
		t.Fatalf("first Login() = %+v", firstLogin)
	}
	second, _, secondLogin := checker.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), "strong-admin-token", "")
	if !secondLogin.OK {
		t.Fatalf("second Login() = %+v", secondLogin)
	}

	checker.Logout(requestWithSession(first))
	if got := checker.Check(requestWithSession(first)); got.OK {
		t.Fatalf("logged-out session remained valid: %+v", got)
	}
	if got := checker.Check(requestWithSession(second)); !got.OK {
		t.Fatalf("independent session was revoked: %+v", got)
	}
}

func TestLogoutWithOldCookieRevokesRotatedSession(t *testing.T) {
	store := newAuthTestStore(t)
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	checker := NewChecker(config.Config{AdminToken: "strong-admin-token"}, store)
	checker.now = func() time.Time { return now }

	initial, setupReq, setup := beginTestTwoFactorSetup(t, checker, "strong-admin-token")
	code := currentTOTPCode(t, setup.ManualKey, now)
	rotated, _, confirm := checker.ConfirmTwoFactorSetup(setupReq, initial.Key, setup.SetupID, code)
	if !confirm.OK {
		t.Fatalf("ConfirmTwoFactorSetup() = %+v", confirm)
	}

	checker.Logout(requestWithSession(initial))
	if got := checker.Check(requestWithSession(rotated)); got.OK {
		t.Fatalf("rotated session survived logout with the old cookie: %+v", got)
	}
}

func TestLogoutBlocksPendingTwoFactorConfirmation(t *testing.T) {
	store := newAuthTestStore(t)
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	checker := NewChecker(config.Config{AdminToken: "strong-admin-token"}, store)
	checker.now = func() time.Time { return now }

	initial, setupReq, setup := beginTestTwoFactorSetup(t, checker, "strong-admin-token")
	checker.Logout(requestWithSession(initial))

	code := currentTOTPCode(t, setup.ManualKey, now)
	if _, _, confirm := checker.ConfirmTwoFactorSetup(setupReq, initial.Key, setup.SetupID, code); confirm.Error != ErrorSessionRequired {
		t.Fatalf("confirmation after logout = %+v, want SESSION_REQUIRED", confirm)
	}
	if _, configured, err := store.GetAdmin2FAConfig(context.Background()); err != nil || configured {
		t.Fatalf("2FA config after rejected confirmation = configured %v, err %v", configured, err)
	}
}

func TestDisplayedTwoFactorSetupSurvivesStaleSetupCompletion(t *testing.T) {
	store := newAuthTestStore(t)
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	checker := NewChecker(config.Config{AdminToken: "strong-admin-token"}, store)
	checker.now = func() time.Time { return now }

	// This setup represents the newly opened modal response that is displayed.
	initial, setupReq, displayed := beginTestTwoFactorSetup(t, checker, "strong-admin-token")
	// This setup represents an older request from the closed modal finishing later.
	if _, stale := checker.BeginTwoFactorSetup(setupReq, initial.Key, "strong-admin-token", "", "proxy.example"); !stale.OK {
		t.Fatalf("stale setup = %+v", stale)
	}

	code := currentTOTPCode(t, displayed.ManualKey, now)
	if _, _, confirm := checker.ConfirmTwoFactorSetup(setupReq, initial.Key, displayed.SetupID, code); !confirm.OK {
		t.Fatalf("displayed setup confirmation = %+v", confirm)
	}
}

func TestTOTPFailureLimitReturnsTooManyRequests(t *testing.T) {
	checker := NewChecker(config.Config{AdminToken: "strong-admin-token"}, nil)
	checker.now = func() time.Time { return time.Unix(59, 0) }
	req := newAuthRequest(http.MethodPost, "/admin/auth/login")
	invalidCode := "000000"
	if currentTOTPCode(t, testTOTPSecret, checker.currentTime()) == invalidCode {
		invalidCode = "000001"
	}
	for attempt := 1; attempt <= totpFailureLimit+1; attempt++ {
		_, res := checker.validateTOTPCode(req, testTOTPSecret, invalidCode)
		if attempt <= totpFailureLimit && res.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", attempt, res.Status)
		}
		if attempt == totpFailureLimit+1 && (res.Status != http.StatusTooManyRequests || res.Error != ErrorTooManyRequests) {
			t.Fatalf("attempt %d result = %+v, want 429", attempt, res)
		}
	}
}

func TestVerifyStoredTOTPRejectsBeforeDecrypting(t *testing.T) {
	store := newAuthTestStore(t)
	now := time.Unix(59, 0).UTC()
	if err := store.SaveAdmin2FAConfig(context.Background(), storage.Admin2FAConfig{Version: 999}); err != nil {
		t.Fatal(err)
	}
	checker := NewChecker(config.Config{AdminToken: "strong-admin-token"}, store)
	checker.now = func() time.Time { return now }
	req := newAuthRequest(http.MethodPost, "/admin/auth/login")

	checker.totpMu.Lock()
	totpLocked := true
	defer func() {
		if totpLocked {
			checker.totpMu.Unlock()
		}
	}()
	verify := func(code string) Result {
		result := make(chan Result, 1)
		go func() {
			result <- checker.verifyStoredTOTP(req, code)
		}()
		select {
		case res := <-result:
			return res
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("verification for %q waited on the TOTP mutex", code)
			return Result{}
		}
	}

	if res := verify(""); res.Error != ErrorTOTPRequired {
		t.Fatalf("empty code result = %+v, want TOTP_REQUIRED", res)
	}
	if res := verify("abc"); res.Error != ErrorInvalidCredentials {
		t.Fatalf("malformed code result = %+v, want INVALID_CREDENTIALS", res)
	}
	failureKey := checker.ClientIP(req)
	checker.totpFails.mu.Lock()
	checker.totpFails.entries[failureKey] = failRecord{N: totpFailureLimit, TS: now}
	checker.totpFails.mu.Unlock()
	if res := verify("123456"); res.Error != ErrorTooManyRequests {
		t.Fatalf("limited code result = %+v, want TOO_MANY_REQUESTS", res)
	}
	checker.totpMu.Unlock()
	totpLocked = false
}

func TestTokenCheckWithStateGuardHoldsReadLock(t *testing.T) {
	checker := NewChecker(config.Config{AdminToken: "strong-admin-token"}, nil)
	req := newAuthRequest(http.MethodPost, "/admin/api")
	req.Header.Set("Authorization", "Bearer strong-admin-token")
	res, release := checker.CheckWithStateGuard(req)
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	if !res.OK || res.AuthMethod != "token" {
		t.Fatalf("guarded check = %+v", res)
	}
	if checker.authStateMu.TryLock() {
		checker.authStateMu.Unlock()
		t.Fatal("successful token check did not retain the 2FA state read lock")
	}
	release()
	released = true
	if !checker.authStateMu.TryLock() {
		t.Fatal("2FA state read lock was not released")
	}
	checker.authStateMu.Unlock()
}

func TestTOTPCodeIsConsumedAtomically(t *testing.T) {
	store := newAuthTestStore(t)
	now := time.Unix(59, 0).UTC()
	token := "strong-admin-token"
	envelope, err := encryptTOTPSecret(token, testTOTPSecret, now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAdmin2FAConfig(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	checker := NewChecker(config.Config{AdminToken: token}, store)
	checker.now = func() time.Time { return now }
	code := currentTOTPCode(t, testTOTPSecret, now)

	start := make(chan struct{})
	results := make(chan Result, 2)
	for range 2 {
		go func() {
			<-start
			_, _, res := checker.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), token, code)
			results <- res
		}()
	}
	close(start)

	successes := 0
	replays := 0
	for range 2 {
		res := <-results
		switch {
		case res.OK:
			successes++
		case res.Error == ErrorInvalidCredentials:
			replays++
		default:
			t.Fatalf("unexpected login result = %+v", res)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("successes = %d, replays = %d; want 1, 1", successes, replays)
	}
	stored, configured, err := store.GetAdmin2FAConfig(context.Background())
	if err != nil || !configured {
		t.Fatalf("stored config = configured %v, err %v", configured, err)
	}
	wantStep := uint64(now.Unix() / int64(twoFactorPeriod))
	if stored.LastUsedStep != wantStep {
		t.Fatalf("last used step = %d, want %d", stored.LastUsedStep, wantStep)
	}
}

func TestTwoFactorRebindRevokesConcurrentOldSecretLogin(t *testing.T) {
	store := newAuthTestStore(t)
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	token := "strong-admin-token"
	checker := NewChecker(config.Config{AdminToken: token}, store)
	checker.now = func() time.Time { return now }

	initialSession, initialReq, initialSetup := beginTestTwoFactorSetup(t, checker, token)
	initialCode := currentTOTPCode(t, initialSetup.ManualKey, now)
	activeSession, _, confirm := checker.ConfirmTwoFactorSetup(initialReq, initialSession.Key, initialSetup.SetupID, initialCode)
	if !confirm.OK {
		t.Fatalf("initial confirm = %+v", confirm)
	}

	now = now.Add(time.Duration(twoFactorPeriod) * time.Second)
	rebindReq := requestWithSession(activeSession)
	rebindCode := currentTOTPCode(t, initialSetup.ManualKey, now)
	replacement, rebind := checker.BeginTwoFactorSetup(rebindReq, activeSession.Key, token, rebindCode, "proxy.example")
	if !rebind.OK {
		t.Fatalf("rebind setup = %+v", rebind)
	}
	now = now.Add(time.Duration(twoFactorPeriod) * time.Second)
	oldSecretCode := currentTOTPCode(t, initialSetup.ManualKey, now)
	newSecretCode := currentTOTPCode(t, replacement.ManualKey, now)

	type loginOutcome struct {
		session Session
		result  Result
	}
	type confirmOutcome struct {
		session Session
		result  Result
	}
	loginDone := make(chan loginOutcome, 1)
	confirmDone := make(chan confirmOutcome, 1)
	checker.totpMu.Lock()
	totpLocked := true
	defer func() {
		if totpLocked {
			checker.totpMu.Unlock()
		}
	}()
	go func() {
		session, _, result := checker.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), token, oldSecretCode)
		loginDone <- loginOutcome{session: session, result: result}
	}()
	waitForStateReadLock(t, checker)
	go func() {
		session, _, result := checker.ConfirmTwoFactorSetup(rebindReq, activeSession.Key, replacement.SetupID, newSecretCode)
		confirmDone <- confirmOutcome{session: session, result: result}
	}()
	checker.totpMu.Unlock()
	totpLocked = false

	var loginResult loginOutcome
	select {
	case loginResult = <-loginDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for old-secret login")
	}
	if !loginResult.result.OK {
		t.Fatalf("old-secret login = %+v", loginResult.result)
	}
	var confirmResult confirmOutcome
	select {
	case confirmResult = <-confirmDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for rebind confirmation")
	}
	if !confirmResult.result.OK {
		t.Fatalf("rebind confirm = %+v", confirmResult.result)
	}
	if got := checker.Check(requestWithSession(loginResult.session)); got.OK {
		t.Fatalf("concurrent old-secret session remained valid: %+v", got)
	}
	if got := checker.Check(requestWithSession(confirmResult.session)); !got.OK {
		t.Fatalf("replacement session is invalid: %+v", got)
	}
}

func TestTwoFactorLifecycleRejectsBareAdminToken(t *testing.T) {
	store := newAuthTestStore(t)
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	cfg := config.Config{AdminToken: "strong-admin-token"}
	checker := NewChecker(cfg, store)
	checker.now = func() time.Time { return now }

	loginReq := newAuthRequest(http.MethodPost, "/admin/auth/login")
	initialSession, status, login := checker.Login(loginReq, cfg.AdminToken, "")
	if !login.OK || status.Configured {
		t.Fatalf("initial login = %+v status=%+v", login, status)
	}

	setupReq := requestWithSession(initialSession)
	setup, setupRes := checker.BeginTwoFactorSetup(setupReq, initialSession.Key, cfg.AdminToken, "", "proxy.example")
	if !setupRes.OK || setup.ManualKey == "" || setup.QRCodeDataURL == "" {
		t.Fatalf("BeginTwoFactorSetup() = %+v setup=%+v", setupRes, setup)
	}
	code := currentTOTPCode(t, setup.ManualKey, now)
	confirmedSession, status, confirm := checker.ConfirmTwoFactorSetup(setupReq, initialSession.Key, setup.SetupID, code)
	if !confirm.OK || !status.Configured || !status.Enforced {
		t.Fatalf("ConfirmTwoFactorSetup() = %+v status=%+v", confirm, status)
	}

	bare := newAuthRequest(http.MethodPost, "/admin/api")
	bare.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
	if got := checker.Check(bare); got.OK || got.Status != http.StatusUnauthorized {
		t.Fatalf("bare token Check() = %+v", got)
	}

	_, _, missingCode := checker.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), cfg.AdminToken, "")
	if missingCode.Error != ErrorTOTPRequired {
		t.Fatalf("login without TOTP = %+v", missingCode)
	}
	if _, _, replayed := checker.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), cfg.AdminToken, code); replayed.Error != ErrorInvalidCredentials {
		t.Fatalf("replayed enrollment TOTP = %+v", replayed)
	}
	now = now.Add(time.Duration(twoFactorPeriod) * time.Second)
	loginCode := currentTOTPCode(t, setup.ManualKey, now)
	activeSession, _, activeLogin := checker.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), cfg.AdminToken, loginCode)
	if !activeLogin.OK {
		t.Fatalf("login with TOTP = %+v", activeLogin)
	}
	if activeSession.Key == confirmedSession.Key {
		t.Fatal("new login reused a session")
	}

	disableReq := requestWithSession(activeSession)
	if _, _, replayed := checker.DisableTwoFactor(disableReq, activeSession.Key, cfg.AdminToken, loginCode); replayed.Error != ErrorInvalidCredentials {
		t.Fatalf("replayed login TOTP for disable = %+v", replayed)
	}
	now = now.Add(time.Duration(twoFactorPeriod) * time.Second)
	disableCode := currentTOTPCode(t, setup.ManualKey, now)
	newSession, status, disabled := checker.DisableTwoFactor(disableReq, activeSession.Key, cfg.AdminToken, disableCode)
	if !disabled.OK || status.Configured || newSession.Key == "" {
		t.Fatalf("DisableTwoFactor() = %+v status=%+v", disabled, status)
	}
	if _, configured, err := store.GetAdmin2FAConfig(context.Background()); err != nil || configured {
		t.Fatalf("stored config after disable = configured %v, err %v", configured, err)
	}
}

func TestEmergencyModeAllowsTokenLoginAndRebinding(t *testing.T) {
	store := newAuthTestStore(t)
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	token := "strong-admin-token"

	normal := NewChecker(config.Config{AdminToken: token}, store)
	normal.now = func() time.Time { return now }
	initial, setupReq, setup := beginTestTwoFactorSetup(t, normal, token)
	oldCode := currentTOTPCode(t, setup.ManualKey, now)
	if _, _, res := normal.ConfirmTwoFactorSetup(setupReq, initial.Key, setup.SetupID, oldCode); !res.OK {
		t.Fatal(res.Error)
	}

	emergency := NewChecker(config.Config{AdminToken: token, Admin2FADisabled: true}, store)
	emergency.now = func() time.Time { return now }
	emergencySession, status, emergencyLogin := emergency.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), token, "")
	if !emergencyLogin.OK || !status.Configured || status.Enforced || !status.EmergencyDisabled {
		t.Fatalf("emergency login = %+v status=%+v", emergencyLogin, status)
	}
	rebindReq := requestWithSession(emergencySession)
	replacement, begin := emergency.BeginTwoFactorSetup(rebindReq, emergencySession.Key, token, "", "proxy.example")
	if !begin.OK {
		t.Fatalf("emergency rebind begin = %+v", begin)
	}
	newCode := currentTOTPCode(t, replacement.ManualKey, now)
	if _, status, confirm := emergency.ConfirmTwoFactorSetup(rebindReq, emergencySession.Key, replacement.SetupID, newCode); !confirm.OK || status.Enforced {
		t.Fatalf("emergency rebind confirm = %+v status=%+v", confirm, status)
	}

	restarted := NewChecker(config.Config{AdminToken: token}, store)
	restarted.now = func() time.Time { return now }
	if _, _, missing := restarted.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), token, ""); missing.Error != ErrorTOTPRequired {
		t.Fatalf("normal mode after restart = %+v", missing)
	}
	if _, _, replayed := restarted.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), token, newCode); replayed.Error != ErrorInvalidCredentials {
		t.Fatalf("replayed TOTP after restart = %+v", replayed)
	}
	now = now.Add(time.Duration(twoFactorPeriod) * time.Second)
	freshCode := currentTOTPCode(t, replacement.ManualKey, now)
	if _, _, valid := restarted.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), token, freshCode); !valid.OK {
		t.Fatalf("new TOTP after recovery = %+v", valid)
	}
}

func TestAdminTokenRotationFailsClosedUntilEmergencyMode(t *testing.T) {
	store := newAuthTestStore(t)
	envelope, err := encryptTOTPSecret("old-admin-token", testTOTPSecret, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAdmin2FAConfig(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	rotated := NewChecker(config.Config{AdminToken: "new-admin-token"}, store)
	status, err := rotated.TwoFactorStatus(context.Background())
	if err != nil || !status.Configured || !status.Enforced {
		t.Fatalf("rotated token status = %+v, err %v", status, err)
	}
	bare := newAuthRequest(http.MethodPost, "/admin/api")
	bare.Header.Set("Authorization", "Bearer new-admin-token")
	if res := rotated.Check(bare); res.Status != http.StatusUnauthorized || res.Error != ErrorUnauthorized {
		t.Fatalf("rotated bare token check = %+v", res)
	}
	if _, _, res := rotated.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), "new-admin-token", "123456"); res.Error != ErrorTwoFactorUnavailable {
		t.Fatalf("rotated token login = %+v", res)
	}
	emergency := NewChecker(config.Config{AdminToken: "new-admin-token", Admin2FADisabled: true}, store)
	if _, status, res := emergency.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), "new-admin-token", ""); !res.OK || !status.EmergencyDisabled {
		t.Fatalf("emergency login after rotation = %+v status=%+v", res, status)
	}
}

func newAuthTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func beginTestTwoFactorSetup(t *testing.T, checker *Checker, token string) (Session, *http.Request, TwoFactorSetup) {
	t.Helper()
	session, _, login := checker.Login(newAuthRequest(http.MethodPost, "/admin/auth/login"), token, "")
	if !login.OK {
		t.Fatalf("Login() = %+v", login)
	}
	request := requestWithSession(session)
	setup, result := checker.BeginTwoFactorSetup(request, session.Key, token, "", "proxy.example")
	if !result.OK {
		t.Fatalf("BeginTwoFactorSetup() = %+v", result)
	}
	return session, request, setup
}

func newAuthRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, "https://proxy.example"+path, nil)
	req.RemoteAddr = "203.0.113.10:12345"
	return req
}

func requestWithSession(session Session) *http.Request {
	req := newAuthRequest(http.MethodPost, "/admin/auth/2fa")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.Token})
	return req
}

func currentTOTPCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func waitForStateReadLock(t *testing.T, checker *Checker) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if checker.authStateMu.TryLock() {
			checker.authStateMu.Unlock()
			runtime.Gosched()
			continue
		}
		return
	}
	t.Fatal("timed out waiting for login to hold the 2FA state read lock")
}
