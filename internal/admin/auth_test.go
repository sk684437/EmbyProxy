package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"embyproxy/internal/auth"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"

	"github.com/pquerna/otp/totp"
)

func TestAuthRoutesLoginStatusAndLogout(t *testing.T) {
	handler := newAuthTestHandler(t, config.Config{AdminToken: "strong-admin-token"})

	login := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/login", map[string]any{"token": "strong-admin-token"}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", login.Code, login.Body.String())
	}
	if got := login.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("login Cache-Control = %q, want no-store", got)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != auth.SessionCookieName || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("login cookies = %+v", cookies)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "https://proxy.example/admin/auth/status", nil)
	statusReq.AddCookie(cookies[0])
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK || !strings.Contains(statusRec.Body.String(), `"authenticated":true`) {
		t.Fatalf("status = %d body=%s", statusRec.Code, statusRec.Body.String())
	}

	api := serveAdminJSON(t, handler, http.MethodPost, "/admin/api", map[string]any{"action": "list"}, cookies[0])
	if api.Code != http.StatusOK || !strings.Contains(api.Body.String(), `"ok":true`) {
		t.Fatalf("api = %d body=%s", api.Code, api.Body.String())
	}

	logout := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/logout", map[string]any{}, cookies[0])
	if logout.Code != http.StatusOK {
		t.Fatalf("logout = %d body=%s", logout.Code, logout.Body.String())
	}
	statusReq = httptest.NewRequest(http.MethodGet, "https://proxy.example/admin/auth/status", nil)
	statusReq.AddCookie(cookies[0])
	statusRec = httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusUnauthorized {
		t.Fatalf("status after logout = %d body=%s", statusRec.Code, statusRec.Body.String())
	}
}

func TestAuthRoutesCompleteTwoFactorEnrollment(t *testing.T) {
	handler := newAuthTestHandler(t, config.Config{AdminToken: "strong-admin-token"})
	setup := beginAuthRouteTwoFactorSetup(t, handler)
	code, err := totp.GenerateCode(setup.manualKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirm := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/2fa/confirm", map[string]any{"setupId": setup.setupID, "code": code}, setup.cookie)
	if confirm.Code != http.StatusOK || !strings.Contains(confirm.Body.String(), `"enforced":true`) {
		t.Fatalf("confirm = %d body=%s", confirm.Code, confirm.Body.String())
	}

	bare := serveAdminJSONWithHeaders(t, handler, http.MethodPost, "/admin/api", map[string]any{"action": "list"}, map[string]string{
		"Authorization": "Bearer strong-admin-token",
	})
	if bare.Code != http.StatusUnauthorized {
		t.Fatalf("bare token api = %d body=%s", bare.Code, bare.Body.String())
	}
	missingCode := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/login", map[string]any{"token": "strong-admin-token"}, nil)
	if missingCode.Code != http.StatusUnauthorized || !strings.Contains(missingCode.Body.String(), auth.ErrorTOTPRequired) {
		t.Fatalf("login without code = %d body=%s", missingCode.Code, missingCode.Body.String())
	}
	replayed := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/login", map[string]any{"token": "strong-admin-token", "code": code}, nil)
	if replayed.Code != http.StatusUnauthorized || !strings.Contains(replayed.Body.String(), auth.ErrorInvalidCredentials) {
		t.Fatalf("replayed login code = %d body=%s", replayed.Code, replayed.Body.String())
	}
	nextCode, err := totp.GenerateCode(setup.manualKey, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	valid := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/login", map[string]any{"token": "strong-admin-token", "code": nextCode}, nil)
	if valid.Code != http.StatusOK {
		t.Fatalf("login with next code = %d body=%s", valid.Code, valid.Body.String())
	}
}

func TestAuthRoutesRejectCrossSitePOST(t *testing.T) {
	handler := newAuthTestHandler(t, config.Config{AdminToken: "strong-admin-token"})
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/admin/auth/login", bytes.NewReader([]byte(`{"token":"strong-admin-token"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), auth.ErrorCrossSiteRequest) {
		t.Fatalf("cross-site login = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestValidAdminOriginWithReverseProxyPort(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		origin    string
		fetchSite string
		proto     string
		want      bool
	}{
		{
			name:      "proxy strips external port",
			host:      "proxy.example",
			origin:    "https://proxy.example:8443",
			fetchSite: "same-origin",
			proto:     "https",
			want:      true,
		},
		{
			name:      "same-site request cannot use port fallback",
			host:      "proxy.example",
			origin:    "https://proxy.example:8443",
			fetchSite: "same-site",
			proto:     "https",
			want:      false,
		},
		{
			name:      "explicit backend port cannot use fallback",
			host:      "proxy.example:443",
			origin:    "https://proxy.example:8443",
			fetchSite: "same-origin",
			proto:     "https",
			want:      false,
		},
		{
			name:      "different hostname is rejected",
			host:      "proxy.example",
			origin:    "https://evil.example:8443",
			fetchSite: "same-origin",
			proto:     "https",
			want:      false,
		},
		{
			name:      "direct request cannot use port fallback",
			host:      "proxy.example",
			origin:    "http://proxy.example:8080",
			fetchSite: "same-origin",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://"+tt.host+"/admin/auth/login", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			if tt.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.proto)
			}

			if got := validAdminOrigin(req); got != tt.want {
				t.Fatalf("validAdminOrigin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdminAPIRechecksTokenAfterReadingBody(t *testing.T) {
	handler := newAuthTestHandler(t, config.Config{AdminToken: "strong-admin-token"})
	setup := beginAuthRouteTwoFactorSetup(t, handler)

	body := newGatedRequestBody(`{"action":"list"}`)
	bodyReleased := false
	defer func() {
		if !bodyReleased {
			close(body.release)
		}
	}()
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/admin/api", body)
	req.Header.Set("Authorization", "Bearer strong-admin-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://proxy.example")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rec, req)
		close(done)
	}()
	select {
	case <-body.started:
	case <-time.After(2 * time.Second):
		t.Fatal("admin API did not start reading the request body")
	}

	code, err := totp.GenerateCode(setup.manualKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirm := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/2fa/confirm", map[string]any{"setupId": setup.setupID, "code": code}, setup.cookie)
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm = %d body=%s", confirm.Code, confirm.Body.String())
	}
	close(body.release)
	bodyReleased = true
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("admin API did not finish after releasing the request body")
	}
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), auth.ErrorUnauthorized) {
		t.Fatalf("admin API after enabling 2FA = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminAPIReleasesAuthStateBeforeWritingResponse(t *testing.T) {
	handler := newAuthTestHandler(t, config.Config{AdminToken: "strong-admin-token"})

	loginReq := httptest.NewRequest(http.MethodPost, "https://proxy.example/admin/auth/login", nil)
	session, _, login := handler.checker.Login(loginReq, "strong-admin-token", "")
	if !login.OK {
		t.Fatalf("Login() = %+v", login)
	}
	setupReq := httptest.NewRequest(http.MethodPost, "https://proxy.example/admin/auth/2fa/setup", nil)
	setupReq.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.Token})
	setup, begin := handler.checker.BeginTwoFactorSetup(setupReq, session.Key, "strong-admin-token", "", "proxy.example")
	if !begin.OK {
		t.Fatalf("BeginTwoFactorSetup() = %+v", begin)
	}

	writer := newBlockingWriteResponseWriter()
	t.Cleanup(writer.releaseWrite)
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/admin/api", bytes.NewBufferString(`{"action":"list"}`))
	req.Header.Set("Authorization", "Bearer strong-admin-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://proxy.example")
	apiDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(writer, req)
		close(apiDone)
	}()
	select {
	case <-writer.writeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("admin API did not reach the response write")
	}

	code, err := totp.GenerateCode(setup.ManualKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirmDone := make(chan auth.Result, 1)
	go func() {
		_, _, result := handler.checker.ConfirmTwoFactorSetup(setupReq, session.Key, setup.SetupID, code)
		confirmDone <- result
	}()
	select {
	case result := <-confirmDone:
		if !result.OK {
			t.Fatalf("ConfirmTwoFactorSetup() = %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("2FA confirmation waited for the admin API client to read its response")
	}

	writer.releaseWrite()
	select {
	case <-apiDone:
	case <-time.After(2 * time.Second):
		t.Fatal("admin API did not finish after releasing the response writer")
	}
}

func TestLogStreamsStopWhenTwoFactorSetupInvalidatesAuthorization(t *testing.T) {
	handler := newAuthTestHandler(t, config.Config{AdminToken: "strong-admin-token"})

	loginReq := httptest.NewRequest(http.MethodPost, "https://proxy.example/admin/auth/login", nil)
	session, _, login := handler.checker.Login(loginReq, "strong-admin-token", "")
	if !login.OK {
		t.Fatalf("Login() = %+v", login)
	}
	setupReq := httptest.NewRequest(http.MethodPost, "https://proxy.example/admin/auth/2fa/setup", nil)
	setupReq.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.Token})
	setup, begin := handler.checker.BeginTwoFactorSetup(setupReq, session.Key, "strong-admin-token", "", "proxy.example")
	if !begin.OK {
		t.Fatalf("BeginTwoFactorSetup() = %+v", begin)
	}

	type activeStream struct {
		name      string
		connected <-chan struct{}
		done      <-chan struct{}
	}
	streams := make([]activeStream, 0, 2)
	for _, credential := range []string{"session", "token"} {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		req := httptest.NewRequest(http.MethodGet, "https://proxy.example/admin/logs/stream", nil).WithContext(ctx)
		switch credential {
		case "session":
			req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.Token})
		case "token":
			req.Header.Set("Authorization", "Bearer strong-admin-token")
		}
		writer := newLogStreamResponseWriter()
		done := make(chan struct{})
		go func() {
			handler.ServeHTTP(writer, req)
			close(done)
		}()
		streams = append(streams, activeStream{name: credential, connected: writer.connected, done: done})
	}
	for _, stream := range streams {
		select {
		case <-stream.connected:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s log stream did not connect", stream.name)
		}
	}

	code, err := totp.GenerateCode(setup.ManualKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, confirm := handler.checker.ConfirmTwoFactorSetup(setupReq, session.Key, setup.SetupID, code); !confirm.OK {
		t.Fatalf("ConfirmTwoFactorSetup() = %+v", confirm)
	}
	handler.log.Info("security", "2FA changed", nil)

	for _, stream := range streams {
		select {
		case <-stream.done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s log stream stayed open after authorization was invalidated", stream.name)
		}
	}
}

func TestAuthRoutesSuppressTrafficCapture(t *testing.T) {
	cwd := t.TempDir()
	store, err := storage.New(filepath.Join(cwd, "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	system := storage.DefaultSystemConfig()
	system.TrafficCaptureEnabled = true
	if err := store.SaveSystemConfig(context.Background(), system); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{CWD: cwd, AdminToken: "strong-admin-token"}
	log := logging.New("silent", false)
	handler := New(cfg, store, auth.NewChecker(cfg, store), nil, log, nil)
	recorder := capture.New(cfg, store, log)
	suppressed := false
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/admin/auth/login", bytes.NewReader([]byte(`{"token":"strong-admin-token"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://proxy.example")
	rec := httptest.NewRecorder()
	recorder.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		suppressed = capture.Suppressed(r)
	})).ServeHTTP(rec, req)
	if !suppressed {
		t.Fatal("auth request was not suppressed from traffic capture")
	}
}

func indexFunctionBlock(t *testing.T, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(indexHTML, startMarker)
	if start < 0 {
		t.Fatalf("indexHTML missing function marker %q", startMarker)
	}
	tail := indexHTML[start:]
	end := strings.Index(tail, endMarker)
	if end < 0 {
		t.Fatalf("indexHTML function %q is incomplete", startMarker)
	}
	return tail[:end]
}

func assertContainsAll(t *testing.T, value string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			t.Fatalf("value missing %q:\n%s", fragment, value)
		}
	}
}

func assertOrdered(t *testing.T, value string, fragments ...string) {
	t.Helper()
	offset := 0
	for _, fragment := range fragments {
		index := strings.Index(value[offset:], fragment)
		if index < 0 {
			t.Fatalf("value missing ordered fragment %q:\n%s", fragment, value)
		}
		offset += index + len(fragment)
	}
}

func TestAdminIndexUsesConditionalTokenPersistenceAndTwoFactorUI(t *testing.T) {
	wants := []string{
		`localStorage.getItem('ep_token')`,
		`persistTokenForStatus(token, r.twoFactor)`,
		`if (AUTH_STATUS.configured) clearSavedToken()`,
		`function acceptRotatedSession(twoFactor)`,
		`id="twoFactorCard"`,
		`id="twoFactorQRCode"`,
		`/admin/auth/2fa/confirm`,
		`credentials: 'same-origin'`,
	}
	for _, want := range wants {
		if !strings.Contains(indexHTML, want) {
			t.Fatalf("indexHTML missing %q", want)
		}
	}
	if strings.Contains(indexHTML, `'Authorization': 'Bearer '`) {
		t.Fatal("indexHTML still sends the saved admin token on every API request")
	}
	accessStart := strings.Index(indexHTML, `id="config-access"`)
	cardStart := strings.Index(indexHTML, `id="twoFactorCard"`)
	operationsStart := strings.Index(indexHTML, `id="config-ops"`)
	if accessStart < 0 || cardStart < accessStart || operationsStart < cardStart {
		t.Fatalf("2FA card is not inside the security settings group: access=%d card=%d operations=%d", accessStart, cardStart, operationsStart)
	}
}

func TestAdminIndexDropsResponsesFromOldAuthenticationGeneration(t *testing.T) {
	block := indexFunctionBlock(t, `async function api(action, data = {})`, "\n}\n\nfunction handleSessionAuthFailure")
	assertOrdered(t, block,
		`if (generation !== authGeneration) return { ok: false, error: '', _status: 401, _stale: true };`,
		`handleSessionAuthFailure(r, generation)`,
		`return r;`,
	)
}

func TestAdminIndexOnlyClearsLocalStateAfterSuccessfulLogout(t *testing.T) {
	block := indexFunctionBlock(t, `async function doLogout()`, "\n}\n\nfunction showLogin")
	guard := strings.Index(block, `if (!r.ok)`)
	clearState := strings.Index(block, `clearSavedToken()`)
	if guard < 0 || clearState < 0 || guard > clearState || !strings.Contains(block[guard:clearState], `return;`) {
		t.Fatalf("doLogout() must return on failure before clearing local state:\n%s", block)
	}
}

func TestAdminIndexLoginGuards(t *testing.T) {
	if !strings.Contains(indexHTML, `let authGeneration = 0;`) {
		t.Fatal("indexHTML is missing the authentication generation")
	}
	restoreBlock := indexFunctionBlock(t, `async function restoreSession()`, "\n}\n\nasync function doLogin")
	loginBlock := indexFunctionBlock(t, `async function doLogin()`, "\n}\n\ndocument.getElementById('tokenInput')")

	t.Run("stale session restoration", func(t *testing.T) {
		assertContainsAll(t, restoreBlock, `const generation = ++authGeneration;`, `if (auto.ok)`)
		if strings.Count(restoreBlock, `if (generation !== authGeneration) return;`) < 2 {
			t.Fatalf("restoreSession() does not guard both asynchronous responses:\n%s", restoreBlock)
		}
		if strings.Contains(restoreBlock, `auto.ok &&`) {
			t.Fatalf("restoreSession() does not accept a successful emergency-mode login:\n%s", restoreBlock)
		}
		assertContainsAll(t, loginBlock, `const generation = ++authGeneration;`, `if (generation !== authGeneration) return;`)
	})

	t.Run("serialized submissions", func(t *testing.T) {
		assertContainsAll(t, indexHTML, `id="loginButton"`, `let loginInFlight = false;`)
		assertOrdered(t, loginBlock,
			`if (loginInFlight) return;`,
			`loginInFlight = true;`,
			`button.disabled = true;`,
			`const r = await authFetch('/admin/auth/login'`,
			`finally {`,
			`loginInFlight = false;`,
			`button.disabled = false;`,
		)
	})
}

func TestAdminIndexStopsProtectedUIAfterSessionFailure(t *testing.T) {
	t.Run("reset protected UI", func(t *testing.T) {
		showLogin := indexFunctionBlock(t, `function showLogin(message = '')`, "\n}\n\nfunction resetProtectedUI")
		assertContainsAll(t, showLogin, `resetProtectedUI();`)
	})

	for _, tt := range []struct {
		name         string
		startMarker  string
		endMarker    string
		statusGuard  string
		failureGuard string
		showModal    string
	}{
		{
			name:         "config modal",
			startMarker:  `async function openConfigModal()`,
			endMarker:    "\n}\n\nfunction closeConfigModal",
			statusGuard:  `if (!await refreshAuthStatus(false)) return;`,
			failureGuard: `if (!r.ok || !r.config)`,
			showModal:    `showModal('configModal')`,
		},
		{
			name:         "Telegram modal",
			startMarker:  `async function openTgModal()`,
			endMarker:    "\n}\n\nfunction closeTgModal",
			failureGuard: `if (!r.ok || !r.config)`,
			showModal:    `showModal('tgModal')`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			block := indexFunctionBlock(t, tt.startMarker, tt.endMarker)
			if tt.statusGuard != "" {
				assertOrdered(t, block, tt.statusGuard, tt.failureGuard, tt.showModal)
			} else {
				assertOrdered(t, block, tt.failureGuard, tt.showModal)
			}
			guard := strings.Index(block, tt.failureGuard)
			showModal := strings.Index(block, tt.showModal)
			if !strings.Contains(block[guard:showModal], `return;`) {
				t.Fatalf("%s can open after an authentication failure:\n%s", tt.name, block)
			}
		})
	}
}

func TestAdminIndexIgnoresClosedTwoFactorResponses(t *testing.T) {
	assertContainsAll(t, indexHTML, `id="twoFactorConfirmBtn"`, `let twoFactorFlowGeneration = 0;`)
	closeBlock := indexFunctionBlock(t, `function closeTwoFactorModal()`, "\n}\n\nasync function submitTwoFactorReauth")
	assertContainsAll(t, closeBlock, `twoFactorFlowGeneration++;`)

	submitBlock := indexFunctionBlock(t, `async function submitTwoFactorReauth()`, "\n}\n\nasync function confirmTwoFactorSetup")
	if !strings.Contains(submitBlock, `const flowGeneration = twoFactorFlowGeneration;`) || strings.Count(submitBlock, `flowGeneration !== twoFactorFlowGeneration`) < 2 {
		t.Fatalf("submitTwoFactorReauth() does not reject stale modal responses:\n%s", submitBlock)
	}
	disableStatus := strings.Index(submitBlock, `acceptRotatedSession(r.twoFactor);`)
	disableFlowGuard := strings.Index(submitBlock, `if (flowGeneration !== twoFactorFlowGeneration)`)
	if disableStatus < 0 || disableFlowGuard < disableStatus {
		t.Fatalf("submitTwoFactorReauth() does not accept the rotated disable session before the modal guard:\n%s", submitBlock)
	}

	confirmBlock := indexFunctionBlock(t, `async function confirmTwoFactorSetup()`, "\n}\n\nasync function openConfigModal")
	if !strings.Contains(confirmBlock, `button.disabled = true;`) || !strings.Contains(confirmBlock, `flowGeneration !== twoFactorFlowGeneration`) {
		t.Fatalf("confirmTwoFactorSetup() does not serialize or invalidate confirmation:\n%s", confirmBlock)
	}
	confirmStatus := strings.Index(confirmBlock, `if (r.ok) acceptRotatedSession(r.twoFactor);`)
	confirmFlowGuard := strings.Index(confirmBlock, `if (flowGeneration !== twoFactorFlowGeneration)`)
	if confirmStatus < 0 || confirmFlowGuard < confirmStatus {
		t.Fatalf("confirmTwoFactorSetup() does not accept the rotated setup session before the modal guard:\n%s", confirmBlock)
	}
	rotationBlock := indexFunctionBlock(t, `function acceptRotatedSession(twoFactor)`, "\n}\n\nfunction persistTokenForStatus")
	assertContainsAll(t, rotationBlock, `authGeneration++;`)
}

type authRouteTwoFactorSetup struct {
	cookie    *http.Cookie
	setupID   string
	manualKey string
}

func beginAuthRouteTwoFactorSetup(t *testing.T, handler *Handler) authRouteTwoFactorSetup {
	t.Helper()
	login := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/login", map[string]any{"token": "strong-admin-token"}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login = %d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %+v", cookies)
	}
	setupRec := serveAdminJSON(t, handler, http.MethodPost, "/admin/auth/2fa/setup", map[string]any{"token": "strong-admin-token"}, cookies[0])
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup = %d body=%s", setupRec.Code, setupRec.Body.String())
	}
	var body struct {
		Setup struct {
			SetupID   string `json:"setupId"`
			ManualKey string `json:"manualKey"`
		} `json:"setup"`
	}
	if err := json.Unmarshal(setupRec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return authRouteTwoFactorSetup{
		cookie:    cookies[0],
		setupID:   body.Setup.SetupID,
		manualKey: body.Setup.ManualKey,
	}
}

func newAuthTestHandler(t *testing.T, cfg config.Config) *Handler {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := logging.New("silent", false)
	checker := auth.NewChecker(cfg, store)
	return New(cfg, store, checker, nil, log, nil)
}

func serveAdminJSON(t *testing.T, handler *Handler, method, path string, body map[string]any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{}
	if cookie != nil {
		headers["Cookie"] = cookie.String()
	}
	return serveAdminJSONWithHeaders(t, handler, method, path, body, headers)
}

func serveAdminJSONWithHeaders(t *testing.T, handler *Handler, method, path string, body map[string]any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, "https://proxy.example"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://proxy.example")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

type gatedRequestBody struct {
	reader  *strings.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGatedRequestBody(value string) *gatedRequestBody {
	return &gatedRequestBody{
		reader:  strings.NewReader(value),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *gatedRequestBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.reader.Read(p)
}

func (b *gatedRequestBody) Close() error {
	return nil
}

type logStreamResponseWriter struct {
	header    http.Header
	mu        sync.Mutex
	status    int
	body      bytes.Buffer
	flushOnce sync.Once
	connected chan struct{}
}

type blockingWriteResponseWriter struct {
	header       http.Header
	writeStarted chan struct{}
	release      chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
}

func newBlockingWriteResponseWriter() *blockingWriteResponseWriter {
	return &blockingWriteResponseWriter{
		header:       make(http.Header),
		writeStarted: make(chan struct{}),
		release:      make(chan struct{}),
	}
}

func (w *blockingWriteResponseWriter) Header() http.Header {
	return w.header
}

func (w *blockingWriteResponseWriter) WriteHeader(int) {}

func (w *blockingWriteResponseWriter) Write(p []byte) (int, error) {
	w.startOnce.Do(func() { close(w.writeStarted) })
	<-w.release
	return len(p), nil
}

func (w *blockingWriteResponseWriter) releaseWrite() {
	w.releaseOnce.Do(func() { close(w.release) })
}

func newLogStreamResponseWriter() *logStreamResponseWriter {
	return &logStreamResponseWriter{
		header:    make(http.Header),
		connected: make(chan struct{}),
	}
}

func (w *logStreamResponseWriter) Header() http.Header {
	return w.header
}

func (w *logStreamResponseWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = status
	}
}

func (w *logStreamResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func (w *logStreamResponseWriter) Flush() {
	w.flushOnce.Do(func() { close(w.connected) })
}
