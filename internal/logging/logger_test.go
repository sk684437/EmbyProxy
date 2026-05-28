package logging

import (
	"strings"
	"testing"
)

func TestRedactTextRedactsEmbeddedURLQuerySecrets(t *testing.T) {
	input := `Get "https://emby.example/emby/Items/1?X-Emby-Token=secret-token&fields=ShareLevel&api_key=secret-key": context canceled`

	got := RedactText(input)
	if strings.Contains(got, "secret-token") || strings.Contains(got, "secret-key") {
		t.Fatalf("RedactText() leaked sensitive query values: %q", got)
	}
	for _, want := range []string{"X-Emby-Token=<redacted>", "api_key=<redacted>", "fields=ShareLevel"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RedactText() = %q, want to contain %q", got, want)
		}
	}
}

func TestFormatValueRedactsEmbeddedURLInErrorMeta(t *testing.T) {
	got := formatValue(`Get "https://emby.example/emby/Items/1?X-Emby-Token=secret-token&fields=ShareLevel": context canceled`)

	if strings.Contains(got, "secret-token") {
		t.Fatalf("formatValue() leaked sensitive query values: %q", got)
	}
	if !strings.Contains(got, "X-Emby-Token=<redacted>") {
		t.Fatalf("formatValue() = %q, want redacted token", got)
	}
}
