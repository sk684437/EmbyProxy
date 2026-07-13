package config

import "testing"

func TestEnvBoolParsesAdmin2FADisabledValues(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  bool
	}{
		{value: "true", want: true},
		{value: "1", want: true},
		{value: "on", want: true},
		{value: "false", want: false},
		{value: "0", want: false},
		{value: "", want: false},
	} {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("ADMIN_2FA_DISABLED", tt.value)
			if got := envBool("ADMIN_2FA_DISABLED", false); got != tt.want {
				t.Fatalf("envBool() = %v, want %v", got, tt.want)
			}
		})
	}
}
