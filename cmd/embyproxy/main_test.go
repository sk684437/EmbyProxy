package main

import "testing"

func TestShouldPrintVersion(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "long flag", args: []string{"--version"}, want: true},
		{name: "short flag", args: []string{"-v"}, want: true},
		{name: "command", args: []string{"version"}, want: true},
		{name: "no args", args: nil, want: false},
		{name: "serve arg", args: []string{"serve"}, want: false},
		{name: "extra args", args: []string{"--version", "extra"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldPrintVersion(tt.args); got != tt.want {
				t.Fatalf("shouldPrintVersion(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
