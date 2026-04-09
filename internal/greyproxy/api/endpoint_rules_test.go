package api

import (
	"strings"
	"testing"
)

func TestValidateEndpointRule(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		path        string
		method      string
		decoder     string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid rule",
			host: "api.example.com", path: "/v1/chat/completions",
			method: "POST", decoder: "openai-chat",
		},
		{
			name: "valid wildcard host",
			host: "*.example.com", path: "/v1/chat/completions",
			method: "POST", decoder: "openai-chat",
		},
		{
			name: "valid wildcard method",
			host: "api.example.com", path: "/v1/chat/completions",
			method: "*", decoder: "openai-chat",
		},
		{
			name: "unknown decoder",
			host: "api.example.com", path: "/v1/chat/completions",
			method: "POST", decoder: "nonexistent-decoder",
			wantErr: true, errContains: "unknown decoder_name",
		},
		{
			name: "path without leading slash",
			host: "api.example.com", path: "v1/chat/completions",
			method: "POST", decoder: "openai-chat",
			wantErr: true, errContains: "path_pattern must start with /",
		},
		{
			name: "bare percent host",
			host: "%", path: "/v1/chat/completions",
			method: "POST", decoder: "openai-chat",
			wantErr: true, errContains: "host_pattern must not be empty",
		},
		{
			name: "bare wildcard host",
			host: "*", path: "/v1/chat/completions",
			method: "POST", decoder: "openai-chat",
			wantErr: true, errContains: "host_pattern must not be empty",
		},
		{
			name: "empty host",
			host: "", path: "/v1/chat/completions",
			method: "POST", decoder: "openai-chat",
			wantErr: true, errContains: "host_pattern must not be empty",
		},
		{
			name: "invalid method",
			host: "api.example.com", path: "/v1/chat/completions",
			method: "FOOBAR", decoder: "openai-chat",
			wantErr: true, errContains: "invalid method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := validateEndpointRule(tt.host, tt.path, tt.method, tt.decoder)
			if tt.wantErr {
				if errMsg == "" {
					t.Errorf("expected validation error containing %q, got none", tt.errContains)
				} else if tt.errContains != "" && !strings.Contains(errMsg, tt.errContains) {
					t.Errorf("error = %q, want it to contain %q", errMsg, tt.errContains)
				}
			} else {
				if errMsg != "" {
					t.Errorf("unexpected validation error: %s", errMsg)
				}
			}
		})
	}
}
