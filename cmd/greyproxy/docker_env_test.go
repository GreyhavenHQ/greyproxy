package main

import (
	"testing"

	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func TestApplyDockerEnvOverrides(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		initial     greyproxy.DockerConfig
		wantEnabled bool
		wantSocket  string
	}{
		{
			name:        "no env vars: config unchanged",
			env:         map[string]string{},
			initial:     greyproxy.DockerConfig{Enabled: false, Socket: "/var/run/docker.sock"},
			wantEnabled: false,
			wantSocket:  "/var/run/docker.sock",
		},
		{
			name:        "ENABLED=true overrides disabled config",
			env:         map[string]string{"GREYPROXY_DOCKER_ENABLED": "true"},
			initial:     greyproxy.DockerConfig{Enabled: false, Socket: ""},
			wantEnabled: true,
			wantSocket:  "",
		},
		{
			name:        "ENABLED=false overrides enabled config",
			env:         map[string]string{"GREYPROXY_DOCKER_ENABLED": "false"},
			initial:     greyproxy.DockerConfig{Enabled: true, Socket: "/var/run/docker.sock"},
			wantEnabled: false,
			wantSocket:  "/var/run/docker.sock",
		},
		{
			name:        "ENABLED unset leaves config value intact",
			env:         map[string]string{},
			initial:     greyproxy.DockerConfig{Enabled: true, Socket: ""},
			wantEnabled: true,
			wantSocket:  "",
		},
		{
			name:        "SOCKET overrides config socket path",
			env:         map[string]string{"GREYPROXY_DOCKER_SOCKET": "/run/podman/podman.sock"},
			initial:     greyproxy.DockerConfig{Enabled: false, Socket: "/var/run/docker.sock"},
			wantEnabled: false,
			wantSocket:  "/run/podman/podman.sock",
		},
		{
			name:        "SOCKET empty string does not override config",
			env:         map[string]string{"GREYPROXY_DOCKER_SOCKET": ""},
			initial:     greyproxy.DockerConfig{Enabled: false, Socket: "/var/run/docker.sock"},
			wantEnabled: false,
			wantSocket:  "/var/run/docker.sock",
		},
		{
			name: "both ENABLED and SOCKET override config",
			env: map[string]string{
				"GREYPROXY_DOCKER_ENABLED": "true",
				"GREYPROXY_DOCKER_SOCKET":  "/run/podman/podman.sock",
			},
			initial:     greyproxy.DockerConfig{Enabled: false, Socket: "/var/run/docker.sock"},
			wantEnabled: true,
			wantSocket:  "/run/podman/podman.sock",
		},
		{
			name:        "ENABLED with unrecognized value leaves config unchanged",
			env:         map[string]string{"GREYPROXY_DOCKER_ENABLED": "yes"},
			initial:     greyproxy.DockerConfig{Enabled: true, Socket: ""},
			wantEnabled: true,
			wantSocket:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Isolate env changes to this subtest.
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg := greyproxy.Config{Docker: tt.initial}
			applyDockerEnvOverrides(&cfg)

			if cfg.Docker.Enabled != tt.wantEnabled {
				t.Errorf("Enabled: got %v, want %v", cfg.Docker.Enabled, tt.wantEnabled)
			}
			if cfg.Docker.Socket != tt.wantSocket {
				t.Errorf("Socket: got %q, want %q", cfg.Docker.Socket, tt.wantSocket)
			}
		})
	}
}