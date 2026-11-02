package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_WorkerSecurityDefaults(t *testing.T) {
	clearConfigEnv(t)
	t.Chdir(t.TempDir())
	t.Setenv("DATA_DIR", t.TempDir())

	cfg, err := NewConfig()
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1", cfg.DockerPublicIP, "new installations must not publish worker ports on every interface")
	assert.Equal(t, "127.0.0.1", cfg.WorkerPublicIP())
	assert.Equal(t, "fixed", cfg.DockerImageSelectionMode, "workers must use the configured image unless model selection is explicitly enabled")
	assert.False(t, cfg.DockerInside, "agents must not receive Docker access by default")
	assert.False(t, cfg.DockerNetAdmin, "network administration must remain an explicit opt-in")
}

func TestConfig_WorkerPublicIP_UsesLoopbackWithoutConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *Config
	}{
		{name: "nil config"},
		{name: "zero config", cfg: &Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, "127.0.0.1", tc.cfg.WorkerPublicIP())
		})
	}
}

func TestConfig_WorkerSecurityDefaults_PreserveExplicitOptIns(t *testing.T) {
	clearConfigEnv(t)
	t.Chdir(t.TempDir())
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("DOCKER_PUBLIC_IP", "0.0.0.0")
	t.Setenv("DOCKER_IMAGE_SELECTION_MODE", "llm")
	t.Setenv("DOCKER_NET_ADMIN", "true")

	cfg, err := NewConfig()
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0", cfg.DockerPublicIP)
	assert.Equal(t, "0.0.0.0", cfg.WorkerPublicIP())
	assert.Equal(t, "llm", cfg.DockerImageSelectionMode)
	assert.True(t, cfg.DockerNetAdmin)
	assert.False(t, cfg.DockerInside, "enabling another worker capability must not grant Docker access")
}
