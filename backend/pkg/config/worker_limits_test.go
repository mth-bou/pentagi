package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig_WorkerLimitsRejectInvalidBudgets(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"DOCKER_WORKER_CPUS", "NaN"}, {"DOCKER_WORKER_CPUS", "+Inf"},
		{"DOCKER_WORKER_CPUS", "-1"}, {"DOCKER_WORKER_CPUS", "0.0001"}, {"DOCKER_WORKER_CPUS", "1025"},
		{"DOCKER_WORKER_MEMORY", "-1"}, {"DOCKER_WORKER_MEMORY", "1024"},
		{"DOCKER_WORKER_MEMORY", "9223372036854775808"},
		{"DOCKER_WORKER_PIDS_LIMIT", "-1"}, {"DOCKER_WORKER_PIDS_LIMIT", "1000001"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			clearConfigEnv(t)
			t.Chdir(t.TempDir())
			t.Setenv(tc.key, tc.value)
			_, err := NewConfig()
			require.Error(t, err)
		})
	}
}

func TestConfig_WorkerLimitsZeroCannotDisableBudgets(t *testing.T) {
	clearConfigEnv(t)
	t.Chdir(t.TempDir())
	t.Setenv("DOCKER_WORKER_CPUS", "0")
	t.Setenv("DOCKER_WORKER_MEMORY", "0")
	t.Setenv("DOCKER_WORKER_PIDS_LIMIT", "0")
	cfg, err := NewConfig()
	require.NoError(t, err)
	cpu, ram, pids := cfg.WorkerLimits()
	require.Equal(t, int64(2e9), cpu)
	require.Equal(t, int64(4<<30), ram)
	require.Equal(t, int64(512), pids)
}
