package docker

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"pentagi/pkg/config"
	"pentagi/pkg/database"

	"github.com/moby/moby/api/types/container"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerSpec_DefaultResourceAndPrivilegeBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{{name: "nil config"}, {name: "zero config", cfg: &config.Config{}}} {
		t.Run(tc.name, func(t *testing.T) {
			_, host := WorkerSpec(tc.cfg, probeImage)
			assertWorkerDefaultBudget(t, host)
			assert.Contains(t, host.CapDrop, "ALL")
			assert.NotContains(t, host.CapAdd, "NET_ADMIN")
			assert.Contains(t, host.SecurityOpt, "no-new-privileges:true")
			assert.False(t, host.Privileged)
		})
	}
}

func TestWorkerSpec_OperatorBudgetAndPrivilegeEscalationOptIn(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("DOCKER_WORKER_CPUS", "0.5")
	t.Setenv("DOCKER_WORKER_MEMORY", "268435456")
	t.Setenv("DOCKER_WORKER_PIDS_LIMIT", "64")
	t.Setenv("DOCKER_WORKER_ALLOW_PRIVILEGE_ESCALATION", "true")
	cfg, err := config.NewConfig()
	require.NoError(t, err)
	_, host := WorkerSpec(cfg, probeImage)
	assert.Equal(t, int64(500000000), host.NanoCPUs)
	assert.Equal(t, int64(256<<20), host.Memory)
	assert.Equal(t, host.Memory, host.MemorySwap, "memory+swap must equal memory to disable swap")
	require.NotNil(t, host.PidsLimit)
	assert.Equal(t, int64(64), *host.PidsLimit)
	assert.NotContains(t, host.SecurityOpt, "no-new-privileges:true", "SUID testing requires explicit operator opt-in")
	assert.False(t, host.Privileged, "SUID opt-in must not grant Docker privileged mode")
}

func assertWorkerDefaultBudget(t *testing.T, host *container.HostConfig) {
	t.Helper()
	assert.Equal(t, int64(2000000000), host.NanoCPUs)
	assert.Equal(t, int64(4<<30), host.Memory)
	assert.Equal(t, host.Memory, host.MemorySwap, "worker must not escape its RAM budget through swap")
	if assert.NotNil(t, host.PidsLimit) {
		assert.Equal(t, int64(512), *host.PidsLimit)
	}
}

// A recording daemon stops at create: even deliberately hostile inputs in the
// rejection tests can never start a privileged container on the developer host.
func recordWorkerCreate(t *testing.T, host *container.HostConfig) (*container.HostConfig, bool, error) {
	t.Helper()
	var captured struct {
		HostConfig *container.HostConfig
	}
	created := false
	cli := daemonWith(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/images/json"):
			return statusResponse(http.StatusOK, `[{"Id":"sha256:probe"}]`), nil
		case strings.HasSuffix(r.URL.Path, "/containers/create"):
			created = true
			require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
			return statusResponse(http.StatusServiceUnavailable, `{"message":"test stops before container creation"}`), nil
		default:
			t.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
			return statusResponse(http.StatusInternalServerError, `{"message":"unexpected request"}`), nil
		}
	})
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	dc := &dockerClient{
		client: cli, db: &containerRecorder{}, logger: logger,
		dataDir: t.TempDir(), hostDir: t.TempDir(), defImage: probeImage,
	}
	_, err := dc.RunContainer(t.Context(), "pentagi-budget-probe", database.ContainerTypePrimary, 1, probeConfig(), host)
	return captured.HostConfig, created, err
}

func TestClient_WorkerBudgetAppliesWithoutWorkerSpec(t *testing.T) {
	for _, tc := range []struct {
		name string
		host *container.HostConfig
	}{{name: "nil host config"}, {name: "zero host config", host: &container.HostConfig{}}} {
		t.Run(tc.name, func(t *testing.T) {
			host, created, err := recordWorkerCreate(t, tc.host)
			require.True(t, created, "the recording daemon must receive the effective worker specification")
			require.ErrorContains(t, err, "test stops before container creation")
			require.NotNil(t, host)
			assertWorkerDefaultBudget(t, host)
			assert.Contains(t, host.SecurityOpt, "no-new-privileges:true")
		})
	}
}

func TestClient_WorkerBudgetCannotBeRaisedByCaller(t *testing.T) {
	pids := int64(-1)
	host, created, err := recordWorkerCreate(t, &container.HostConfig{
		Resources: container.Resources{
			NanoCPUs: 8000000000, Memory: 16 << 30, MemorySwap: -1, PidsLimit: &pids,
			CPUPeriod: 100000, CPUQuota: 800000,
		},
	})
	require.True(t, created)
	require.ErrorContains(t, err, "test stops before container creation")
	require.NotNil(t, host)
	assertWorkerDefaultBudget(t, host)
	assert.Zero(t, host.CPUPeriod, "legacy CPU fields cannot conflict with NanoCPUs")
	assert.Zero(t, host.CPUQuota)
}

func TestClient_WorkerBudgetKeepsStricterCallerLimits(t *testing.T) {
	pids := int64(32)
	host, created, err := recordWorkerCreate(t, &container.HostConfig{
		Resources: container.Resources{NanoCPUs: 250000000, Memory: 128 << 20, MemorySwap: -1, PidsLimit: &pids},
	})
	require.True(t, created)
	require.ErrorContains(t, err, "test stops before container creation")
	require.NotNil(t, host)
	assert.Equal(t, int64(250000000), host.NanoCPUs)
	assert.Equal(t, int64(128<<20), host.Memory)
	assert.Equal(t, host.Memory, host.MemorySwap)
	require.NotNil(t, host.PidsLimit)
	assert.Equal(t, int64(32), *host.PidsLimit)
}

func TestClient_WorkerRejectsDockerPrivilegeEscapesBeforeCreate(t *testing.T) {
	for _, tc := range []struct {
		name string
		host container.HostConfig
	}{
		{name: "privileged", host: container.HostConfig{Privileged: true}},
		{name: "host pid namespace", host: container.HostConfig{PidMode: "host"}},
		{name: "host ipc namespace", host: container.HostConfig{IpcMode: "host"}},
		{name: "host network namespace", host: container.HostConfig{NetworkMode: "host"}},
		{name: "dangerous capability", host: container.HostConfig{CapAdd: []string{"SYS_ADMIN"}}},
		{name: "parent cgroup", host: container.HostConfig{Resources: container.Resources{CgroupParent: "untrusted-parent"}}},
		{name: "host device", host: container.HostConfig{Resources: container.Resources{Devices: []container.DeviceMapping{{PathOnHost: "/dev/null", PathInContainer: "/dev/probe", CgroupPermissions: "rwm"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, created, err := recordWorkerCreate(t, &tc.host)
			require.Error(t, err)
			assert.False(t, created, "unsafe specification must be rejected before it reaches container create")
		})
	}
}

func TestClient_WorkerBudgetIsEnforcedByDocker(t *testing.T) {
	_ = newDaemonClient(t)
	cfg := &config.Config{DataDir: t.TempDir(), DockerDefaultImage: probeImage}
	workerClient, err := NewDockerClient(t.Context(), &containerRecorder{}, cfg)
	require.NoError(t, err)
	dc := workerClient.(*dockerClient)
	flowID := int64(5)
	dc.portsBase = reserveFreePortBase(t, flowID)
	_, inspect := runProbeContainer(t, dc, probeName(t), flowID, probeConfig(), nil)
	assertWorkerDefaultBudget(t, inspect.HostConfig)
	assert.Contains(t, inspect.HostConfig.SecurityOpt, "no-new-privileges:true")
	output := runInSandbox(t, dc, inspect.ID, "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/pids.max; grep '^NoNewPrivs:' /proc/self/status; cat /sys/fs/cgroup/cpu.max")
	assert.Contains(t, output, "4294967296\n0\n512\n")
	assert.Contains(t, output, "NoNewPrivs:\t1")
	lines := strings.Split(strings.TrimSpace(output), "\n")
	require.Len(t, lines, 5)
	cpu := strings.Fields(lines[4])
	require.Len(t, cpu, 2)
	quota, err := strconv.ParseInt(cpu[0], 10, 64)
	require.NoError(t, err, "cpu.max must contain a numeric quota, not max")
	period, err := strconv.ParseInt(cpu[1], 10, 64)
	require.NoError(t, err)
	assert.Equal(t, period*2, quota, "cgroup CPU bandwidth must enforce the two-CPU budget")
}
