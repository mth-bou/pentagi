package docker

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"pentagi/pkg/config"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func reusableWorkerInspection(cfg *config.Config) container.InspectResponse {
	workerConfig, host := WorkerSpec(cfg, probeImage)
	name := "bridge"
	if cfg.WorkerEgressMode() == "isolated" {
		name = cfg.DockerNetwork
		host.DNS = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		host.Sysctls = map[string]string{"net.ipv6.conf.all.disable_ipv6": "1"}
	}
	host.NetworkMode = container.NetworkMode(name)
	host.IpcMode = "private"
	host.CgroupnsMode = "private"
	host.Runtime = "runc"
	host.Binds = []string{"pentagi-reuse-probe-data:/work"}
	workerConfig.WorkingDir = "/work"
	return container.InspectResponse{
		ID: "reusable-worker", State: &container.State{Running: true}, Config: workerConfig,
		HostConfig:      host,
		Mounts:          []container.MountPoint{{Type: mount.TypeVolume, Name: "pentagi-reuse-probe-data", Destination: "/work", RW: true}},
		NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{name: {}}},
	}
}

func reuseProbeClient(t *testing.T, cfg *config.Config, inspect container.InspectResponse, networkDocument map[string]any) *dockerClient {
	t.Helper()
	cli := daemonWith(t, func(r *http.Request) (*http.Response, error) {
		var document any
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/reusable-worker/json"):
			document = inspect
		case strings.Contains(r.URL.Path, "/networks/"):
			document = networkDocument
		default:
			t.Errorf("unexpected daemon request: %s %s", r.Method, r.URL.Path)
			return statusResponse(http.StatusInternalServerError, `{"message":"unexpected request"}`), nil
		}
		body, err := json.Marshal(document)
		require.NoError(t, err)
		return statusResponse(http.StatusOK, string(body)), nil
	})
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &dockerClient{client: cli, logger: logger, workerConfig: cfg, network: cfg.DockerNetwork}
}

func TestWorkerReuse_RejectsLegacyAndWeakenedWorkerBudgets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*container.InspectResponse, *config.Config)
	}{
		{name: "unlimited memory", mutate: func(i *container.InspectResponse, _ *config.Config) { i.HostConfig.Memory = 0 }},
		{name: "unlimited cpu", mutate: func(i *container.InspectResponse, _ *config.Config) { i.HostConfig.NanoCPUs = 0 }},
		{name: "unlimited pids", mutate: func(i *container.InspectResponse, _ *config.Config) { i.HostConfig.PidsLimit = nil }},
		{name: "unlimited swap", mutate: func(i *container.InspectResponse, _ *config.Config) { i.HostConfig.MemorySwap = -1 }},
		{name: "missing no new privileges", mutate: func(i *container.InspectResponse, _ *config.Config) { i.HostConfig.SecurityOpt = nil }},
		{name: "privileged", mutate: func(i *container.InspectResponse, _ *config.Config) { i.HostConfig.Privileged = true }},
		{name: "unsafe capability", mutate: func(i *container.InspectResponse, _ *config.Config) {
			i.HostConfig.CapAdd = append(i.HostConfig.CapAdd, "SYS_ADMIN")
		}},
		{name: "operator reduced memory", mutate: func(_ *container.InspectResponse, c *config.Config) { c.DockerWorkerMemory = 256 << 20 }},
		{name: "operator reduced cpu", mutate: func(_ *container.InspectResponse, c *config.Config) { c.DockerWorkerCPUs = 0.5 }},
		{name: "operator reduced pids", mutate: func(_ *container.InspectResponse, c *config.Config) { c.DockerWorkerPidsLimit = 64 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			inspect := reusableWorkerInspection(cfg)
			tc.mutate(&inspect, cfg)
			dc := reuseProbeClient(t, cfg, inspect, nil)
			running, err := dc.IsContainerRunning(t.Context(), inspect.ID)
			assert.Error(t, err, "a previously created worker must satisfy today's policy before reuse")
			assert.False(t, running)
		})
	}
}

func TestWorkerReuse_RejectsEscapedOrReplacedIsolatedNetwork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*container.InspectResponse, map[string]any)
	}{
		{name: "old unrestricted worker", mutate: func(i *container.InspectResponse, _ map[string]any) {
			i.HostConfig.NetworkMode = "bridge"
			i.NetworkSettings.Networks = map[string]*network.EndpointSettings{"bridge": {}}
		}},
		{name: "additional bridge attached", mutate: func(i *container.InspectResponse, _ map[string]any) {
			i.NetworkSettings.Networks["external-network"] = &network.EndpointSettings{}
		}},
		{name: "isolated network replaced", mutate: func(_ *container.InspectResponse, n map[string]any) { n["Internal"] = false }},
		{name: "ipv6 enabled on replacement", mutate: func(_ *container.InspectResponse, n map[string]any) { n["EnableIPv6"] = true }},
		{name: "dns forwarding restored", mutate: func(i *container.InspectResponse, _ map[string]any) { i.HostConfig.DNS = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{DockerEgressMode: "isolated", DockerNetwork: "pentagi-isolated-probe"}
			inspect := reusableWorkerInspection(cfg)
			net := isolatedNetworkDocument()
			tc.mutate(&inspect, net)
			dc := reuseProbeClient(t, cfg, inspect, net)
			running, err := dc.IsContainerRunning(t.Context(), inspect.ID)
			assert.Error(t, err, "network scope must be checked again before worker reuse")
			assert.False(t, running)
		})
	}
}

func TestWorkerReuse_AcceptsWorkersThatStillSatisfyTheCurrentPolicy(t *testing.T) {
	for _, cfg := range []*config.Config{
		{},
		{DockerEgressMode: "isolated", DockerNetwork: "pentagi-isolated-probe"},
	} {
		t.Run(cfg.WorkerEgressMode(), func(t *testing.T) {
			inspect := reusableWorkerInspection(cfg)
			dc := reuseProbeClient(t, cfg, inspect, isolatedNetworkDocument())
			running, err := dc.IsContainerRunning(t.Context(), inspect.ID)
			require.NoError(t, err)
			assert.True(t, running)
		})
	}
}

func TestWorkerReuse_RejectsRetiredDockerAuthorityAndNetworkInCompatibilityMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*container.InspectResponse, *config.Config)
	}{
		{name: "retired Docker socket", mutate: func(i *container.InspectResponse, _ *config.Config) {
			i.Mounts = append(i.Mounts, container.MountPoint{Type: mount.TypeBind, Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"})
		}},
		{name: "retired Docker certificates", mutate: func(i *container.InspectResponse, _ *config.Config) {
			i.Mounts = append(i.Mounts, container.MountPoint{Type: mount.TypeBind, Source: "/worker/certs", Destination: "/worker/certs"})
		}},
		{name: "retired Docker endpoint", mutate: func(i *container.InspectResponse, _ *config.Config) {
			i.Config.Env = append(i.Config.Env, "DOCKER_HOST=tcp://retired-daemon:3376")
		}},
		{name: "retired host networking", mutate: func(i *container.InspectResponse, c *config.Config) {
			c.DockerRequireRootless = true
			i.HostConfig.NetworkMode = "host"
			i.NetworkSettings.Networks = map[string]*network.EndpointSettings{"host": {}}
		}},
		{name: "changed bridge scope", mutate: func(_ *container.InspectResponse, c *config.Config) { c.DockerNetwork = "new-lab" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			inspect := reusableWorkerInspection(cfg)
			tc.mutate(&inspect, cfg)
			dc := reuseProbeClient(t, cfg, inspect, nil)
			running, err := dc.IsContainerRunning(t.Context(), inspect.ID)
			require.Error(t, err)
			require.False(t, running)
		})
	}
}

func TestWorkerReuse_PreservesExplicitCurrentDockerEndpoint(t *testing.T) {
	cfg := &config.Config{DockerInside: true, DockerInsideHost: "tcp://worker.example:3376", DockerInsideTLSVerify: "1", DockerInsideCertPath: "/worker/certs/"}
	inspection := reusableWorkerInspection(cfg)
	inspection.Config.Env = cfg.WorkerDockerEnv()
	inspection.Mounts = append(inspection.Mounts, container.MountPoint{Type: mount.TypeBind, Source: filepath.Clean(cfg.DockerInsideCertPath), Destination: filepath.Clean(cfg.DockerInsideCertPath), RW: false})
	dc := reuseProbeClient(t, cfg, inspection, nil)
	dc.inside, dc.insideEnv, dc.insideCertPath = true, cfg.WorkerDockerEnv(), cfg.WorkerDockerCertPath()
	running, err := dc.IsContainerRunning(t.Context(), inspection.ID)
	require.NoError(t, err)
	require.True(t, running)
}
