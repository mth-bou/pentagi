package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"pentagi/pkg/config"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func isolatedEgressConfig(t *testing.T, name string) (*config.Config, error) {
	t.Helper()
	t.Chdir(t.TempDir())
	for key, value := range map[string]string{
		"DATA_DIR": t.TempDir(), "DOCKER_EGRESS_MODE": "isolated", "DOCKER_NETWORK": name,
		"DOCKER_INSIDE": "false", "DOCKER_NET_ADMIN": "false", "DOCKER_WORK_DIR": "",
		"DOCKER_REQUIRE_ROOTLESS": "false", "DOCKER_DEFAULT_IMAGE": probeImage,
	} {
		t.Setenv(key, value)
	}
	return config.NewConfig()
}

func isolatedNetworkDocument() map[string]any {
	return map[string]any{
		"Name": "pentagi-isolated-probe", "Id": "isolated-probe", "Driver": "bridge", "Internal": true,
		"EnableIPv6": false,
		"Options":    map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
	}
}

func egressRecordingDaemon(t *testing.T, document map[string]any, missing bool) *int {
	t.Helper()
	return egressRecordingDaemonWithInfo(t, document, missing, egressDaemonInfo())
}

func egressDaemonInfo() map[string]any {
	return map[string]any{
		"ID": "egress-test", "MemoryLimit": true, "SwapLimit": true, "CPUCfsQuota": true, "PidsLimit": true,
		"SecurityOptions": []string{"name=rootless"}, "CgroupVersion": "2", "CgroupDriver": "systemd",
	}
}

func egressRecordingDaemonWithInfo(t *testing.T, document map[string]any, missing bool, info map[string]any) *int {
	t.Helper()
	creates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("API-Version", "1.55")
			_, _ = io.WriteString(w, "OK")
		case strings.HasSuffix(r.URL.Path, "/info"):
			require.NoError(t, json.NewEncoder(w).Encode(info))
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			_, _ = io.WriteString(w, `[]`)
		case strings.HasSuffix(r.URL.Path, "/networks/create"):
			creates++
			_, _ = io.WriteString(w, `{"Id":"auto-created-network"}`)
		case strings.Contains(r.URL.Path, "/networks/"):
			if missing {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"message":"network missing"}`)
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode(document))
		default:
			t.Errorf("unexpected daemon request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+server.Listener.Addr().String())
	t.Setenv("DOCKER_API_VERSION", "1.55")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	return &creates
}

func TestEgress_IsolatedModeRejectsUntrustedNetworksWithoutCreatingOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		mutate  func(map[string]any)
		missing bool
	}{
		{name: "missing explicit name", network: ""},
		{name: "host network", network: "host"},
		{name: "default bridge", network: "bridge"},
		{name: "none network", network: "none"},
		{name: "missing network", network: "pentagi-isolated-probe", missing: true},
		{name: "external bridge", network: "pentagi-isolated-probe", mutate: func(n map[string]any) { n["Internal"] = false }},
		{name: "ipv6 enabled", network: "pentagi-isolated-probe", mutate: func(n map[string]any) { n["EnableIPv6"] = true }},
		{name: "overlay driver", network: "pentagi-isolated-probe", mutate: func(n map[string]any) { n["Driver"] = "overlay" }},
		{name: "gateway mode absent", network: "pentagi-isolated-probe", mutate: func(n map[string]any) { n["Options"] = map[string]string{} }},
		{name: "routed gateway", network: "pentagi-isolated-probe", mutate: func(n map[string]any) {
			n["Options"] = map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "routed"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := isolatedEgressConfig(t, tc.network)
			if err != nil {
				return // Invalid configurations may be rejected before opening the daemon.
			}
			document := isolatedNetworkDocument()
			if tc.mutate != nil {
				tc.mutate(document)
			}
			creates := egressRecordingDaemon(t, document, tc.missing)
			_, err = NewDockerClient(t.Context(), &containerRecorder{}, cfg)
			assert.Error(t, err, "isolated mode must refuse a network without the enforced isolation contract")
			assert.Zero(t, *creates, "isolated mode must never silently create an unrestricted network")
		})
	}
}

func TestEgress_IsolatedModeAcceptsAnExplicitIsolatedBridge(t *testing.T) {
	cfg, err := isolatedEgressConfig(t, "pentagi-isolated-probe")
	require.NoError(t, err)
	creates := egressRecordingDaemon(t, isolatedNetworkDocument(), false)
	_, err = NewDockerClient(t.Context(), &containerRecorder{}, cfg)
	require.NoError(t, err)
	assert.Zero(t, *creates)
}

func TestEgress_IsolatedModeRejectsEscapeOptions(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{key: "DOCKER_INSIDE", value: "true"},
		{key: "DOCKER_NET_ADMIN", value: "true"},
		{key: "DOCKER_WORK_DIR", value: "/host/work"},
		{key: "DOCKER_EGRESS_MODE", value: "isolatd"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			_, err := isolatedEgressConfig(t, "pentagi-isolated-probe")
			require.NoError(t, err)
			t.Setenv(tc.key, tc.value)
			cfg, err := config.NewConfig()
			if err != nil {
				return
			}
			egressRecordingDaemon(t, isolatedNetworkDocument(), false)
			_, err = NewDockerClient(t.Context(), &containerRecorder{}, cfg)
			assert.Error(t, err, "a configuration that bypasses isolated egress must be refused")
		})
	}
}

func TestDockerBoundary_RequiresEnforcedDaemonResourceLimits(t *testing.T) {
	for _, field := range []string{"MemoryLimit", "SwapLimit", "CPUCfsQuota", "PidsLimit"} {
		t.Run(field, func(t *testing.T) {
			_, err := isolatedEgressConfig(t, "pentagi-isolated-probe")
			require.NoError(t, err)
			t.Setenv("DOCKER_EGRESS_MODE", "unrestricted")
			t.Setenv("DOCKER_NETWORK", "")
			cfg, err := config.NewConfig()
			require.NoError(t, err)
			info := egressDaemonInfo()
			info[field] = false
			egressRecordingDaemonWithInfo(t, isolatedNetworkDocument(), false, info)
			_, err = NewDockerClient(t.Context(), &containerRecorder{}, cfg)
			assert.Error(t, err, "the application must not promise resource limits a daemon cannot enforce")
		})
	}
}

func TestDockerBoundary_RequiresRootlessWithDelegatedCgroupV2(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "rootful", mutate: func(info map[string]any) { info["SecurityOptions"] = []string{"name=seccomp,profile=builtin"} }},
		{name: "cgroup v1", mutate: func(info map[string]any) { info["CgroupVersion"] = "1" }},
		{name: "no cgroup delegation", mutate: func(info map[string]any) { info["CgroupDriver"] = "none" }},
		{name: "empty cgroup driver", mutate: func(info map[string]any) { info["CgroupDriver"] = "" }},
		{name: "non-systemd cgroup driver", mutate: func(info map[string]any) { info["CgroupDriver"] = "cgroupfs" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := isolatedEgressConfig(t, "pentagi-isolated-probe")
			require.NoError(t, err)
			t.Setenv("DOCKER_REQUIRE_ROOTLESS", "true")
			cfg, err := config.NewConfig()
			require.NoError(t, err)
			info := egressDaemonInfo()
			tc.mutate(info)
			egressRecordingDaemonWithInfo(t, isolatedNetworkDocument(), false, info)
			_, err = NewDockerClient(t.Context(), &containerRecorder{}, cfg)
			assert.Error(t, err, "rootless mode requires a rootless daemon and cgroup v2 delegation")
		})
	}
}

func TestDockerBoundary_AcceptsRootlessWithDelegatedCgroupV2(t *testing.T) {
	_, err := isolatedEgressConfig(t, "pentagi-isolated-probe")
	require.NoError(t, err)
	t.Setenv("DOCKER_REQUIRE_ROOTLESS", "true")
	cfg, err := config.NewConfig()
	require.NoError(t, err)
	egressRecordingDaemonWithInfo(t, isolatedNetworkDocument(), false, egressDaemonInfo())
	_, err = NewDockerClient(t.Context(), &containerRecorder{}, cfg)
	require.NoError(t, err)
}

func TestEgress_IsolatedWorkerCanReachOnlyItsLabNetwork(t *testing.T) {
	probe := newDaemonClient(t)
	require.NoError(t, probe.pullImage(t.Context(), probeImage))
	isolated := createEgressProbeNetwork(t, probe, true)
	ordinary := createEgressProbeNetwork(t, probe, false)
	_, targetIP := startEgressHTTPProbe(t, probe, isolated, "isolated-target")
	ordinaryID, ordinaryIP := startEgressHTTPProbe(t, probe, ordinary, "ordinary-target")
	ordinaryInspect, err := probe.client.NetworkInspect(t.Context(), ordinary, client.NetworkInspectOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, ordinaryInspect.Network.IPAM.Config)
	gateway := ordinaryInspect.Network.IPAM.Config[0].Gateway.String()
	listener, err := net.Listen("tcp", net.JoinHostPort(gateway, "0"))
	require.NoError(t, err)
	hostServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "host-witness")
	}))
	hostServer.Listener.Close()
	hostServer.Listener = listener
	hostServer.Start()
	t.Cleanup(hostServer.Close)
	require.Equal(t, "host-witness", runInSandbox(t, probe, ordinaryID, "wget -q -T 2 -O - "+hostServer.URL+" 2>&1"), "the host gateway witness must be reachable from the ordinary bridge")

	cfg, err := isolatedEgressConfig(t, isolated)
	require.NoError(t, err)
	worker, err := NewDockerClient(t.Context(), &containerRecorder{}, cfg)
	require.NoError(t, err)
	dc := worker.(*dockerClient)
	dc.portsBase = reserveFreePortBase(t, 6)
	_, inspect := runProbeContainer(t, dc, probeName(t), 6, probeConfig(), nil)
	require.Len(t, inspect.NetworkSettings.Networks, 1, "the worker must not also join the default bridge")
	require.Contains(t, inspect.NetworkSettings.Networks, isolated)
	assert.Empty(t, inspect.HostConfig.PortBindings, "isolated workers must not publish callback ports")
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, inspect.HostConfig.DNS, "external DNS forwarding must be disabled")
	assert.Equal(t, "1", inspect.HostConfig.Sysctls["net.ipv6.conf.all.disable_ipv6"])
	assert.NotContains(t, inspect.HostConfig.CapAdd, "NET_RAW", "isolated workers must not have raw Ethernet access")
	assert.Equal(t, "1", strings.TrimSpace(runInSandbox(t, dc, inspect.ID, "cat /proc/sys/net/ipv6/conf/all/disable_ipv6")))
	bounding := strings.Fields(runInSandbox(t, dc, inspect.ID, "grep '^CapBnd:' /proc/self/status"))
	require.Len(t, bounding, 2)
	bits, err := strconv.ParseUint(bounding[1], 16, 64)
	require.NoError(t, err)
	assert.Zero(t, bits&(1<<13), "CAP_NET_RAW must be absent from the kernel bounding set")
	running, err := dc.IsContainerRunning(t.Context(), inspect.ID)
	require.NoError(t, err, "a newly created isolated worker must also pass the reuse policy")
	require.True(t, running)
	assert.Equal(t, "1\n", runInSandbox(t, dc, inspect.ID, "cat /proc/sys/net/ipv6/conf/all/disable_ipv6"))
	assert.Equal(t, "isolated-target", runInSandbox(t, dc, inspect.ID, "wget -q -T 2 -O - http://"+targetIP+":8080 2>&1"))
	assert.Equal(t, "blocked\n", runInSandbox(t, dc, inspect.ID, "if wget -q -T 2 -O /dev/null http://"+ordinaryIP+":8080; then echo escaped; else echo blocked; fi"))
	assert.Equal(t, "blocked\n", runInSandbox(t, dc, inspect.ID, "if wget -q -T 2 -O /dev/null "+hostServer.URL+"; then echo escaped; else echo blocked; fi"))
	assert.Empty(t, strings.TrimSpace(runInSandbox(t, dc, inspect.ID, "ip route | grep '^default ' || true")), "isolated workers must have no default route")
}

func createEgressProbeNetwork(t *testing.T, dc *dockerClient, isolated bool) string {
	t.Helper()
	name := probeName(t)
	options := client.NetworkCreateOptions{Driver: "bridge", Internal: isolated}
	if isolated {
		options.Options = map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
	}
	_, err := dc.client.NetworkCreate(t.Context(), name, options)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := dc.client.NetworkRemove(context.WithoutCancel(t.Context()), name, client.NetworkRemoveOptions{})
		assert.NoError(t, err)
	})
	return name
}

func startEgressHTTPProbe(t *testing.T, dc *dockerClient, networkName, marker string) (string, string) {
	t.Helper()
	containerID := startSandbox(t, dc, &container.Config{Image: probeImage}, &container.HostConfig{NetworkMode: container.NetworkMode(networkName)})
	server := fmt.Sprintf("while :; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s' | nc -l -p 8080 >/dev/null; done", len(marker), marker)
	_ = startInSandbox(t, dc, containerID, []string{"sh", "-c", server}, false)
	require.Eventually(t, func() bool {
		return marker == runInSandbox(t, dc, containerID, "wget -q -T 1 -O - http://127.0.0.1:8080 2>&1")
	}, 5*time.Second, 100*time.Millisecond, "the witness HTTP server must be healthy before testing isolation")
	inspect, err := dc.client.ContainerInspect(t.Context(), containerID, client.ContainerInspectOptions{})
	require.NoError(t, err)
	endpoint := inspect.Container.NetworkSettings.Networks[networkName]
	require.NotNil(t, endpoint)
	return containerID, endpoint.IPAddress.String()
}
