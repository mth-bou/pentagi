package docker

import (
	"testing"

	"pentagi/pkg/config"

	"github.com/stretchr/testify/require"
)

func TestClient_DefaultConfigPublishesWorkerPortsOnlyOnLoopback(t *testing.T) {
	// Skip cleanly when the optional integration daemon is unavailable.
	_ = newDaemonClient(t)
	cfg := &config.Config{DataDir: t.TempDir(), DockerDefaultImage: probeImage}
	workerClient, err := NewDockerClient(t.Context(), &containerRecorder{}, cfg)
	require.NoError(t, err)
	dc := workerClient.(*dockerClient)
	flowID := int64(4)
	dc.portsBase = reserveFreePortBase(t, flowID)

	_, inspect := runProbeContainer(t, dc, probeName(t), flowID, probeConfig(), nil)
	require.Len(t, inspect.NetworkSettings.Ports, 2)
	for _, bindings := range inspect.NetworkSettings.Ports {
		require.Len(t, bindings, 1)
		require.Equal(t, "127.0.0.1", bindings[0].HostIP.String())
	}
	for _, point := range inspect.Mounts {
		require.NotEqual(t, "/var/run/docker.sock", point.Destination)
	}
}
