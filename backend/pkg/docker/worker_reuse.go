package docker

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

// Reusing a live worker must not grandfather in old resource limits or network
// access. Refuse rather than deleting it: /work and operator-installed tools
// must remain recoverable. Callers surface the error and require recreation.
func (dc *dockerClient) validateReusableWorker(ctx context.Context, inspection container.InspectResponse) error {
	cfg := dc.workerConfig
	if cfg == nil { // application clients always carry the NewDockerClient policy
		return nil
	}
	if err := cfg.ValidateWorkerLimits(); err != nil {
		return err
	}
	if err := cfg.ValidateDockerBoundary(); err != nil {
		return err
	}
	host := inspection.HostConfig
	if host == nil {
		return fmt.Errorf("worker host configuration missing")
	}
	cpu, memory, pids := cfg.WorkerLimits()
	if host.NanoCPUs <= 0 || host.NanoCPUs > cpu || host.Memory <= 0 || host.Memory > memory ||
		host.MemorySwap != host.Memory || host.PidsLimit == nil || *host.PidsLimit <= 0 || *host.PidsLimit > pids {
		return fmt.Errorf("worker exceeds the current CPU, memory, swap or PID budget")
	}
	if host.Privileged || !slices.Contains(host.CapDrop, "ALL") ||
		(host.PidMode != "" && host.PidMode != "private") ||
		(host.IpcMode != "" && host.IpcMode != "private") ||
		(host.CgroupnsMode != "" && host.CgroupnsMode != "private") ||
		host.UsernsMode == "host" || host.UTSMode == "host" || host.CgroupParent != "" ||
		len(host.Devices) != 0 || len(host.DeviceRequests) != 0 || len(host.DeviceCgroupRules) != 0 ||
		(host.OomKillDisable != nil && *host.OomKillDisable) {
		return fmt.Errorf("worker has an unsafe privilege or namespace configuration")
	}
	for _, cap := range host.CapAdd {
		if !slices.Contains(workerCapabilities(cfg), strings.TrimPrefix(strings.ToUpper(cap), "CAP_")) {
			return fmt.Errorf("worker has an unapproved capability")
		}
	}
	if !cfg.DockerWorkerAllowPrivilegeEscalation && !slices.Contains(host.SecurityOpt, "no-new-privileges:true") {
		return fmt.Errorf("worker is missing no-new-privileges")
	}
	for _, option := range host.SecurityOpt {
		if option != "no-new-privileges:true" && !(cfg.DockerWorkerAllowPrivilegeEscalation && option == "no-new-privileges:false") {
			return fmt.Errorf("worker has an unapproved security option")
		}
	}
	if err := dc.validateReusedWorkerAccess(inspection); err != nil {
		return err
	}
	if err := dc.validateReusedWorkerNetwork(inspection); err != nil {
		return err
	}
	if cfg.WorkerEgressMode() == "isolated" {
		if inspection.NetworkSettings == nil || len(inspection.NetworkSettings.Networks) != 1 ||
			inspection.NetworkSettings.Networks[dc.network] == nil || string(host.NetworkMode) != dc.network ||
			len(host.PortBindings) != 0 || host.PublishAllPorts ||
			!slices.Equal(host.DNS, []netip.Addr{netip.MustParseAddr("127.0.0.1")}) ||
			host.Sysctls["net.ipv6.conf.all.disable_ipv6"] != "1" {
			return fmt.Errorf("worker no longer satisfies the isolated lab network policy")
		}
		return verifyIsolatedNetwork(ctx, dc.client, dc.network)
	}
	return nil
}

func (dc *dockerClient) validateReusedWorkerAccess(inspection container.InspectResponse) error {
	cfg := dc.workerConfig
	namedWorkOnly := cfg.DockerRequireRootless || cfg.WorkerEgressMode() == "isolated"
	for _, mounted := range inspection.Mounts {
		if mounted.Destination == WorkFolderPathInContainer {
			if mounted.Type == mount.TypeVolume {
				continue
			}
			if !namedWorkOnly && mounted.Type == mount.TypeBind && dc.hostDir != "" &&
				strings.HasPrefix(filepath.Clean(mounted.Source), filepath.Clean(dc.hostDir)+string(filepath.Separator)) {
				continue
			}
			return fmt.Errorf("worker retains an unapproved host workdir")
		}
		if dc.inside && !namedWorkOnly {
			if mounted.Type == mount.TypeBind && dc.socket != "" && filepath.Clean(mounted.Source) == filepath.Clean(dc.socket) && filepath.Clean(mounted.Destination) == defaultDockerSocketPath {
				continue
			}
			if mounted.Type == mount.TypeBind && dc.insideCertPath != "" && filepath.Clean(mounted.Source) == filepath.Clean(dc.insideCertPath) && filepath.Clean(mounted.Destination) == filepath.Clean(dc.insideCertPath) && !mounted.RW {
				continue
			}
		}
		if mounted.Type == mount.TypeBind || namedWorkOnly || mounted.Destination == defaultDockerSocketPath {
			return fmt.Errorf("worker retains an unapproved mount or retired Docker authority")
		}
	}
	var expected []string
	if dc.inside {
		expected = dc.insideEnv
	}
	if inspection.Config == nil {
		return fmt.Errorf("worker configuration missing")
	}
	for _, entry := range inspection.Config.Env {
		key, _, _ := strings.Cut(entry, "=")
		if (key == "DOCKER_HOST" || key == "DOCKER_TLS_VERIFY" || key == "DOCKER_CERT_PATH") && !slices.Contains(expected, entry) {
			return fmt.Errorf("worker retains a retired Docker endpoint or credential configuration")
		}
	}
	for _, entry := range expected {
		if !slices.Contains(inspection.Config.Env, entry) {
			return fmt.Errorf("worker Docker endpoint no longer matches its configured access")
		}
	}
	return nil
}

func (dc *dockerClient) validateReusedWorkerNetwork(inspection container.InspectResponse) error {
	if inspection.NetworkSettings == nil {
		return fmt.Errorf("worker network configuration missing")
	}
	mode := string(inspection.HostConfig.NetworkMode)
	wanted := dc.network
	if wanted == "" {
		wanted = "bridge"
	}
	if dc.workerConfig.DockerRequireRootless && mode == "host" {
		return fmt.Errorf("rootless worker boundary forbids host networking")
	}
	if (wanted == "host") != (mode == "host") || strings.HasPrefix(mode, "container:") ||
		len(inspection.NetworkSettings.Networks) != 1 || inspection.NetworkSettings.Networks[wanted] == nil {
		return fmt.Errorf("worker network membership no longer matches the configured scope")
	}
	return nil
}
