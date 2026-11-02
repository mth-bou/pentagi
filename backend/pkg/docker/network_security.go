package docker

import (
	"context"
	"fmt"
	"slices"

	"pentagi/pkg/config"

	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
)

func validateControlDaemon(cfg *config.Config, info system.Info) error {
	if !info.MemoryLimit || !info.SwapLimit || !info.CPUCfsQuota || !info.PidsLimit {
		return fmt.Errorf("worker Docker daemon must enforce memory, swap, CPU and PID cgroup limits")
	}
	if cfg.DockerRequireRootless && (!slices.Contains(info.SecurityOptions, "name=rootless") ||
		info.CgroupVersion != "2" || info.CgroupDriver != "systemd") {
		return fmt.Errorf("DOCKER_REQUIRE_ROOTLESS requires a rootless daemon with delegated cgroup v2 controllers")
	}
	return nil
}

// Validate rather than create: silently provisioning a different network would
// change the operator's target scope. Recheck at every worker creation as well
// as startup, so replacement by an ordinary bridge cannot silently open egress.
func verifyIsolatedNetwork(ctx context.Context, cli *client.Client, name string) error {
	result, err := cli.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect isolated worker network: %w", err)
	}
	net := result.Network
	if net.Driver != "bridge" || !net.Internal || net.EnableIPv6 ||
		net.Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" {
		return fmt.Errorf("worker network %q must be an internal IPv4 bridge with gateway_mode_ipv4=isolated and IPv6 disabled", name)
	}
	return nil
}
