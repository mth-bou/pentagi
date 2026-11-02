package docker

import (
	"fmt"
	"slices"
	"strings"

	"pentagi/pkg/config"

	"github.com/moby/moby/api/types/container"
)

// applyWorkerSecurity runs before any daemon mutation, including for callers
// that bypass WorkerSpec. Only the orchestrator adds mounts and network access.
func applyWorkerSecurity(cfg *config.Config, host *container.HostConfig) error {
	if err := cfg.ValidateWorkerLimits(); err != nil {
		return err
	}
	if host.Privileged || host.PidMode != "" || host.IpcMode != "" ||
		host.UTSMode != "" || host.UsernsMode != "" || host.CgroupnsMode != "" ||
		host.NetworkMode != "" || host.CgroupParent != "" || host.Runtime != "" ||
		len(host.Devices) != 0 || len(host.DeviceRequests) != 0 || len(host.DeviceCgroupRules) != 0 ||
		len(host.Binds) != 0 || len(host.Mounts) != 0 || len(host.VolumesFrom) != 0 ||
		host.MaskedPaths != nil || host.ReadonlyPaths != nil || len(host.Tmpfs) != 0 ||
		len(host.Annotations) != 0 || len(host.Links) != 0 || host.PublishAllPorts || len(host.PortBindings) != 0 ||
		len(host.Sysctls) != 0 || host.CPURealtimePeriod != 0 || host.CPURealtimeRuntime != 0 ||
		(host.OomKillDisable != nil && *host.OomKillDisable) || host.OomScoreAdj < 0 {
		return fmt.Errorf("unsafe worker host configuration: namespace, device, mount or privilege override")
	}
	allowed := workerCapabilities(cfg)
	if host.CapAdd == nil {
		host.CapAdd = allowed
	}
	for _, cap := range host.CapAdd {
		if !slices.Contains(allowed, strings.TrimPrefix(strings.ToUpper(cap), "CAP_")) {
			return fmt.Errorf("worker capability %q is not allowed", cap)
		}
	}
	if !slices.Contains(host.CapDrop, "ALL") {
		host.CapDrop = append(host.CapDrop, "ALL")
	}
	allowEscalation := cfg != nil && cfg.DockerWorkerAllowPrivilegeEscalation
	for _, option := range host.SecurityOpt {
		if option != "no-new-privileges:true" && !(allowEscalation && option == "no-new-privileges:false") {
			return fmt.Errorf("worker security option %q is not allowed", option)
		}
	}
	if !allowEscalation && !slices.Contains(host.SecurityOpt, "no-new-privileges:true") {
		host.SecurityOpt = append(host.SecurityOpt, "no-new-privileges:true")
	}
	nanoCPUs, memory, pids := cfg.WorkerLimits()
	if host.NanoCPUs <= 0 || host.NanoCPUs > nanoCPUs {
		host.NanoCPUs = nanoCPUs
	}
	// Do not let the legacy CPU API conflict with the enforced NanoCPUs quota.
	host.CPUPeriod, host.CPUQuota = 0, 0
	if host.Memory <= 0 || host.Memory > memory {
		host.Memory = memory
	}
	host.MemorySwap = host.Memory
	if host.MemoryReservation > host.Memory {
		host.MemoryReservation = host.Memory
	}
	if host.PidsLimit == nil || *host.PidsLimit <= 0 || *host.PidsLimit > pids {
		host.PidsLimit = &pids
	}
	return nil
}
