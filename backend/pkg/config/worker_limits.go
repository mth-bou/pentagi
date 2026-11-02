package config

import (
	"fmt"
	"math"
)

// Zero values select finite defaults; zero never means unlimited.
func (c *Config) WorkerLimits() (nanoCPUs, memory, pids int64) {
	nanoCPUs, memory, pids = 2_000_000_000, 4<<30, 512
	if c == nil {
		return
	}
	if c.DockerWorkerCPUs > 0 && c.DockerWorkerCPUs <= 1024 {
		nanoCPUs = int64(c.DockerWorkerCPUs * 1e9)
	}
	if c.DockerWorkerMemory > 0 {
		memory = c.DockerWorkerMemory
	}
	if c.DockerWorkerPidsLimit > 0 {
		pids = c.DockerWorkerPidsLimit
	}
	return
}

func (c *Config) ValidateWorkerLimits() error {
	if c == nil {
		return nil
	}
	if math.IsNaN(c.DockerWorkerCPUs) || math.IsInf(c.DockerWorkerCPUs, 0) ||
		c.DockerWorkerCPUs < 0 || c.DockerWorkerCPUs > 1024 ||
		(c.DockerWorkerCPUs > 0 && c.DockerWorkerCPUs < 0.001) {
		return fmt.Errorf("DOCKER_WORKER_CPUS must be 0 (default) or between 0.001 and 1024")
	}
	if c.DockerWorkerMemory < 0 || c.DockerWorkerMemory > 1<<60 ||
		(c.DockerWorkerMemory > 0 && c.DockerWorkerMemory < 6<<20) {
		return fmt.Errorf("DOCKER_WORKER_MEMORY must be 0 (default) or between 6 MiB and 1 EiB, in bytes")
	}
	if c.DockerWorkerPidsLimit < 0 || c.DockerWorkerPidsLimit > 1_000_000 {
		return fmt.Errorf("DOCKER_WORKER_PIDS_LIMIT must be between 0 (default) and 1000000")
	}
	return nil
}
