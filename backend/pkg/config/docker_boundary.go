package config

import (
	"fmt"
	"strings"
)

func (c *Config) WorkerEgressMode() string {
	if c == nil || c.DockerEgressMode == "" {
		return "unrestricted"
	}
	return strings.ToLower(strings.TrimSpace(c.DockerEgressMode))
}

func (c *Config) ValidateDockerBoundary() error {
	mode := c.WorkerEgressMode()
	if mode != "isolated" && mode != "unrestricted" {
		return fmt.Errorf("DOCKER_EGRESS_MODE must be isolated or unrestricted")
	}
	if c == nil {
		return nil
	}
	if mode == "isolated" {
		if c.DockerNetwork == "" || c.DockerNetwork == "host" || c.DockerNetwork == "bridge" || c.DockerNetwork == "none" {
			return fmt.Errorf("isolated egress requires DOCKER_NETWORK to name an existing isolated lab bridge")
		}
		if c.DockerInside || c.DockerNetAdmin || c.DockerWorkDir != "" {
			return fmt.Errorf("isolated egress forbids DOCKER_INSIDE, DOCKER_NET_ADMIN and DOCKER_WORK_DIR")
		}
	}
	if c.DockerRequireRootless && (c.DockerInside || c.DockerWorkDir != "" || c.DockerNetwork == "host") {
		return fmt.Errorf("rootless worker boundary forbids nested Docker, host work directories and host networking")
	}
	return nil
}
