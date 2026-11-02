package providers

import (
	"strings"
	"testing"

	"pentagi/pkg/config"

	"github.com/stretchr/testify/assert"
)

func TestImageSelection_DigestAllowListDoesNotAuthorizeOtherVersions(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("a", 64)
	otherDigest := "sha256:" + strings.Repeat("b", 64)
	const repository = "registry.example.com/security/worker"
	const fallback = "debian:stable"

	for _, allowed := range []string{repository + "@" + digest, repository + ":reviewed@" + digest} {
		t.Run(allowed, func(t *testing.T) {
			t.Parallel()
			policy := newImagePolicy(&config.Config{
				DockerAllowedImages:          allowed,
				DockerDefaultImageForPentest: fallback,
			}, fallback)

			for _, answer := range []string{repository, repository + ":latest", repository + "@" + otherDigest} {
				image, rejected := policy.resolve(answer)
				assert.True(t, rejected, "a pinned allow-list must reject %s", answer)
				assert.Equal(t, fallback, image)
			}

			image, rejected := policy.resolve(allowed)
			assert.False(t, rejected, "the exact reviewed reference remains usable")
			assert.Equal(t, allowed, image)
		})
	}
}
