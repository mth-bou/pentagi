# Security work in this fork

This fork keeps PentAGI's interface and platform features. It is a maintained
development branch, not a security-certified distribution.

## Changes implemented

- The optional [hardened Compose profile](docker-compose.hardened.yml) removes
  the control service's local Docker socket, requires mTLS to a dedicated rootless
  worker daemon, and drops the control container's capabilities. Rootless and
  cgroup-controller requirements fail closed. The profile is tested as a merged
  configuration; it has not been deployed end-to-end.
- `DOCKER_EGRESS_MODE=isolated` confines workers to an explicitly provisioned
  internal bridge with an isolated gateway. It removes raw packet capability,
  callbacks, external DNS and IPv6; only targets on that bridge remain reachable.
  The example environment and hardened profile select it. The backend/base
  Compose compatibility fallback remains `unrestricted`, with a warning.
- Existing live workers are checked against the current resource, privilege and
  isolated-network policy before reuse. Incompatible workers are refused with a
  recreation error; they are not silently deleted or automatically stopped.
- Ollama chat and embedding requests cannot follow a cross-origin redirect.
  This prevents a reproduced synthetic-key leak caused by the adapter reattaching
  credentials after redirect. Authenticated remote HTTP endpoints are rejected.
  See the [eight remaining module-wide alerts and reachability review](backend/docs/ollama-security.md).
- Workers have a ceiling of 2 CPUs, 4 GiB RAM, no swap, and 512 processes.
  `DOCKER_WORKER_CPUS`, `DOCKER_WORKER_MEMORY` (bytes) and
  `DOCKER_WORKER_PIDS_LIMIT` adjust the ceilings. Zero selects the bounded default;
  negative, non-finite and out-of-range values fail validation. A caller may
  tighten these ceilings but cannot raise them through a container specification.
- `no-new-privileges` is enabled by default. Set
  `DOCKER_WORKER_ALLOW_PRIVILEGE_ESCALATION=true` only for SUID/sudo lab tests.
  This does not enable Docker privileged mode. Namespace, device, arbitrary mount,
  cgroup-parent and unapproved capability overrides are rejected before creation.
  These checks protect the application creation path; they are not an authorization
  proxy for someone who already possesses the daemon socket.
- Digest-pinned image allow-list entries require the exact reference. They no
  longer authorize an arbitrary tag or digest from the same repository.
- Worker callback ports bind to `127.0.0.1` by default, including when the Docker
  client is constructed from an empty configuration.
- Worker image selection defaults to `fixed`. Only an explicit `llm` setting
  enables model selection; unknown values fail closed to the configured image.
- The example environment no longer enables `NET_ADMIN` or supplies a host
  Docker socket for workers.
- Go is pinned to `1.26.10` for development, CI and the application build.
  `golang.org/x/net` is updated to `v0.62.0`, `go-jose/v4` to `v4.1.6`, and the
  OpenTelemetry trace exporter modules to `v1.45.0`, with required Go module
  updates. These address the audited HTML parsing, JOSE and exporter logging
  advisories; they are not a claim that every dependency is vulnerability-free.

These defaults affect new/unspecified settings. An existing `.env` containing
`DOCKER_PUBLIC_IP=0.0.0.0`, `DOCKER_NET_ADMIN=true`, or
`DOCKER_IMAGE_SELECTION_MODE=llm` remains an explicit opt-in and must be reviewed.
Local-only callback ports prevent remote reverse callbacks until an operator
selects the appropriate lab interface. They do not filter outbound connections,
and host networking bypasses port publication controls.

See [the hardening and migration guide](backend/docs/fork-hardening.md) before
activating isolated egress or the rootless profile. Existing `.env` values and
running workers do not acquire these protections merely by pulling the branch.

## Run the fork's code

The upstream `vxcontrol/pentagi` image does **not** contain this fork's Go fixes.
Build the application from this checkout, give the resulting image a local tag,
and set `PENTAGI_IMAGE` in the local `.env` to that tag before deployment:

```bash
docker build -t pentagi-local:hardening .
# In .env: PENTAGI_IMAGE=pentagi-local:hardening
```

Builds download dependencies. No hardened image has been published by this fork.
Review credentials and all auxiliary images before starting the Compose stack.

## Validation

Regression tests cover digest substitution, default worker networking, explicit
operator opt-ins, resource enforcement, privilege overrides, worker reuse,
network confinement and Ollama credential redirects. Run from `backend/`:

```bash
go test -race ./pkg/config ./pkg/docker ./pkg/providers/... ./pkg/system
```

The Docker package also contains daemon integration tests. An unavailable daemon
causes those tests to skip; a passing unit suite alone does not prove runtime
isolation. Use a dedicated test daemon or disposable VM for those checks.

The loopback integration regression can be run separately against a test daemon:

```bash
go test ./pkg/docker -run TestClient_DefaultConfigPublishesWorkerPortsOnlyOnLoopback -v
```

It starts a short-lived Alpine probe and checks the Docker daemon's published
bindings and mounts, without running an agent or an LLM request. It removes its
container and work volume on completion.

## Remaining security work

1. Validate the optional rootless/mTLS deployment end-to-end on the dedicated
   worker environment. The controller retains full API authority over that
   dedicated daemon; per-flow API authorization remains future work. The base
   deployment still mounts the host Docker socket.
2. Bound the aggregate number of concurrent workers and retained work volumes;
   per-worker cgroup ceilings do not bound the whole deployment or disk usage.
3. Extend the isolated lab mode with independently enforced per-flow target
   allow-lists or controlled Internet access when needed. Current confinement
   uses network membership, not domain/CIDR allow-lists or per-flow isolation.
4. Complete dependency and container-image remediation with reachability review,
   fresh SBOMs and runtime tests. A scanner's package count is not an exploit count.
5. Remove predictable bootstrap credentials from manual deployments without
   breaking existing databases; test both first installation and upgrades.
6. Review secret handling, persisted reports and optional telemetry. Use dedicated
   lab credentials and disposable target data while this work is ongoing.
