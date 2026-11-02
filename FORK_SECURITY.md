# Security work in this fork

This fork keeps PentAGI's interface and platform features. It is a maintained
development branch, not a security-certified distribution.

## Changes implemented

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
operator opt-ins, and default image-selection behavior. Run from `backend/`:

```bash
go test -race ./pkg/config ./pkg/docker ./pkg/providers
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

1. Restrict the control service's access to Docker using a dedicated worker host
   and a narrowly scoped, tested authorization boundary. The main service still
   holds powerful Docker access in the upstream deployment architecture.
2. Enforce and test configurable CPU, memory and process budgets per worker.
3. Add an enforceable egress policy separating lab targets, host/LAN services and
   external model endpoints; prompt-based scope rules are not network controls.
4. Complete dependency and container-image remediation with reachability review,
   fresh SBOMs and runtime tests. A scanner's package count is not an exploit count.
5. Remove predictable bootstrap credentials from manual deployments without
   breaking existing databases; test both first installation and upgrades.
6. Review secret handling, persisted reports and optional telemetry. Use dedicated
   lab credentials and disposable target data while this work is ongoing.
