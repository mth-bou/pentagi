# Worker and Docker control boundary

Decision recorded 2026-11-02. The UI and platform remain available, while worker
tools run with finite budgets and optional network confinement. No container
runtime can make arbitrary autonomous code completely safe on a shared kernel.

## Resource and privilege policy

Every `RunContainer` call applies the same budget as `WorkerSpec`, including the
startup sandbox probes: 2 CPU units of bandwidth, 4 GiB RAM, zero swap, 512 PIDs.
Use `DOCKER_WORKER_CPUS`, `DOCKER_WORKER_MEMORY` (bytes) and
`DOCKER_WORKER_PIDS_LIMIT` to change the per-worker ceiling. Zero restores the
default; unlimited negative values are rejected. A lower caller-provided limit
is retained. An unsupported daemon resource controller prevents application
startup instead of silently ignoring the promised limits.

Workers use the explicit capability allow-list with `CapDrop=ALL` and
`no-new-privileges:true`. Dangerous capability, device, mount, runtime, namespace
and cgroup-parent requests fail before any worker is created. SUID/SGID and
non-root `sudo`/`su` testing now require
`DOCKER_WORKER_ALLOW_PRIVILEGE_ESCALATION=true`; this opt-in keeps all other
restrictions. Run such tests in a separate disposable lab. RAM/CPU/PID ceilings
are per worker; concurrent flows and retained volumes still need aggregate and
disk budgets.

## Isolated egress

`DOCKER_EGRESS_MODE=isolated` requires an explicitly provisioned `DOCKER_NETWORK`
with driver `bridge`, `--internal`, IPv6 off, and
`com.docker.network.bridge.gateway_mode_ipv4=isolated`. The last setting removes
the bridge's host IP: an internal bridge alone still exposes host listeners.
The application validates these properties at startup and before each worker,
refuses a missing/nonconforming bridge, and never creates a replacement network
in isolated mode.

Workers join only that network. They have no default route, published callback
ports, external DNS resolver, nested Docker, `NET_ADMIN`, `NET_RAW` or host workdir mounts.
The orchestrator uses per-worker named work volumes. IPv6 is also disabled in
the worker namespace. Only targets explicitly attached to the same lab bridge
can be reached. These are the allowed destinations, at network membership level;
this is not a domain/CIDR allow-list or an HTTP proxy. Do not attach the database,
scraper, Ollama, model API endpoints, Docker API endpoint, or a forwarding proxy
to this network. Keep targets single-homed, without routing privileges. All
flows sharing this lab network can contact each other and its targets; use a
separate daemon/deployment/network for independent trust domains.

Internet package installation and remote reverse callbacks from workers are
unavailable in this mode. Prebuild the tool image and load it into the worker
daemon before starting. Image pulls by the daemon and LLM requests by the main
service are outside the worker network; protect these control-plane paths
separately. `DOCKER_EGRESS_MODE=unrestricted` is the explicit compatibility mode
for existing installations. It is still the backend/base Compose fallback, with
a startup warning. The example environment and hardened profile select isolated
mode; reviewing an existing `.env` is required. Unknown mode names fail closed.

Raw-packet scans are unavailable in isolated mode; use TCP-connect scanning
such as `nmap -sT`. Build target containers with `--cap-drop ALL` and
`--security-opt no-new-privileges:true`, and keep them on this one bridge only.
Network membership is an operator-managed trust boundary; the application does
not authorize or continuously police administrator changes to other containers.

Before switching an existing deployment or tightening limits, stop its flows
and workers and preserve any needed data. A live worker is inspected before
reuse/terminal operations: old unlimited budgets, missing privilege controls,
extra network attachments or a downgraded lab bridge cause an explicit error.
Recreate incompatible workers deliberately; the application does not silently
delete their files, stop existing background processes, or migrate them between
networks. Changing `.env` does not retroactively change a running container.

## Dedicated rootless daemon profile

The main service's Docker API access is powerful. The in-process checks above
cannot restrict a compromised service that calls that API directly. The optional
`docker-compose.hardened.yml` therefore removes the **local host** socket and
requires mTLS to a dedicated rootless daemon. `DOCKER_REQUIRE_ROOTLESS=true`
checks its reported rootless security option, cgroup v2 and delegated resource
controllers. It also forbids nested Docker, host networking and host workdirs.
This profile does not deploy or modify a daemon automatically.

Use a disposable worker VM, or a dedicated unprivileged Linux account with no
personal files, SSH credentials, Docker-group membership or sudo rights. A
compromised controller can still control everything accessible to that account
and every container on that daemon. Rootless Docker mitigates host-root access;
it is not per-flow API authorization or a VM boundary. A generic socket proxy
that permits `POST /containers/create` does not validate its dangerous body.
The existing worker-node OPA example protects nested DinD calls, not the main
service's control API. Those are different trust boundaries.

Follow Docker's [rootless setup](https://docs.docker.com/engine/security/rootless/)
and [resource-controller requirements](https://docs.docker.com/engine/security/rootless/tips/).
Do not replace or stop your current WSL Docker daemon just to try this profile.
Use a separate daemon endpoint and dedicated client certificates. Bind its TLS
listener to the private lab interface, restrict access to the controller, require
client certificates, and keep the CA private key off the controller. Store
`ca.pem`, `cert.pem`, `key.pem` in a private client directory (`0700`, key `0600`).
The control container runs as UID/GID `0:0` with all capabilities dropped. On
this WSL installation's rootful **control** daemon, stage a separate copy owned
by root so it can read the key without `DAC_OVERRIDE` (do not change ownership
of your original user-owned credentials):

```bash
sudo install -d -m 0700 -o root -g root /etc/pentagi-worker-client
sudo install -m 0600 -o root -g root /path/client/ca.pem /path/client/cert.pem \
  /path/client/key.pem /etc/pentagi-worker-client/
```

Use that directory as `PENTAGI_WORKER_TLS_DIR`. A rootless or userns-remapped
control daemon requires its own UID mapping/ownership preparation instead;
the root-owned staging example is specifically for a rootful control daemon.
Never expose unauthenticated TCP port 2375.

On that **worker daemon**, provision the lab bridge explicitly (requires an
Engine supporting isolated gateway mode; tested here with Docker 29.3.0):

```bash
docker --host tcp://WORKER:2376 --tlsverify --tlscacert /path/ca.pem \
  --tlscert /path/cert.pem --tlskey /path/key.pem network create \
  --driver bridge --internal --ipv6=false \
  --opt com.docker.network.bridge.gateway_mode_ipv4=isolated pentagi-lab
```

Attach only your disposable target containers to this bridge, without another
network. Use preloaded images and keep target services unprivileged. Then in the
fork checkout build and validate the merged configuration before starting:

```bash
docker build -t pentagi-local:hardening .
export PENTAGI_HARDENED_IMAGE=pentagi-local:hardening
export PENTAGI_WORKER_DOCKER_HOST=tcp://WORKER:2376
export PENTAGI_WORKER_TLS_DIR=/etc/pentagi-worker-client
export PENTAGI_LAB_NETWORK=pentagi-lab
docker compose -f docker-compose.yml -f docker-compose.hardened.yml config --quiet
```

The local Docker daemon builds/runs the control stack. The worker endpoint above
must be reachable **from inside the main service container**, with a certificate
SAN matching its hostname. It is not the local loopback address of that container.
Require Compose 2.24.4+ for `!override`. The override removes the ambient Ollama
signing-identity volume; use the explicit Ollama API-key configuration. Auxiliary
database/scraper services retain their base configuration and must be reviewed
before deployment, including bootstrap credentials. No service is launched by
these validation commands; this change does not publish an application image.

To roll back behavior, remove the override and explicitly select compatibility
settings. This restores the previous Docker authority and network exposure;
keep it confined to a disposable environment. Do not switch running workers to
an unrestricted bridge as a troubleshooting shortcut.

## Validation

From `backend/`, run `go test -race ./pkg/config ./pkg/docker ./pkg/providers/ollama
./pkg/providers/embeddings ./pkg/system`. Docker tests skip without a daemon.
Run the real regression probes against a dedicated test daemon:

```bash
go test ./pkg/docker -run 'TestClient_WorkerBudgetIsEnforcedByDocker|TestEgress_IsolatedWorkerCanReachOnlyItsLabNetwork' -count=1 -v
```

They inspect cgroup values and `NoNewPrivs`, retain connectivity to a healthy
lab HTTP target, and block healthy witnesses on a separate bridge and the host
gateway. They check DNS settings, IPv6 disablement and absence of a default
route. Only uniquely named test containers, volumes and networks are removed.
The rootless predicate is covered with daemon fixtures; the mTLS/rootless
deployment profile has been rendered and checked, not deployed end-to-end.
See [Ollama review](ollama-security.md) for the dependency alerts and credential
redirect regression tests.

Network rationale: [Docker gateway modes](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).
