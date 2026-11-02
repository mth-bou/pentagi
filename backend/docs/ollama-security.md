# Ollama security review in this fork

Reviewed 2026-11-02 against `github.com/ollama/ollama v0.32.5`.

## Application transport fix

The LangChain Ollama adapter installs an authentication RoundTripper that attaches
the configured key on **every** request. After a cross-origin HTTP redirect,
Go's usual header stripping therefore did not prevent a key from being sent to
the new destination. Local regression servers reproduced this for chat and
embeddings using a synthetic key.

This fork wraps the HTTP client used by both adapters. The redirect policy and
the final transport reject a different scheme, hostname or effective port.
Prompts and embeddings never follow a cross-origin redirect, even without a key.
Authenticated non-loopback endpoints require HTTPS; literal loopback HTTP is
accepted for local service/testing. URL credentials, queries and fragments are
rejected. Credentials added later by SDK environment settings are checked at the
transport boundary as well. Existing TLS verification, proxy, timeout and
same-origin redirect settings remain in effect. Configure a trusted transport
and leave `EXTERNAL_SSL_INSECURE=false`.

This is a separate application integration flaw, not a claim to fix the server
advisories below. The server must still be updated and isolated independently.

## Scanner alerts and reachability

The Go database supplies module-wide records without precise affected packages
or symbols for these eight advisories. `govulncheck` consequently reports calls
to the imported API client. No ignore rule or dependency replacement has been
added to silence them.

| Go advisory | Affected operation described by the advisory | PentAGI review |
| --- | --- | --- |
| [3557](https://pkg.go.dev/vuln/GO-2025-3557) | Unbounded allocation importing a crafted GGUF model | Server/model parser, absent from this application build |
| [3558](https://pkg.go.dev/vuln/GO-2025-3558) | Out-of-bounds read of crafted GGUF | Server/model parser, absent |
| [3559](https://pkg.go.dev/vuln/GO-2025-3559) | GGUF padding division by zero | Server/model parser, absent |
| [3582](https://pkg.go.dev/vuln/GO-2025-3582) | GGUF null dereference | Server/model parser, absent |
| [3689](https://pkg.go.dev/vuln/GO-2025-3689) | Crafted GGUF block count division by zero | Server/model parser, absent |
| [3695](https://pkg.go.dev/vuln/GO-2025-3695) | Manifest processing in server `/api/pull` | Server implementation absent; optional pulls invoke an external server |
| [3824](https://pkg.go.dev/vuln/GO-2025-3824) | Registry authentication realm token exposure during server model pull | Server implementation absent; upstream [fix #13738](https://github.com/ollama/ollama/pull/13738) exists, but the Go record still gives no fixed version |
| [4251](https://pkg.go.dev/vuln/GO-2025-4251) | Unauthenticated server model-management API | PentAGI is a client; protect the external server API separately |

The compiled dependency graph of `./cmd/pentagi` contains only Ollama `api`,
`auth`, `envconfig`, `format`, `internal/orderedmap`, `types/model` and `version`.
It contains no Ollama server or GGUF parser. This supports deferring these
module-wide alerts **for the PentAGI binary**; it does not establish the security
of a separate Ollama daemon, a model file, or a container image.

Keep `OLLAMA_SERVER_PULL_MODELS_ENABLED=false`. Preload trusted models through
an administrator-controlled path. Bind a local Ollama server to loopback; use
authenticated TLS for a remote one and do not put it on the worker lab network.
PentAGI's Compose stack does not deploy an Ollama server, so there is no local
daemon update implied by this patch.

Recheck on every Ollama dependency/server update and by 2026-12-02 at the latest:

```bash
cd backend
go list -deps ./cmd/pentagi | rg '^github.com/ollama/ollama/'
govulncheck ./cmd/pentagi
go test -race ./pkg/providers/ollama ./pkg/providers/embeddings ./pkg/system
```

The source scanner is expected to continue reporting the eight module-wide
records until upstream database metadata becomes more precise. Evaluate new
advisories rather than accepting their presence as a permanent baseline.
