package ollama

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/providers/provider"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vxcontrol/langchaingo/llms"
	"github.com/vxcontrol/langchaingo/llms/streaming"
)

const securityProbeAPIKey = "synthetic-ollama-security-probe-key"

func newSecurityProbeProvider(t *testing.T, serverURL, key string) *ollamaProvider {
	t.Helper()
	cfg := &config.Config{
		OllamaServerURL: serverURL, OllamaServerAPIKey: key, OllamaServerModel: ollamaDefaultModel,
	}
	providerConfig, err := DefaultProviderConfig(cfg)
	require.NoError(t, err)
	prov, err := New(cfg, provider.DefaultProviderNameOllama, providerConfig)
	require.NoError(t, err)
	return prov.(*ollamaProvider)
}

func TestOllama_SecurityRejectsCrossOriginRedirectBeforeSendingRequest(t *testing.T) {
	t.Setenv("OLLAMA_AUTH", "false")
	t.Setenv("OLLAMA_API_KEY", "")
	var recipientHits, recipientWithCredentials atomic.Int64
	recipient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recipientHits.Add(1)
		if r.Header.Get("Authorization") == "Bearer "+securityProbeAPIKey {
			recipientWithCredentials.Add(1)
		}
		fmt.Fprintln(w, `{"model":"probe","message":{"role":"assistant","content":"redirected"},"done":true,"done_reason":"stop"}`)
	}))
	t.Cleanup(recipient.Close)
	// A different hostname makes net/http strip Authorization; the dependency's
	// auth transport then adds it again. Both destinations stay on loopback.
	otherOrigin := strings.Replace(recipient.URL, "127.0.0.1", "localhost", 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherOrigin+"/api/chat", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)
	prov := newSecurityProbeProvider(t, origin.URL, securityProbeAPIKey)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err := prov.llm.GenerateContent(ctx, []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "probe")})
	assert.Error(t, err, "a redirected inference request must fail rather than leave the configured origin")
	assert.Zero(t, recipientHits.Load(), "do not send prompts or credentials to a redirected origin")
	assert.Zero(t, recipientWithCredentials.Load(), "the dependency must not reattach the key at the redirected origin")
}

func TestOllama_SecurityPreservesAuthenticatedStreamingAtConfiguredOrigin(t *testing.T) {
	t.Setenv("OLLAMA_AUTH", "false")
	t.Setenv("OLLAMA_API_KEY", "")
	var authenticated atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+securityProbeAPIKey {
			authenticated.Add(1)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintln(w, `{"model":"probe","message":{"role":"assistant","content":"safe"},"done":false}`)
		fmt.Fprintln(w, `{"model":"probe","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop"}`)
	}))
	t.Cleanup(origin.Close)
	prov := newSecurityProbeProvider(t, origin.URL, securityProbeAPIKey)
	var streamed strings.Builder
	response, err := prov.llm.GenerateContent(t.Context(), []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "probe")},
		llms.WithStreamingFunc(func(_ context.Context, chunk streaming.Chunk) error {
			if chunk.Type == streaming.ChunkTypeText {
				streamed.WriteString(chunk.Content)
			}
			return nil
		}))
	require.NoError(t, err)
	require.NotEmpty(t, response.Choices)
	assert.Equal(t, "safe", response.Choices[0].Content)
	assert.Equal(t, "safe", streamed.String())
	assert.Equal(t, int64(1), authenticated.Load())
}

func TestOllama_SecurityRequiresTLSForRemoteAPIKeys(t *testing.T) {
	t.Setenv("OLLAMA_AUTH", "false")
	t.Setenv("OLLAMA_API_KEY", "")
	for _, tc := range []struct {
		name, serverURL, key string
		wantError            bool
	}{
		{"remote key over HTTP", "http://ollama.example:11434", securityProbeAPIKey, true},
		{"remote key over HTTPS", "https://ollama.example", securityProbeAPIKey, false},
		{"unauthenticated local HTTP", "http://127.0.0.1:11434", "", false},
		{"authenticated loopback HTTP", "http://127.0.0.1:11434", securityProbeAPIKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{OllamaServerURL: tc.serverURL, OllamaServerAPIKey: tc.key, OllamaServerModel: ollamaDefaultModel}
			providerConfig, err := DefaultProviderConfig(cfg)
			require.NoError(t, err)
			_, err = New(cfg, provider.DefaultProviderNameOllama, providerConfig)
			if tc.wantError {
				assert.Error(t, err, "reject the insecure endpoint during construction, without a network request")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
