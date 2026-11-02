package embeddings

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const embeddingSecurityProbeKey = "synthetic-embedding-security-probe-key"

func TestEmbedder_OllamaSecurityRejectsCrossOriginRedirectBeforeSendingRequest(t *testing.T) {
	t.Setenv("OLLAMA_AUTH", "false")
	t.Setenv("OLLAMA_API_KEY", "")
	var recipientHits, recipientWithCredentials atomic.Int64
	recipient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recipientHits.Add(1)
		if r.Header.Get("Authorization") == "Bearer "+embeddingSecurityProbeKey {
			recipientWithCredentials.Add(1)
		}
		fmt.Fprintln(w, `{"embedding":[0.1,0.2]}`)
	}))
	t.Cleanup(recipient.Close)
	otherOrigin := strings.Replace(recipient.URL, "127.0.0.1", "localhost", 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherOrigin+"/api/embeddings", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)
	e, err := newOllama(&config.Config{
		OllamaServerURL: origin.URL, OllamaServerAPIKey: embeddingSecurityProbeKey,
		EmbeddingModel: "nomic-embed-text", EmbeddingBatchSize: 512,
	}, origin.Client())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err = e.EmbedDocuments(ctx, []string{"private probe text"})
	assert.Error(t, err)
	assert.Zero(t, recipientHits.Load(), "embedding data must stay at the configured origin")
	assert.Zero(t, recipientWithCredentials.Load(), "the transport must not reattach the key at a redirected origin")
}

func TestEmbedder_OllamaSecurityPreservesAuthenticatedEmbedding(t *testing.T) {
	t.Setenv("OLLAMA_AUTH", "false")
	t.Setenv("OLLAMA_API_KEY", "")
	var authenticated atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+embeddingSecurityProbeKey {
			authenticated.Add(1)
		}
		fmt.Fprintln(w, `{"embedding":[0.1,0.2]}`)
	}))
	t.Cleanup(origin.Close)
	e, err := newOllama(&config.Config{
		OllamaServerURL: origin.URL, OllamaServerAPIKey: embeddingSecurityProbeKey,
		EmbeddingModel: "nomic-embed-text", EmbeddingBatchSize: 512,
	}, origin.Client())
	require.NoError(t, err)
	embeddings, err := e.EmbedDocuments(t.Context(), []string{"probe"})
	require.NoError(t, err)
	assert.Equal(t, [][]float32{{0.1, 0.2}}, embeddings)
	assert.Equal(t, int64(1), authenticated.Load())
}

func TestEmbedder_OllamaSecurityRejectsRemoteHTTPAPIKeyDuringConstruction(t *testing.T) {
	t.Setenv("OLLAMA_API_KEY", "")
	_, err := newOllama(&config.Config{
		OllamaServerURL: "http://ollama.example:11434", OllamaServerAPIKey: embeddingSecurityProbeKey,
		EmbeddingModel: "nomic-embed-text", EmbeddingBatchSize: 512,
	}, &http.Client{})
	assert.Error(t, err, "an inherited chat key also requires TLS at a remote embedding endpoint")
}
