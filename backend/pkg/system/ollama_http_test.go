package system

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOllamaHTTPClientRejectsAmbiguousEndpoints(t *testing.T) {
	for _, endpoint := range []string{"", "/relative", "ftp://example.com", "https://user:synthetic@example.com", "https://example.com?key=synthetic", "https://example.com#fragment"} {
		_, err := NewOllamaHTTPClient(endpoint, "", nil)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "synthetic")
	}
}

func TestOllamaHTTPClientKeepsSameOriginRedirectAndClientSettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/finish", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	original := &http.Client{Timeout: 123}
	guarded, err := NewOllamaHTTPClient(server.URL, "", original)
	require.NoError(t, err)
	require.Equal(t, original.Timeout, guarded.Timeout)
	require.Nil(t, original.Transport)
	require.Nil(t, original.CheckRedirect)
	guarded.Timeout = 0
	resp, err := guarded.Get(server.URL + "/start")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestOllamaHTTPClientBlocksCredentialsAddedAfterConstruction(t *testing.T) {
	guarded, err := NewOllamaHTTPClient("http://ollama.example", "", nil)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://ollama.example/api/tags", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer synthetic")
	_, err = guarded.Do(req)
	require.ErrorContains(t, err, "HTTPS")
	require.NotContains(t, err.Error(), "synthetic")
}
