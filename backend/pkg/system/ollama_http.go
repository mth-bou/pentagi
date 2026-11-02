package system

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// NewOllamaHTTPClient confines SDK requests to the configured origin. Some
// SDK transports reattach bearer credentials after net/http strips them on a
// redirect, so checking only the original request's headers is insufficient.
// The caller's client and transport are preserved without mutating shared state.
func NewOllamaHTTPClient(serverURL, apiKey string, original *http.Client) (*http.Client, error) {
	base, err := url.Parse(serverURL)
	if err != nil || base.Hostname() == "" || (base.Scheme != "http" && base.Scheme != "https") ||
		base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Opaque != "" {
		return nil, fmt.Errorf("Ollama endpoint must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	if apiKey != "" && !ollamaCredentialsSafe(base) {
		return nil, fmt.Errorf("Ollama API keys require HTTPS outside loopback")
	}
	if original == nil {
		original = http.DefaultClient
	}
	copyClient := *original
	transport := copyClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	copyClient.Transport = &ollamaOriginTransport{origin: base, transport: transport}
	copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !sameOllamaOrigin(base, req.URL) {
			return fmt.Errorf("Ollama redirect outside the configured origin is blocked")
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many Ollama redirects")
		}
		if original.CheckRedirect != nil {
			return original.CheckRedirect(req, via)
		}
		return nil
	}
	return &copyClient, nil
}

type ollamaOriginTransport struct {
	origin    *url.URL
	transport http.RoundTripper
}

func (t *ollamaOriginTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !sameOllamaOrigin(t.origin, req.URL) || req.URL.User != nil {
		return nil, fmt.Errorf("Ollama request outside the configured origin is blocked")
	}
	// Also covers credentials added by SDK environment variables or signing.
	if req.Header.Get("Authorization") != "" && !ollamaCredentialsSafe(req.URL) {
		return nil, fmt.Errorf("Ollama credentials require HTTPS outside loopback")
	}
	return t.transport.RoundTrip(req)
}

func ollamaCredentialsSafe(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	// Do not trust DNS names such as localhost for this exception: a custom
	// resolver or proxy could route them elsewhere. Use a literal loopback IP.
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.IsLoopback()
}

func sameOllamaOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && ollamaPort(a) == ollamaPort(b)
}

func ollamaPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
