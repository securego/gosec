package autofix

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/securego/gosec/v2/issue"
)

// fakeLiteLLMProxy serves /v1/models and /v1/chat/completions like a LiteLLM
// proxy and records the chat requests it receives.
type fakeLiteLLMProxy struct {
	models       []string
	reply        string
	finishReason string
	chatStatus   int
	authStatus   int

	mu       sync.Mutex
	requests []map[string]any
	auth     []string
}

func (p *fakeLiteLLMProxy) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.auth = append(p.auth, r.Header.Get("Authorization"))
		p.mu.Unlock()
		if p.authStatus != 0 {
			w.WriteHeader(p.authStatus)
			_, _ = io.WriteString(w, `{"error":{"message":"Authentication Error, invalid proxy server token passed","type":"auth_error"}}`)
			return
		}
		data := make([]map[string]string, 0, len(p.models))
		for _, m := range p.models {
			data = append(data, map[string]string{"id": m, "object": "model"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		p.mu.Lock()
		p.requests = append(p.requests, body)
		p.auth = append(p.auth, r.Header.Get("Authorization"))
		p.mu.Unlock()
		if p.chatStatus != 0 {
			w.WriteHeader(p.chatStatus)
			_, _ = io.WriteString(w, `{"error":{"message":"litellm.BadRequestError: model rejected the request","type":"invalid_request_error"}}`)
			return
		}
		finishReason := p.finishReason
		if finishReason == "" {
			finishReason = "stop"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-1",
			"object":  "chat.completion",
			"created": 1,
			"model":   body["model"],
			"choices": []map[string]any{{
				"index":         0,
				"finish_reason": finishReason,
				"message":       map[string]any{"role": "assistant", "content": p.reply},
			}},
		})
	})
	return mux
}

func newFakeLiteLLMProxy(t *testing.T, p *fakeLiteLLMProxy) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(p.handler(t))
	t.Cleanup(server.Close)
	return server
}

func TestParseLiteLLMModel(t *testing.T) {
	tests := []struct {
		input    string
		isLite   bool
		expected string
	}{
		{input: "litellm", isLite: true, expected: ""},
		{input: "litellm/claude-sonnet-4-6", isLite: true, expected: "claude-sonnet-4-6"},
		{input: "litellm:gemini-2.5-flash", isLite: true, expected: "gemini-2.5-flash"},
		{input: "litellm/bedrock/anthropic.claude-3-haiku", isLite: true, expected: "bedrock/anthropic.claude-3-haiku"},
		{input: "litellm/", isLite: true, expected: ""},
		{input: "litellmx", isLite: false, expected: ""},
		{input: "claude-sonnet-4-6", isLite: false, expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.isLite, isLiteLLMModel(tt.input))
			assert.Equal(t, tt.expected, parseLiteLLMModel(tt.input))
		})
	}
}

func TestLiteLLMBaseURL(t *testing.T) {
	assert.Equal(t, "http://localhost:4000/v1", liteLLMBaseURL(""))
	assert.Equal(t, "http://localhost:4000/v1", liteLLMBaseURL("http://localhost:4000"))
	assert.Equal(t, "http://localhost:4000/v1", liteLLMBaseURL(" http://localhost:4000/v1/ "))
	assert.Equal(t, "https://llm.example.com/team/v1", liteLLMBaseURL("https://llm.example.com/team"))
}

func TestLiteLLMClient_SendsChatCompletionToProxy(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"gpt-4.1-mini", "claude-sonnet-4-6"}, reply: "  Use parameterized queries.  "}
	server := newFakeLiteLLMProxy(t, proxy)

	client, err := newLiteLLMClient(context.Background(), liteLLMConfig{
		Model:   "litellm/claude-sonnet-4-6",
		APIKey:  "test-proxy-key",
		BaseURL: server.URL + "/",
	})
	require.NoError(t, err)

	resp, err := client.GenerateSolution(context.Background(), "fix G201")
	require.NoError(t, err)
	assert.Equal(t, "Use parameterized queries.", resp)

	require.Len(t, proxy.requests, 1)
	req := proxy.requests[0]
	assert.Equal(t, "claude-sonnet-4-6", req["model"])
	assert.Equal(t, true, req["drop_params"])
	// No output limit: a reasoning model could spend it all before answering.
	assert.NotContains(t, req, "max_tokens")
	messages, ok := req["messages"].([]any)
	require.True(t, ok)
	require.Len(t, messages, 1)
	assert.Equal(t, map[string]any{"role": "user", "content": "fix G201"}, messages[0])
	for _, auth := range proxy.auth {
		assert.Equal(t, "Bearer test-proxy-key", auth)
	}
}

func TestLiteLLMClient_AcceptsV1BaseURL(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"gpt-4.1-mini"}, reply: "ok"}
	server := newFakeLiteLLMProxy(t, proxy)

	client, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm:gpt-4.1-mini", BaseURL: server.URL + "/v1"})
	require.NoError(t, err)

	_, err = client.GenerateSolution(context.Background(), "prompt")
	require.NoError(t, err)
	require.Len(t, proxy.requests, 1)
}

func TestLiteLLMClient_BareProviderUsesFirstProxyModel(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"gemini-2.5-flash", "gpt-4.1-mini", "gemini-2.5-flash"}, reply: "ok"}
	server := newFakeLiteLLMProxy(t, proxy)

	client, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm", BaseURL: server.URL})
	require.NoError(t, err)

	_, err = client.GenerateSolution(context.Background(), "prompt")
	require.NoError(t, err)
	require.Len(t, proxy.requests, 1)
	assert.Equal(t, "gemini-2.5-flash", proxy.requests[0]["model"])
}

func TestLiteLLMClient_UnknownModelFailsBeforeAnyRequest(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"gpt-4.1-mini", "gemini-2.5-flash"}}
	server := newFakeLiteLLMProxy(t, proxy)

	_, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm/gpt-4.1-mni", BaseURL: server.URL})
	require.EqualError(t, err, `model "gpt-4.1-mni" is not served by the litellm proxy at `+server.URL+`/v1; available models: gpt-4.1-mini, gemini-2.5-flash`)
	assert.Empty(t, proxy.requests)
}

func TestLiteLLMClient_EmptyModelList(t *testing.T) {
	proxy := &fakeLiteLLMProxy{}
	server := newFakeLiteLLMProxy(t, proxy)

	_, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm", BaseURL: server.URL})
	require.ErrorContains(t, err, "lists no models")

	// A named model is still sent when the proxy lists nothing (for example a
	// key restricted from listing models).
	client, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm/gpt-4.1-mini", BaseURL: server.URL})
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestLiteLLMClient_RejectedKey(t *testing.T) {
	proxy := &fakeLiteLLMProxy{authStatus: http.StatusUnauthorized}
	server := newFakeLiteLLMProxy(t, proxy)

	_, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm/gpt-4.1-mini", APIKey: "bad", BaseURL: server.URL})
	require.EqualError(t, err, "listing litellm models: 401 Unauthorized: Authentication Error, invalid proxy server token passed")
	assert.Empty(t, proxy.requests)
}

func TestLiteLLMClient_ProxyErrorIsReported(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"gpt-4.1-mini"}, chatStatus: http.StatusBadRequest}
	server := newFakeLiteLLMProxy(t, proxy)

	client, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm/gpt-4.1-mini", BaseURL: server.URL})
	require.NoError(t, err)

	_, err = client.GenerateSolution(context.Background(), "prompt")
	require.EqualError(t, err, `generating autofix with litellm model "gpt-4.1-mini": 400 litellm.BadRequestError: model rejected the request`)
}

func TestLiteLLMClient_EmptyReply(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"gpt-4.1-mini"}, reply: " "}
	server := newFakeLiteLLMProxy(t, proxy)

	client, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm/gpt-4.1-mini", BaseURL: server.URL})
	require.NoError(t, err)

	_, err = client.GenerateSolution(context.Background(), "prompt")
	require.EqualError(t, err, "nothing found in the first autofix returned by litellm")
}

func TestLiteLLMClient_OutputLimitBeforeAnswer(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"xyz-agent"}, finishReason: "length"}
	server := newFakeLiteLLMProxy(t, proxy)

	client, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm/xyz-agent", BaseURL: server.URL})
	require.NoError(t, err)

	_, err = client.GenerateSolution(context.Background(), "prompt")
	require.EqualError(t, err, `litellm model "xyz-agent" hit its output limit before answering`)
}

func TestLiteLLMClient_SkipSSL(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"gpt-4.1-mini"}, reply: "ok"}
	server := httptest.NewTLSServer(proxy.handler(t))
	t.Cleanup(server.Close)

	_, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm/gpt-4.1-mini", BaseURL: server.URL})
	require.Error(t, err, "self-signed certificate must be rejected by default")

	client, err := newLiteLLMClient(context.Background(), liteLLMConfig{Model: "litellm/gpt-4.1-mini", BaseURL: server.URL, SkipSSL: true})
	require.NoError(t, err)
	_, err = client.GenerateSolution(context.Background(), "prompt")
	require.NoError(t, err)
}

func TestNewLiteLLMHTTPClient_KeepsProxyEnvironment(t *testing.T) {
	for _, skipSSL := range []bool{false, true} {
		transport, ok := newLiteLLMHTTPClient(skipSSL).Transport.(*http.Transport)
		require.True(t, ok)
		assert.NotNil(t, transport.Proxy)
		if skipSSL {
			require.NotNil(t, transport.TLSClientConfig)
			assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
		}
	}
}

// A claude-named proxy alias behind the litellm prefix must reach the proxy,
// not the native Anthropic client.
func TestGenerateSolution_LiteLLMRoutesClaudeAliasToProxy(t *testing.T) {
	proxy := &fakeLiteLLMProxy{models: []string{"claude-sonnet-4-6"}, reply: "Validate the input."}
	server := newFakeLiteLLMProxy(t, proxy)

	issues := []*issue.Issue{{What: "Potential file inclusion via variable"}}
	err := GenerateSolution("litellm/claude-sonnet-4-6", "test-proxy-key", server.URL, false, issues)
	require.NoError(t, err)
	assert.Equal(t, "Validate the input.", issues[0].Autofix)
	require.Len(t, proxy.requests, 1)
	assert.Equal(t, "claude-sonnet-4-6", proxy.requests[0]["model"])
}

func TestGenerateSolution_LiteLLMUnreachableProxy(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	err := GenerateSolution("litellm/gpt-4.1-mini", "", url, false, []*issue.Issue{{What: "x"}})
	require.ErrorContains(t, err, "initializing AI client: listing litellm models")
}
