package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestConnectionDoesNotExposeTools(t *testing.T) {
	var requests, toolsSeen atomic.Int64
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var body struct {
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		toolsSeen.Add(int64(len(body.Tools)))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"fixture","object":"chat.completion","model":"fixture","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer fake.Close()
	cfg := ConfigFrom("ollama", "fixture", fake.URL, "", "")
	cfg.Stream = false
	_, reply, err := TestConnection(context.Background(), cfg)
	if err != nil || reply != "OK" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	if requests.Load() != 1 || toolsSeen.Load() != 0 {
		t.Fatalf("requests=%d tools=%d", requests.Load(), toolsSeen.Load())
	}
}
