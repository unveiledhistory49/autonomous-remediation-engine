package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProposer_NVIDIAFormat(t *testing.T) {
	expectedModel := "nvidia/nemotron-3-ultra-550b-a55b"
	apiKey := "nvapi-test-secret-key"
	incidentLog := "2026-09-22T22:00:00Z [FATAL] storage: Disk /var/log/ai-gateway at 98% capacity, write failed with ENOSPC"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("expected path ending in /chat/completions, got %s", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer "+apiKey {
			t.Errorf("expected Authorization Bearer %s, got %s", apiKey, auth)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		var req chatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if req.Model != expectedModel {
			t.Errorf("expected model %s, got %s", expectedModel, req.Model)
		}
		if len(req.Messages) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(req.Messages))
		}
		if req.Messages[0].Role != "system" || !strings.Contains(req.Messages[0].Content, "RBK-DISK-001") {
			t.Errorf("system prompt missing catalog or role: %s", req.Messages[0].Content)
		}
		if req.Messages[1].Role != "user" || !strings.Contains(req.Messages[1].Content, incidentLog) {
			t.Errorf("user message missing incident log: %s", req.Messages[1].Content)
		}

		resp := chatCompletionResponse{
			ID: "chatcmpl-test-123",
			Choices: []struct {
				Index   int `json:"index"`
				Message struct {
					Role             string `json:"role"`
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content,omitempty"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Index: 0,
					Message: struct {
						Role             string `json:"role"`
						Content          string `json:"content"`
						ReasoningContent string `json:"reasoning_content,omitempty"`
					}{
						Role:             "assistant",
						Content:          `{"runbook_id": "RBK-DISK-001", "target_resource": "/var/log/ai-gateway", "severity": "HIGH", "diagnosis": "Disk volume capacity saturated at 98% with ENOSPC write errors."}`,
						ReasoningContent: "Analyzed log: disk fullness detected at 98% on /var/log/ai-gateway. Matching against RBK-DISK-001 safe log drain.",
					},
					FinishReason: "stop",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		BaseURL: server.URL,
		APIKey:  apiKey,
		Model:   expectedModel,
	}

	proposer, err := NewProposer(cfg)
	if err != nil {
		t.Fatalf("failed to create proposer: %v", err)
	}

	proposal, err := proposer.ProposeRemediation(context.Background(), incidentLog)
	if err != nil {
		t.Fatalf("ProposeRemediation failed: %v", err)
	}

	if proposal.RunbookID != "RBK-DISK-001" {
		t.Errorf("expected RunbookID RBK-DISK-001, got %s", proposal.RunbookID)
	}
	if proposal.TargetResource != "/var/log/ai-gateway" {
		t.Errorf("expected TargetResource /var/log/ai-gateway, got %s", proposal.TargetResource)
	}
	if proposal.Severity != "HIGH" {
		t.Errorf("expected Severity HIGH, got %s", proposal.Severity)
	}
	if !strings.Contains(proposal.Diagnosis, "Disk volume capacity saturated") {
		t.Errorf("unexpected diagnosis: %s", proposal.Diagnosis)
	}
	if !strings.Contains(proposal.ReasoningContent, "Analyzed log: disk fullness detected") {
		t.Errorf("unexpected reasoning content: %s", proposal.ReasoningContent)
	}
}

func TestProposer_MarkdownCodeFence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := chatCompletionResponse{
			Choices: []struct {
				Index   int `json:"index"`
				Message struct {
					Role             string `json:"role"`
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content,omitempty"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Message: struct {
						Role             string `json:"role"`
						Content          string `json:"content"`
						ReasoningContent string `json:"reasoning_content,omitempty"`
					}{
						Role: "assistant",
						Content: "Here is the triage output:\n```json\n{\n" +
							"  \"runbook_id\": \"RBK-PROC-001\",\n" +
							"  \"target_resource\": \"ai-gateway\",\n" +
							"  \"severity\": \"CRITICAL\",\n" +
							"  \"diagnosis\": \"Thread deadlock detected\"\n" +
							"}\n```\nHope this helps!",
						ReasoningContent: "Identified hung worker process.",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	proposal, err := ProposeRemediation(context.Background(), Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}, "worker hang log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if proposal.RunbookID != "RBK-PROC-001" {
		t.Errorf("expected RBK-PROC-001, got %s", proposal.RunbookID)
	}
	if proposal.TargetResource != "ai-gateway" {
		t.Errorf("expected ai-gateway, got %s", proposal.TargetResource)
	}
	if proposal.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", proposal.Severity)
	}
	if proposal.ReasoningContent != "Identified hung worker process." {
		t.Errorf("expected reasoning trace, got %s", proposal.ReasoningContent)
	}
}

func TestProposer_ThinkTagsExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := chatCompletionResponse{
			Choices: []struct {
				Index   int `json:"index"`
				Message struct {
					Role             string `json:"role"`
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content,omitempty"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Message: struct {
						Role             string `json:"role"`
						Content          string `json:"content"`
						ReasoningContent string `json:"reasoning_content,omitempty"`
					}{
						Role: "assistant",
						Content: "<think>Step 1: Check TLS cert expiration. Step 2: Select RBK-TLS-001.</think>\n" +
							`{"runbook_id": "RBK-TLS-001", "target_resource": "ai-gateway", "severity": "HIGH", "diagnosis": "TLS certificate expired"}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	proposal, err := ProposeRemediation(context.Background(), Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}, "cert expired log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if proposal.RunbookID != "RBK-TLS-001" {
		t.Errorf("expected RBK-TLS-001, got %s", proposal.RunbookID)
	}
	if !strings.Contains(proposal.ReasoningContent, "Select RBK-TLS-001") {
		t.Errorf("expected reasoning trace from think tags, got %s", proposal.ReasoningContent)
	}
}

func TestProposer_AliasMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := chatCompletionResponse{
			Choices: []struct {
				Index   int `json:"index"`
				Message struct {
					Role             string `json:"role"`
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content,omitempty"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Message: struct {
						Role             string `json:"role"`
						Content          string `json:"content"`
						ReasoningContent string `json:"reasoning_content,omitempty"`
					}{
						Role:    "assistant",
						Content: `{"runbook_id": "config_rollback", "target_resource": "/etc/ai-gateway/config.yaml", "severity": "HIGH", "diagnosis": "Corrupted YAML syntax"}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	proposal, err := ProposeRemediation(context.Background(), Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}, "config syntax error")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if proposal.RunbookID != "RBK-CFG-001" {
		t.Errorf("expected alias config_rollback to normalize to RBK-CFG-001, got %s", proposal.RunbookID)
	}
}

func TestProposer_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": {"message": "Invalid API Key"}}`))
	}))
	defer server.Close()

	_, err := ProposeRemediation(context.Background(), Config{
		BaseURL: server.URL,
		APIKey:  "invalid-key",
	}, "incident log")
	if err == nil {
		t.Fatal("expected error on HTTP 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected error to mention 401, got %v", err)
	}
}

func TestProposer_UnauthorizedRunbookRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := chatCompletionResponse{
			Choices: []struct {
				Index   int `json:"index"`
				Message struct {
					Role             string `json:"role"`
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content,omitempty"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Message: struct {
						Role             string `json:"role"`
						Content          string `json:"content"`
						ReasoningContent string `json:"reasoning_content,omitempty"`
					}{
						Role:    "assistant",
						Content: `{"runbook_id": "RBK-UNAUTHORIZED-RM-RF", "target_resource": "/root", "severity": "CRITICAL", "diagnosis": "Dangerous action"}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	_, err := ProposeRemediation(context.Background(), Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}, "dangerous request")
	if err == nil {
		t.Fatal("expected error for unauthorized runbook ID, got nil")
	}
	if !strings.Contains(err.Error(), "unauthorized") && !strings.Contains(err.Error(), "unrecognized") {
		t.Errorf("expected error to mention unauthorized runbook, got %v", err)
	}
}

func TestProposer_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := ProposeRemediation(ctx, Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}, "incident")
	if err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
}

func TestProposer_EmptyConfig(t *testing.T) {
	_, err := NewProposer(Config{BaseURL: "", APIKey: "key"})
	if err == nil {
		t.Error("expected error for empty BaseURL")
	}

	_, err = NewProposer(Config{BaseURL: "http://localhost", APIKey: ""})
	if err == nil {
		t.Error("expected error for empty APIKey")
	}
}
