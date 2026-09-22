package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Authorized Runbook Catalog Identifiers
const (
	RunbookDiskCleanup    = "RBK-DISK-001"
	RunbookProcessHang    = "RBK-PROC-001"
	RunbookTLSRotation    = "RBK-TLS-001"
	RunbookConfigRollback = "RBK-CFG-001"
)

// DefaultSystemPrompt instructs the LLM to behave as an SRE Incident Triage Agent
// and specifies the authorized runbook catalog and JSON response schema.
const DefaultSystemPrompt = `You are an expert SRE Incident Triage Agent for an Autonomous Remediation Engine.
Your job is to analyze unstructured system incident logs, metrics, alerts, and stack traces, diagnose the root cause, and select the exact matching deterministic runbook from the authorized runbook catalog.

AUTHORIZED RUNBOOK CATALOG:
1. RBK-DISK-001 (disk_cleanup_var_log):
   - Description: Safe log partition drain. Prunes rotated archive logs (*.gz, *.log.1) while preserving active log inodes and validating filesystem space.
   - Use for: Disk capacity saturation, out of disk space errors, /var/log partition fullness (>85%), filesystem write failures due to ENOSPC.
   - Target Resource: The affected directory path (e.g. "/var/log", "/var/log/ai-gateway", "/tmp").
   - Severity: HIGH

2. RBK-PROC-001 (service_deadlock_restart):
   - Description: Process hang / deadlock recovery via escalation ladder (SIGTERM -> graceful wait -> SIGKILL -> respawn -> socket binding & health assertion).
   - Use for: Deadlocked thread pool, hung process, unresponsive health checks (/healthz timeout), process unresponsiveness, missing heartbeats.
   - Target Resource: The affected service or process name (e.g. "ai-gateway").
   - Severity: CRITICAL

3. RBK-TLS-001 (tls_cert_rotation):
   - Description: Automated TLS certificate rotation and zero-downtime reload.
   - Use for: Expired or expiring TLS/mTLS certificates (< 7 days), TLS handshake failures, certificate verification failures, invalid x509 certs.
   - Target Resource: Service name or certificate path (e.g. "ai-gateway", "/etc/ssl/certs/ai-gateway.crt").
   - Severity: HIGH

4. RBK-CFG-001 (config_rollback):
   - Description: Rollback of invalid configuration to last known good (LKG) backup with schema validation.
   - Use for: Crash loop after config change, invalid JSON/YAML configuration, parse errors, schema validation failures.
   - Target Resource: Configuration file path (e.g. "/etc/ai-gateway/config.yaml").
   - Severity: HIGH

RESPONSE INSTRUCTIONS:
Analyze the provided incident log carefully. You MUST return ONLY a valid JSON object matching the following schema:
{
  "runbook_id": "RBK-DISK-001" | "RBK-PROC-001" | "RBK-TLS-001" | "RBK-CFG-001",
  "target_resource": "<affected resource path or service name>",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "diagnosis": "<concise explanation of root cause and observed failure>"
}
Do not wrap your output in conversational text. Return the JSON object only.`

// Config specifies configuration for the AI Incident Triage Proposer.
type Config struct {
	BaseURL    string
	APIKey     string
	Model      string
	Timeout    time.Duration
	HTTPClient *http.Client
}

// Proposal represents the structured triage recommendation produced by the LLM.
type Proposal struct {
	RunbookID        string `json:"runbook_id"`
	TargetResource   string `json:"target_resource"`
	Severity         string `json:"severity"`
	Diagnosis        string `json:"diagnosis"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

// Proposer communicates with an OpenAI/NVIDIA-compatible inference endpoint to triage incidents.
type Proposer struct {
	cfg        Config
	httpClient *http.Client
}

// NewProposer constructs a new Proposer with validation and defaults.
func NewProposer(cfg Config) (*Proposer, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("ai proposer: BaseURL cannot be empty")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("ai proposer: APIKey cannot be empty")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		cfg.Model = "nvidia/nemotron-3-ultra-550b-a55b"
	}
	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &Proposer{
		cfg:        cfg,
		httpClient: client,
	}, nil
}

// ProposeRemediation is a package-level helper that initializes a Proposer and generates a proposal.
func ProposeRemediation(ctx context.Context, cfg Config, incidentLog string) (*Proposal, error) {
	p, err := NewProposer(cfg)
	if err != nil {
		return nil, err
	}
	return p.ProposeRemediation(ctx, incidentLog)
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatCompletionResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role             string `json:"role"`
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    any    `json:"code"`
	} `json:"error,omitempty"`
}

type intermediateProposal struct {
	RunbookID         string `json:"runbook_id"`
	RunbookIDAlt      string `json:"runbookId"`
	TargetResource    string `json:"target_resource"`
	TargetResourceAlt string `json:"targetResource"`
	Severity          string `json:"severity"`
	Diagnosis         string `json:"diagnosis"`
	ReasoningContent  string `json:"reasoning_content"`
	ReasoningAlt      string `json:"reasoning"`
}

// ProposeRemediation sends a chat completion request to [BaseURL]/chat/completions,
// instructs the model to act as an SRE Incident Triage Agent, and parses the returned JSON proposal.
func (p *Proposer) ProposeRemediation(ctx context.Context, incidentLog string) (*Proposal, error) {
	if strings.TrimSpace(incidentLog) == "" {
		return nil, errors.New("ai proposer: incidentLog cannot be empty")
	}

	endpoint := strings.TrimRight(p.cfg.BaseURL, "/")
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}

	reqPayload := chatCompletionRequest{
		Model: p.cfg.Model,
		Messages: []chatMessage{
			{
				Role:    "system",
				Content: DefaultSystemPrompt,
			},
			{
				Role:    "user",
				Content: fmt.Sprintf("Incident Log / Telemetry:\n\n%s", incidentLog),
			},
		},
		Temperature: 0.1,
		MaxTokens:   1024,
	}

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("ai proposer: failed to marshal request payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ai proposer: failed to create http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ai proposer: http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ai proposer: failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ai proposer: inference endpoint returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var chatResp chatCompletionResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return nil, fmt.Errorf("ai proposer: failed to unmarshal completion response: %w (raw: %s)", err, string(respBytes))
	}

	if chatResp.Error != nil && chatResp.Error.Message != "" {
		return nil, fmt.Errorf("ai proposer: inference API error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return nil, errors.New("ai proposer: no completion choices returned by model")
	}

	choice := chatResp.Choices[0]
	rawContent := choice.Message.Content
	reasoning := choice.Message.ReasoningContent

	// Extract reasoning trace from <think> tags if reasoning_content was empty
	if thinkReasoning, cleaned := extractThinkTags(rawContent); thinkReasoning != "" {
		if reasoning == "" {
			reasoning = thinkReasoning
		}
		rawContent = cleaned
	}

	jsonStr, err := extractJSON(rawContent)
	if err != nil {
		return nil, fmt.Errorf("ai proposer: %w", err)
	}

	var intermediate intermediateProposal
	if err := json.Unmarshal([]byte(jsonStr), &intermediate); err != nil {
		return nil, fmt.Errorf("ai proposer: failed to unmarshal proposal schema: %w (payload: %s)", err, jsonStr)
	}

	rbID := intermediate.RunbookID
	if rbID == "" {
		rbID = intermediate.RunbookIDAlt
	}
	rbID = normalizeRunbookID(rbID)

	targetRes := intermediate.TargetResource
	if targetRes == "" {
		targetRes = intermediate.TargetResourceAlt
	}
	targetRes = strings.TrimSpace(targetRes)

	severity := strings.TrimSpace(strings.ToUpper(intermediate.Severity))
	if severity == "" {
		severity = "HIGH"
	}

	diag := strings.TrimSpace(intermediate.Diagnosis)

	if reasoning == "" {
		if intermediate.ReasoningContent != "" {
			reasoning = strings.TrimSpace(intermediate.ReasoningContent)
		} else if intermediate.ReasoningAlt != "" {
			reasoning = strings.TrimSpace(intermediate.ReasoningAlt)
		}
	}

	proposal := &Proposal{
		RunbookID:        rbID,
		TargetResource:   targetRes,
		Severity:         severity,
		Diagnosis:        diag,
		ReasoningContent: strings.TrimSpace(reasoning),
	}

	if proposal.RunbookID == "" {
		return nil, errors.New("ai proposer: proposal missing runbook_id")
	}
	if proposal.TargetResource == "" {
		return nil, errors.New("ai proposer: proposal missing target_resource")
	}

	// Validate deterministic runbook catalog membership
	if !isValidRunbookID(proposal.RunbookID) {
		return nil, fmt.Errorf("ai proposer: unrecognized or unauthorized runbook %q proposed by model", proposal.RunbookID)
	}

	return proposal, nil
}

// normalizeRunbookID canonicalizes aliases and variations into official catalog IDs.
func normalizeRunbookID(id string) string {
	clean := strings.TrimSpace(id)
	switch strings.ToUpper(clean) {
	case "RBK-DISK-001", "DISK_CLEANUP_VAR_LOG", "DISK_LOG_DRAIN":
		return RunbookDiskCleanup
	case "RBK-PROC-001", "SERVICE_DEADLOCK_RESTART", "SERVICE_HANG_RECOVERY":
		return RunbookProcessHang
	case "RBK-TLS-001", "TLS_CERT_RENEW_INTERNAL", "TLS_CERT_ROTATION", "TLS_CERT_RELOAD":
		return RunbookTLSRotation
	case "RBK-CFG-001", "CONFIG_ROLLBACK":
		return RunbookConfigRollback
	default:
		return strings.ToUpper(clean)
	}
}

// isValidRunbookID asserts whether the runbook ID belongs to the authorized production catalog.
func isValidRunbookID(id string) bool {
	switch id {
	case RunbookDiskCleanup, RunbookProcessHang, RunbookTLSRotation, RunbookConfigRollback:
		return true
	default:
		return false
	}
}

// extractThinkTags parses <think>...</think> tags and separates reasoning from content.
func extractThinkTags(content string) (reasoning string, clean string) {
	start := strings.Index(content, "<think>")
	if start != -1 {
		end := strings.Index(content, "</think>")
		if end != -1 && end > start {
			reasoning = strings.TrimSpace(content[start+len("<think>") : end])
			clean = strings.TrimSpace(content[:start] + content[end+len("</think>"):])
			return reasoning, clean
		}
	}
	return "", content
}

// extractJSON extracts a valid JSON object string from raw LLM output,
// handling markdown code fences (```json ... ```), raw JSON, or JSON embedded in conversational text.
func extractJSON(content string) (string, error) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return "", errors.New("response content is empty")
	}

	// 1. Markdown code fences: ```json ... ```
	if idx := strings.Index(trimmed, "```json"); idx != -1 {
		rest := trimmed[idx+len("```json"):]
		if endIdx := strings.Index(rest, "```"); endIdx != -1 {
			candidate := strings.TrimSpace(rest[:endIdx])
			if json.Valid([]byte(candidate)) {
				return candidate, nil
			}
		}
	}

	// 2. Generic code fences: ``` ... ```
	if idx := strings.Index(trimmed, "```"); idx != -1 {
		rest := trimmed[idx+3:]
		if newlineIdx := strings.Index(rest, "\n"); newlineIdx != -1 && newlineIdx < 10 {
			rest = rest[newlineIdx+1:]
		}
		if endIdx := strings.Index(rest, "```"); endIdx != -1 {
			candidate := strings.TrimSpace(rest[:endIdx])
			if json.Valid([]byte(candidate)) {
				return candidate, nil
			}
		}
	}

	// 3. Raw standalone JSON object
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") && json.Valid([]byte(trimmed)) {
		return trimmed, nil
	}

	// 4. Substring from first '{' to last '}'
	firstBrace := strings.Index(trimmed, "{")
	lastBrace := strings.LastIndex(trimmed, "}")
	if firstBrace != -1 && lastBrace != -1 && lastBrace > firstBrace {
		candidate := strings.TrimSpace(trimmed[firstBrace : lastBrace+1])
		if json.Valid([]byte(candidate)) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("unable to extract valid JSON proposal from LLM output: %q", trimmed)
}
