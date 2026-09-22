package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ServiceConfig defines a supervised service for the autonomous poller.
type ServiceConfig struct {
	Name      string `json:"name" yaml:"name"`
	HealthURL string `json:"health_url" yaml:"health_url"`
	PIDFile   string `json:"pid_file" yaml:"pid_file"`
	Port      int    `json:"port" yaml:"port"`
}

// PathConfig defines a filesystem volume threshold for the autonomous poller.
type PathConfig struct {
	Path       string  `json:"path" yaml:"path"`
	MinFreePct float64 `json:"min_free_pct" yaml:"min_free_pct"`
}

// Config encapsulates the complete runtime daemon configuration.
type Config struct {
	UnixSocketPath    string          `json:"unix_socket_path" yaml:"unix_socket_path"`
	HTTPAddr          string          `json:"http_addr" yaml:"http_addr"`
	HMACSecret        string          `json:"hmac_secret" yaml:"hmac_secret"`
	AuditLogPath      string          `json:"audit_log_path" yaml:"audit_log_path"`
	LockDir           string          `json:"lock_dir" yaml:"lock_dir"`
	JournalDir        string          `json:"journal_dir" yaml:"journal_dir"`
	DampingStateFile  string          `json:"damping_state_file" yaml:"damping_state_file"`
	HostUUID          string          `json:"host_uuid" yaml:"host_uuid"`
	PollInterval      time.Duration   `json:"poll_interval" yaml:"poll_interval"`
	MonitoredServices []ServiceConfig `json:"monitored_services" yaml:"monitored_services"`
	MonitoredPaths    []PathConfig    `json:"monitored_paths" yaml:"monitored_paths"`
}

// DefaultConfig returns a production configuration with sensible defaults.
// Automatically adjusts paths if executing as root or unprivileged user.
func DefaultConfig() *Config {
	isRoot := os.Geteuid() == 0

	socketPath := "/tmp/remediation.sock"
	lockDir := "/tmp/remediation-locks/"
	auditLog := "/tmp/remediation-audit.wal"
	journalDir := "/tmp/remediation-journal/"
	dampingFile := "/tmp/remediation-damping.json"

	if isRoot {
		socketPath = "/run/remediation.sock"
		lockDir = "/var/run/remediation/"
		auditLog = "/var/lib/autonomous-remediation/audit/audit.wal"
		journalDir = "/var/lib/autonomous-remediation/journal/"
		dampingFile = "/var/lib/autonomous-remediation/damping.json"
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "remediation-daemon-node"
	}

	return &Config{
		UnixSocketPath:   socketPath,
		HTTPAddr:         "127.0.0.1:9443",
		HMACSecret:       "",
		AuditLogPath:     auditLog,
		LockDir:          lockDir,
		JournalDir:       journalDir,
		DampingStateFile: dampingFile,
		HostUUID:         hostname,
		PollInterval:     2 * time.Second,
		MonitoredServices: []ServiceConfig{
			{
				Name:      "ai-gateway",
				HealthURL: "http://127.0.0.1:8080/healthz",
				PIDFile:   "/var/run/ai-gateway.pid",
				Port:      8080,
			},
			{
				Name:      "guardrail-proxy",
				HealthURL: "http://127.0.0.1:8081/healthz",
				PIDFile:   "/var/run/guardrail-proxy.pid",
				Port:      8081,
			},
		},
		MonitoredPaths: []PathConfig{
			{
				Path:       "/var/log",
				MinFreePct: 15.0,
			},
		},
	}
}

// UnmarshalJSON implements custom JSON unmarshaling to handle string or numeric poll_intervals.
func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := &struct {
		*Alias
		RawPollInterval        any `json:"poll_interval"`
		RawPollIntervalSeconds any `json:"poll_interval_seconds"`
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// Parse poll interval if provided
	if aux.RawPollInterval != nil {
		switch v := aux.RawPollInterval.(type) {
		case string:
			d, err := time.ParseDuration(v)
			if err != nil {
				// Try as seconds integer
				if sec, sErr := strconv.Atoi(v); sErr == nil {
					c.PollInterval = time.Duration(sec) * time.Second
				} else {
					return fmt.Errorf("invalid poll_interval %q: %w", v, err)
				}
			} else {
				c.PollInterval = d
			}
		case float64:
			c.PollInterval = time.Duration(v) * time.Second
		}
	} else if aux.RawPollIntervalSeconds != nil {
		switch v := aux.RawPollIntervalSeconds.(type) {
		case float64:
			c.PollInterval = time.Duration(v) * time.Second
		case string:
			if sec, err := strconv.Atoi(v); err == nil {
				c.PollInterval = time.Duration(sec) * time.Second
			}
		}
	}

	return nil
}

// LoadConfig reads and parses configuration from a file path.
// If path is empty, DefaultConfig is returned.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	return ParseConfig(data)
}

// ParseConfig decodes raw JSON or basic YAML configuration bytes.
func ParseConfig(data []byte) (*Config, error) {
	cfg := DefaultConfig()

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return cfg, nil
	}

	// If starts with '{', attempt native JSON unmarshaling first
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal([]byte(trimmed), cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
		return cfg, nil
	}

	// Otherwise, parse using our zero-dependency YAML parser
	yamlMap, err := ParseBasicYAML(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	jsonBytes, err := json.Marshal(yamlMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal intermediate YAML map: %w", err)
	}

	if err := json.Unmarshal(jsonBytes, cfg); err != nil {
		return nil, fmt.Errorf("failed to apply parsed YAML to config struct: %w", err)
	}

	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}

	return cfg, nil
}

type lineInfo struct {
	indent int
	text   string
}

// ParseBasicYAML converts standard basic YAML into generic Go maps/slices with zero external dependencies.
func ParseBasicYAML(yamlStr string) (map[string]any, error) {
	var lines []lineInfo
	scanner := bufio.NewScanner(strings.NewReader(yamlStr))
	for scanner.Scan() {
		raw := stripYAMLComment(scanner.Text())
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		lines = append(lines, lineInfo{indent: indent, text: trimmed})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(lines) == 0 {
		return make(map[string]any), nil
	}

	val, _ := parseYAMLBlock(lines, 0, lines[0].indent)
	if m, ok := val.(map[string]any); ok {
		return m, nil
	}
	return nil, errors.New("root YAML block must be a mapping")
}

func stripYAMLComment(line string) string {
	inQuotes := false
	var quoteChar rune
	for i, r := range line {
		if r == '"' || r == '\'' {
			if !inQuotes {
				inQuotes = true
				quoteChar = r
			} else if quoteChar == r {
				inQuotes = false
			}
		} else if r == '#' && !inQuotes {
			return line[:i]
		}
	}
	return line
}

func parseYAMLBlock(lines []lineInfo, idx int, blockIndent int) (any, int) {
	if idx >= len(lines) {
		return nil, idx
	}

	// Check if this block is a list
	if strings.HasPrefix(lines[idx].text, "- ") || lines[idx].text == "-" {
		var list []any
		for idx < len(lines) && lines[idx].indent == blockIndent {
			lineText := lines[idx].text
			if !strings.HasPrefix(lineText, "- ") && lineText != "-" {
				break
			}
			itemText := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(lineText, "-"), " "))
			idx++

			if itemText == "" {
				if idx < len(lines) && lines[idx].indent > blockIndent {
					child, nextIdx := parseYAMLBlock(lines, idx, lines[idx].indent)
					list = append(list, child)
					idx = nextIdx
				} else {
					list = append(list, nil)
				}
			} else if strings.Contains(itemText, ":") {
				parts := strings.SplitN(itemText, ":", 2)
				k := strings.TrimSpace(parts[0])
				vStr := strings.TrimSpace(parts[1])
				itemMap := make(map[string]any)

				if vStr != "" {
					itemMap[k] = parseYAMLValue(vStr)
				} else {
					if idx < len(lines) && lines[idx].indent > blockIndent {
						sub, nextIdx := parseYAMLBlock(lines, idx, lines[idx].indent)
						itemMap[k] = sub
						idx = nextIdx
					}
				}

				// Collect subsequent keys belonging to this list item
				for idx < len(lines) && lines[idx].indent > blockIndent {
					if strings.HasPrefix(lines[idx].text, "- ") {
						break
					}
					if strings.Contains(lines[idx].text, ":") {
						mParts := strings.SplitN(lines[idx].text, ":", 2)
						mk := strings.TrimSpace(mParts[0])
						mvStr := strings.TrimSpace(mParts[1])
						subIndent := lines[idx].indent
						idx++
						if mvStr != "" {
							itemMap[mk] = parseYAMLValue(mvStr)
						} else {
							if idx < len(lines) && lines[idx].indent > subIndent {
								sub, nextIdx := parseYAMLBlock(lines, idx, lines[idx].indent)
								itemMap[mk] = sub
								idx = nextIdx
							}
						}
					} else {
						idx++
					}
				}
				list = append(list, itemMap)
			} else {
				list = append(list, parseYAMLValue(itemText))
			}
		}
		return list, idx
	}

	// Map
	m := make(map[string]any)
	for idx < len(lines) && lines[idx].indent == blockIndent {
		if !strings.Contains(lines[idx].text, ":") {
			idx++
			continue
		}
		parts := strings.SplitN(lines[idx].text, ":", 2)
		k := strings.TrimSpace(parts[0])
		vStr := strings.TrimSpace(parts[1])
		idx++

		if vStr != "" {
			m[k] = parseYAMLValue(vStr)
		} else {
			if idx < len(lines) && lines[idx].indent > blockIndent {
				sub, nextIdx := parseYAMLBlock(lines, idx, lines[idx].indent)
				m[k] = sub
				idx = nextIdx
			} else {
				m[k] = nil
			}
		}
	}
	return m, idx
}

func parseYAMLValue(s string) any {
	s = strings.TrimSpace(s)
	// Quoted strings
	if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
		(strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`)) {
		if len(s) >= 2 {
			return s[1 : len(s)-1]
		}
		return ""
	}

	low := strings.ToLower(s)
	if low == "true" || low == "yes" || low == "on" {
		return true
	}
	if low == "false" || low == "no" || low == "off" {
		return false
	}

	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}

	return s
}
