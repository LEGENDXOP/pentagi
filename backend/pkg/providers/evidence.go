package providers

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// maxEvidenceBodySize is the maximum size for request/response bodies stored as evidence.
	// Bodies exceeding this limit are truncated to prevent memory bloat.
	maxEvidenceBodySize = 4 * 1024 // 4KB

	// Evidence types
	EvidenceTypeHTTP     = "http"
	EvidenceTypeTerminal = "terminal"
	EvidenceTypeFile     = "file"
)

// Evidence represents a captured piece of evidence for a penetration testing finding.
// It can hold HTTP request/response pairs, terminal command output, or file-based evidence.
type Evidence struct {
	FindingID  string        `json:"finding_id"`
	Type       string        `json:"type"` // "http", "terminal", "file"
	Request    *HTTPRequest  `json:"request,omitempty"`
	Response   *HTTPResponse `json:"response,omitempty"`
	Command    string        `json:"command,omitempty"`
	Output     string        `json:"output,omitempty"` // truncated to maxEvidenceBodySize
	Timestamp  time.Time     `json:"timestamp"`
	ReproSteps []string      `json:"repro_steps"`
}

// HTTPRequest captures the essential fields of an outbound HTTP request.
type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

// HTTPResponse captures the essential fields of an HTTP response.
type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"` // truncated to maxEvidenceBodySize
}

// EvidenceStore is a thread-safe in-memory store for captured evidence,
// keyed by finding ID. Multiple pieces of evidence can be associated with
// a single finding (e.g., multiple requests proving the same vulnerability).
type EvidenceStore struct {
	mu        sync.RWMutex
	evidences map[string][]Evidence // findingID → evidences
}

// NewEvidenceStore creates a new, empty EvidenceStore ready for use.
func NewEvidenceStore() *EvidenceStore {
	return &EvidenceStore{
		evidences: make(map[string][]Evidence),
	}
}

// Add appends an evidence item to the store. If the finding ID is empty,
// the evidence is stored under the key "_unassigned" for later association.
func (es *EvidenceStore) Add(e Evidence) {
	es.mu.Lock()
	defer es.mu.Unlock()

	key := e.FindingID
	if key == "" {
		key = "_unassigned"
	}

	// Truncate output/body fields to prevent memory bloat
	e.Output = truncateString(e.Output, maxEvidenceBodySize)
	if e.Request != nil {
		e.Request.Body = truncateString(e.Request.Body, maxEvidenceBodySize)
	}
	if e.Response != nil {
		e.Response.Body = truncateString(e.Response.Body, maxEvidenceBodySize)
	}

	es.evidences[key] = append(es.evidences[key], e)
}

// GetForFinding returns all evidence items associated with a specific finding ID.
// Returns nil if no evidence exists for the given finding.
func (es *EvidenceStore) GetForFinding(findingID string) []Evidence {
	es.mu.RLock()
	defer es.mu.RUnlock()

	result := make([]Evidence, len(es.evidences[findingID]))
	copy(result, es.evidences[findingID])
	return result
}

// GetAll returns a snapshot of all stored evidence, keyed by finding ID.
func (es *EvidenceStore) GetAll() map[string][]Evidence {
	es.mu.RLock()
	defer es.mu.RUnlock()

	result := make(map[string][]Evidence, len(es.evidences))
	for k, v := range es.evidences {
		items := make([]Evidence, len(v))
		copy(items, v)
		result[k] = items
	}
	return result
}

// FormatForReport produces a human-readable summary of all stored evidence,
// suitable for inclusion in a penetration testing report.
func (es *EvidenceStore) FormatForReport() string {
	es.mu.RLock()
	defer es.mu.RUnlock()

	if len(es.evidences) == 0 {
		return "No evidence captured."
	}

	var sb strings.Builder
	sb.WriteString("═══════════════════════════════════════════\n")
	sb.WriteString("           EVIDENCE SNAPSHOTS\n")
	sb.WriteString("═══════════════════════════════════════════\n\n")

	evidenceNum := 0
	for findingID, items := range es.evidences {
		for _, e := range items {
			evidenceNum++
			sb.WriteString(fmt.Sprintf("── Evidence #%d ──\n", evidenceNum))
			if findingID != "_unassigned" {
				sb.WriteString(fmt.Sprintf("Finding:   %s\n", findingID))
			}
			sb.WriteString(fmt.Sprintf("Type:      %s\n", e.Type))
			sb.WriteString(fmt.Sprintf("Timestamp: %s\n", e.Timestamp.Format(time.RFC3339)))

			if e.Request != nil {
				sb.WriteString("\n--- REQUEST ---\n")
				sb.WriteString(fmt.Sprintf("%s %s\n", e.Request.Method, e.Request.URL))
				for k, v := range e.Request.Headers {
					sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
				}
				if e.Request.Body != "" {
					sb.WriteString(fmt.Sprintf("\n%s\n", e.Request.Body))
				}
			}

			if e.Response != nil {
				sb.WriteString("\n--- RESPONSE ---\n")
				sb.WriteString(fmt.Sprintf("HTTP %d\n", e.Response.StatusCode))
				for k, v := range e.Response.Headers {
					sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
				}
				if e.Response.Body != "" {
					sb.WriteString(fmt.Sprintf("\n%s\n", e.Response.Body))
				}
			}

			if e.Command != "" {
				sb.WriteString(fmt.Sprintf("\nCommand: %s\n", e.Command))
			}
			if e.Output != "" {
				sb.WriteString(fmt.Sprintf("\nOutput:\n%s\n", e.Output))
			}

			if len(e.ReproSteps) > 0 {
				sb.WriteString("\n--- REPRODUCTION STEPS ---\n")
				for i, step := range e.ReproSteps {
					sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
				}
			}

			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// ---------------------------------------------------------------------------
// HTTP Output Parsers
// ---------------------------------------------------------------------------

// curlVerboseRequestLine matches lines like: > GET /path HTTP/1.1
var curlVerboseRequestLine = regexp.MustCompile(`^>\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/`)

// curlVerboseResponseLine matches lines like: < HTTP/1.1 200 OK
var curlVerboseResponseLine = regexp.MustCompile(`^<\s+HTTP/[\d.]+\s+(\d{3})`)

// curlVerboseRequestHeader matches lines like: > Host: example.com
var curlVerboseRequestHeader = regexp.MustCompile(`^>\s+([^:]+):\s*(.+)$`)

// curlVerboseResponseHeader matches lines like: < Content-Type: text/html
var curlVerboseResponseHeader = regexp.MustCompile(`^<\s+([^:]+):\s*(.+)$`)

// curlConnectLine matches SSL/TLS verbose lines and connection info we want to skip
var curlSSLLine = regexp.MustCompile(`^\*\s+(SSL|TLS|ALPN|CAfile|CApath|subject:|issuer:|expire|subjectAlt|Connected to|Trying|TCP_NODELAY|connect to)`)

// curlURLLine matches the URL from "Connected to <host>" or the command itself
var curlConnectedTo = regexp.MustCompile(`^\*\s+Connected to\s+(\S+)\s+`)

// ParseCurlVerbose parses the stderr output of `curl -v` into structured
// HTTPRequest and HTTPResponse objects. It handles HTTPS connections by
// skipping SSL/TLS negotiation lines.
//
// Returns an error if no valid request or response line is found.
func ParseCurlVerbose(output string) (*HTTPRequest, *HTTPResponse, error) {
	lines := strings.Split(output, "\n")

	req := &HTTPRequest{
		Headers: make(map[string]string),
	}
	resp := &HTTPResponse{
		Headers: make(map[string]string),
	}

	var (
		foundRequest  bool
		foundResponse bool
		inBody        bool
		bodyLines     []string
		connectedHost string
	)

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")

		// Skip SSL/TLS verbose lines
		if curlSSLLine.MatchString(line) {
			// But extract connected host for URL construction
			if m := curlConnectedTo.FindStringSubmatch(line); len(m) > 1 {
				connectedHost = m[1]
			}
			continue
		}

		// Skip empty verbose markers
		if line == ">" || line == "<" || line == "* " {
			continue
		}

		// Parse request line: > GET /path HTTP/1.1
		if m := curlVerboseRequestLine.FindStringSubmatch(line); len(m) > 2 {
			req.Method = m[1]
			req.URL = m[2] // path component; we'll reconstruct full URL below
			foundRequest = true
			inBody = false
			continue
		}

		// Parse request headers: > Header: Value
		if foundRequest && !foundResponse {
			if m := curlVerboseRequestHeader.FindStringSubmatch(line); len(m) > 2 {
				headerName := strings.TrimSpace(m[1])
				headerValue := strings.TrimSpace(m[2])
				req.Headers[headerName] = headerValue
				if strings.EqualFold(headerName, "Host") && connectedHost == "" {
					connectedHost = headerValue
				}
				continue
			}
		}

		// Parse response status line: < HTTP/1.1 200 OK
		if m := curlVerboseResponseLine.FindStringSubmatch(line); len(m) > 1 {
			code, err := strconv.Atoi(m[1])
			if err == nil {
				resp.StatusCode = code
			}
			foundResponse = true
			inBody = false
			continue
		}

		// Parse response headers: < Header: Value
		if foundResponse && !inBody {
			if m := curlVerboseResponseHeader.FindStringSubmatch(line); len(m) > 2 {
				resp.Headers[strings.TrimSpace(m[1])] = strings.TrimSpace(m[2])
				continue
			}

			// Empty "<" line or non-header line after response headers signals body start
			if strings.HasPrefix(line, "<") || line == "" {
				if foundResponse && len(resp.Headers) > 0 {
					inBody = true
				}
				continue
			}
		}

		// Collect body lines (everything after headers that isn't a verbose marker)
		if inBody && !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, "{") {
			// Actually, body lines can start with anything — just exclude curl verbose markers
		}
		if inBody && !strings.HasPrefix(line, "* ") {
			bodyLines = append(bodyLines, rawLine)
		}
	}

	if !foundRequest && !foundResponse {
		return nil, nil, fmt.Errorf("no valid curl verbose request/response found in output")
	}

	// Reconstruct full URL if we only have a path
	if req.URL != "" && !strings.HasPrefix(req.URL, "http") {
		scheme := "http"
		if strings.Contains(output, "SSL connection") || strings.Contains(output, "TLS") ||
			strings.Contains(output, "HTTPS") || strings.Contains(output, "port 443") {
			scheme = "https"
		}
		host := connectedHost
		if h, ok := req.Headers["Host"]; ok && host == "" {
			host = h
		}
		if host != "" {
			req.URL = fmt.Sprintf("%s://%s%s", scheme, host, req.URL)
		}
	}

	// Set response body
	if len(bodyLines) > 0 {
		body := strings.Join(bodyLines, "\n")
		resp.Body = truncateString(strings.TrimSpace(body), maxEvidenceBodySize)
	}

	var reqPtr *HTTPRequest
	var respPtr *HTTPResponse
	if foundRequest {
		reqPtr = req
	}
	if foundResponse {
		respPtr = resp
	}

	return reqPtr, respPtr, nil
}

// httpieStatusLine matches HTTPie output status lines like: HTTP/1.1 200 OK
var httpieStatusLine = regexp.MustCompile(`^HTTP/[\d.]+\s+(\d{3})`)

// httpieHeaderLine matches HTTPie header output like: Content-Type: application/json
var httpieHeaderLine = regexp.MustCompile(`^([A-Za-z][\w-]*)\s*:\s*(.+)$`)

// ParseHTTPieOutput parses HTTPie's default (prettified) output into structured
// HTTPRequest and HTTPResponse objects. HTTPie by default shows the response
// headers and body. With --print=HhBb it also shows the request.
//
// Returns an error if no valid response status line is found.
func ParseHTTPieOutput(output string) (*HTTPRequest, *HTTPResponse, error) {
	lines := strings.Split(output, "\n")

	req := &HTTPRequest{
		Headers: make(map[string]string),
	}
	resp := &HTTPResponse{
		Headers: make(map[string]string),
	}

	var (
		foundResponse   bool
		inResponseHdrs  bool
		inRequestHdrs   bool
		inBody          bool
		bodyLines       []string
		requestFound    bool
		seenBlankInHdrs bool
	)

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")

		// Detect request line from HTTPie --print=Hh output
		// Format: GET /path HTTP/1.1  (no > prefix like curl)
		if !foundResponse && !requestFound {
			parts := strings.Fields(line)
			if len(parts) >= 2 && isHTTPMethod(parts[0]) {
				req.Method = parts[0]
				req.URL = parts[1]
				requestFound = true
				inRequestHdrs = true
				continue
			}
		}

		// Parse request headers (before response)
		if inRequestHdrs && !foundResponse {
			if strings.TrimSpace(line) == "" {
				inRequestHdrs = false
				seenBlankInHdrs = true
				continue
			}
			if m := httpieHeaderLine.FindStringSubmatch(line); len(m) > 2 {
				req.Headers[strings.TrimSpace(m[1])] = strings.TrimSpace(m[2])
				continue
			}
		}

		// Parse response status line
		if m := httpieStatusLine.FindStringSubmatch(line); len(m) > 1 {
			code, err := strconv.Atoi(m[1])
			if err == nil {
				resp.StatusCode = code
			}
			foundResponse = true
			inResponseHdrs = true
			inBody = false
			_ = seenBlankInHdrs
			continue
		}

		// Parse response headers
		if inResponseHdrs && !inBody {
			if strings.TrimSpace(line) == "" {
				inResponseHdrs = false
				inBody = true
				continue
			}
			if m := httpieHeaderLine.FindStringSubmatch(line); len(m) > 2 {
				resp.Headers[strings.TrimSpace(m[1])] = strings.TrimSpace(m[2])
				continue
			}
		}

		// Collect body
		if inBody {
			bodyLines = append(bodyLines, rawLine)
		}
	}

	if !foundResponse {
		return nil, nil, fmt.Errorf("no valid HTTPie response found in output")
	}

	if len(bodyLines) > 0 {
		body := strings.Join(bodyLines, "\n")
		resp.Body = truncateString(strings.TrimSpace(body), maxEvidenceBodySize)
	}

	var reqPtr *HTTPRequest
	if requestFound {
		reqPtr = req
	}

	return reqPtr, resp, nil
}

// DetectAndParseHTTP examines a command string and its output to determine
// if it contains parseable HTTP traffic. It supports curl -v and HTTPie output.
// Returns nil if no HTTP evidence can be extracted.
func DetectAndParseHTTP(command, output string) *Evidence {
	if output == "" {
		return nil
	}

	var (
		req *HTTPRequest
		resp *HTTPResponse
		err  error
	)

	// Detect curl -v (or --verbose) usage
	if isCurlVerbose(command) {
		req, resp, err = ParseCurlVerbose(output)
		if err != nil {
			return nil
		}
	} else if isHTTPieCommand(command) {
		req, resp, err = ParseHTTPieOutput(output)
		if err != nil {
			return nil
		}
	} else {
		// Not a recognized HTTP command
		return nil
	}

	if req == nil && resp == nil {
		return nil
	}

	// Build reproduction steps from the command
	reproSteps := buildReproSteps(command)

	evidence := &Evidence{
		Type:       EvidenceTypeHTTP,
		Request:    req,
		Response:   resp,
		Command:    command,
		Output:     truncateString(output, maxEvidenceBodySize),
		Timestamp:  time.Now().UTC(),
		ReproSteps: reproSteps,
	}

	return evidence
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// truncateString truncates a string to maxLen bytes. If truncated, it appends
// a marker indicating the original size.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("\n\n[TRUNCATED: original size %d bytes]", len(s))
}

// isCurlVerbose checks if a command string is a curl invocation using -v or --verbose.
func isCurlVerbose(command string) bool {
	if !strings.Contains(command, "curl") {
		return false
	}
	// Check for -v flag (possibly combined like -vvv, -sv, -vk, etc.)
	// or --verbose flag
	parts := strings.Fields(command)
	for _, p := range parts {
		if p == "--verbose" {
			return true
		}
		// Match short flags containing 'v' like -v, -vvv, -sv, -kv, etc.
		if strings.HasPrefix(p, "-") && !strings.HasPrefix(p, "--") && strings.Contains(p, "v") {
			return true
		}
	}
	return false
}

// isHTTPieCommand checks if a command string is an HTTPie invocation.
func isHTTPieCommand(command string) bool {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false
	}
	// HTTPie binary is "http" or "https"
	base := parts[0]
	return base == "http" || base == "https" || base == "httpie"
}

// isHTTPMethod returns true if the string is a valid HTTP method.
func isHTTPMethod(s string) bool {
	switch strings.ToUpper(s) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}

// buildReproSteps generates reproduction steps from a curl/httpie command.
func buildReproSteps(command string) []string {
	steps := []string{}

	// Extract the target URL from the command
	targetURL := extractURL(command)

	if isCurlVerbose(command) {
		steps = append(steps, fmt.Sprintf("Execute the following curl command:\n  %s", command))
		if targetURL != "" {
			steps = append(steps, fmt.Sprintf("Target URL: %s", targetURL))
		}
		steps = append(steps, "Observe the HTTP request and response in verbose output")
		steps = append(steps, "Verify the vulnerability is confirmed in the response")
	} else if isHTTPieCommand(command) {
		steps = append(steps, fmt.Sprintf("Execute the following HTTPie command:\n  %s", command))
		if targetURL != "" {
			steps = append(steps, fmt.Sprintf("Target URL: %s", targetURL))
		}
		steps = append(steps, "Observe the HTTP response")
		steps = append(steps, "Verify the vulnerability is confirmed in the response")
	} else {
		steps = append(steps, fmt.Sprintf("Execute:\n  %s", command))
	}

	return steps
}

// extractURL tries to find a URL in a command string.
func extractURL(command string) string {
	parts := strings.Fields(command)
	for _, p := range parts {
		// Remove surrounding quotes
		p = strings.Trim(p, "'\"")
		if _, err := url.ParseRequestURI(p); err == nil {
			if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
				return p
			}
		}
	}
	return ""
}
