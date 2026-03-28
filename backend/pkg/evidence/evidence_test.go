package evidence

import (
	"strings"
	"testing"
	"time"
)

func TestNewEvidenceStore(t *testing.T) {
	store := NewEvidenceStore()
	if store == nil {
		t.Fatal("NewEvidenceStore returned nil")
	}
	if store.evidences == nil {
		t.Fatal("evidences map not initialized")
	}
}

func TestEvidenceStore_AddAndGet(t *testing.T) {
	store := NewEvidenceStore()

	e := Evidence{
		FindingID: "F001",
		Type:      EvidenceTypeHTTP,
		Command:   "curl -v http://target/api",
		Timestamp: time.Now(),
	}
	store.Add(e)

	results := store.GetForFinding("F001")
	if len(results) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(results))
	}
	if results[0].FindingID != "F001" {
		t.Errorf("expected finding ID F001, got %s", results[0].FindingID)
	}
}

func TestEvidenceStore_AddUnassigned(t *testing.T) {
	store := NewEvidenceStore()

	e := Evidence{
		Type:    EvidenceTypeTerminal,
		Command: "nmap -sV target",
	}
	store.Add(e)

	results := store.GetForFinding("_unassigned")
	if len(results) != 1 {
		t.Fatalf("expected 1 unassigned evidence, got %d", len(results))
	}
}

func TestEvidenceStore_GetAll(t *testing.T) {
	store := NewEvidenceStore()

	store.Add(Evidence{FindingID: "F001", Type: EvidenceTypeHTTP})
	store.Add(Evidence{FindingID: "F001", Type: EvidenceTypeHTTP})
	store.Add(Evidence{FindingID: "F002", Type: EvidenceTypeTerminal})

	all := store.GetAll()
	if len(all) != 2 {
		t.Fatalf("expected 2 finding IDs, got %d", len(all))
	}
	if len(all["F001"]) != 2 {
		t.Errorf("expected 2 evidences for F001, got %d", len(all["F001"]))
	}
	if len(all["F002"]) != 1 {
		t.Errorf("expected 1 evidence for F002, got %d", len(all["F002"]))
	}
}

func TestEvidenceStore_TruncatesOnAdd(t *testing.T) {
	store := NewEvidenceStore()

	bigBody := strings.Repeat("A", 10*1024) // 10KB
	e := Evidence{
		FindingID: "F001",
		Type:      EvidenceTypeHTTP,
		Output:    bigBody,
		Response: &HTTPResponse{
			StatusCode: 200,
			Headers:    map[string]string{},
			Body:       bigBody,
		},
		Request: &HTTPRequest{
			Method:  "POST",
			URL:     "http://target/upload",
			Headers: map[string]string{},
			Body:    bigBody,
		},
	}
	store.Add(e)

	results := store.GetForFinding("F001")
	if len(results[0].Output) >= 10*1024 {
		t.Errorf("output was not truncated: len=%d", len(results[0].Output))
	}
	if len(results[0].Response.Body) >= 10*1024 {
		t.Errorf("response body was not truncated: len=%d", len(results[0].Response.Body))
	}
	if len(results[0].Request.Body) >= 10*1024 {
		t.Errorf("request body was not truncated: len=%d", len(results[0].Request.Body))
	}
	if !strings.Contains(results[0].Output, "[TRUNCATED:") {
		t.Error("truncated output should contain truncation marker")
	}
}

func TestEvidenceStore_FormatForReport(t *testing.T) {
	store := NewEvidenceStore()

	store.Add(Evidence{
		FindingID: "F001",
		Type:      EvidenceTypeHTTP,
		Request: &HTTPRequest{
			Method:  "GET",
			URL:     "http://target/api/users/1",
			Headers: map[string]string{"Host": "target"},
		},
		Response: &HTTPResponse{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"id":1,"name":"admin"}`,
		},
		Timestamp:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		ReproSteps: []string{"Run curl -v http://target/api/users/1", "Observe 200 response with user data"},
	})

	report := store.FormatForReport()
	if !strings.Contains(report, "EVIDENCE SNAPSHOTS") {
		t.Error("report should contain header")
	}
	if !strings.Contains(report, "GET http://target/api/users/1") {
		t.Error("report should contain request line")
	}
	if !strings.Contains(report, "HTTP 200") {
		t.Error("report should contain response status")
	}
	if !strings.Contains(report, "REPRODUCTION STEPS") {
		t.Error("report should contain repro steps")
	}
}

func TestEvidenceStore_FormatForReport_Empty(t *testing.T) {
	store := NewEvidenceStore()
	report := store.FormatForReport()
	if report != "No evidence captured." {
		t.Errorf("unexpected empty report: %s", report)
	}
}

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

const sampleCurlVerbose = `*   Trying 192.168.1.100:80...
* TCP_NODELAY set
* Connected to 192.168.1.100 (192.168.1.100) port 80 (#0)
> GET /api/users/1 HTTP/1.1
> Host: 192.168.1.100
> User-Agent: curl/7.68.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Content-Type: application/json
< Content-Length: 45
< 
{"id":1,"username":"admin","role":"superuser"}
* Connection #0 to host 192.168.1.100 left intact`

func TestParseCurlVerbose_Basic(t *testing.T) {
	req, resp, err := ParseCurlVerbose(sampleCurlVerbose)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req == nil {
		t.Fatal("request is nil")
	}
	if req.Method != "GET" {
		t.Errorf("expected GET, got %s", req.Method)
	}
	if !strings.Contains(req.URL, "/api/users/1") {
		t.Errorf("expected URL containing /api/users/1, got %s", req.URL)
	}
	if req.Headers["Host"] != "192.168.1.100" {
		t.Errorf("expected Host header 192.168.1.100, got %s", req.Headers["Host"])
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Headers["Content-Type"] != "application/json" {
		t.Errorf("expected application/json, got %s", resp.Headers["Content-Type"])
	}
	if !strings.Contains(resp.Body, "admin") {
		t.Errorf("expected body containing 'admin', got %s", resp.Body)
	}
}

const sampleCurlVerboseHTTPS = `*   Trying 10.0.0.1:443...
* TCP_NODELAY set
* Connected to target.local (10.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* SSL connection using TLSv1.3
* subject: CN=target.local
* issuer: CN=target.local
* SSL certificate verify result: self-signed certificate (18), continuing anyway.
> POST /login HTTP/1.1
> Host: target.local
> Content-Type: application/x-www-form-urlencoded
> Content-Length: 29
> 
< HTTP/1.1 302 Found
< Location: /dashboard
< Set-Cookie: session=abc123; HttpOnly
< 
* Connection #0 to host target.local left intact`

func TestParseCurlVerbose_HTTPS(t *testing.T) {
	req, resp, err := ParseCurlVerbose(sampleCurlVerboseHTTPS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req == nil {
		t.Fatal("request is nil")
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	if !strings.Contains(req.URL, "https://") {
		t.Errorf("expected HTTPS URL, got %s", req.URL)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
}

func TestParseCurlVerbose_NoOutput(t *testing.T) {
	_, _, err := ParseCurlVerbose("")
	if err == nil {
		t.Error("expected error for empty output")
	}
}

func TestParseCurlVerbose_Malformed(t *testing.T) {
	_, _, err := ParseCurlVerbose("just some random text\nno curl output here")
	if err == nil {
		t.Error("expected error for malformed output")
	}
}

const sampleHTTPieOutput = `HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 23

{"status":"vulnerable"}`

func TestParseHTTPieOutput_Basic(t *testing.T) {
	_, resp, err := ParseHTTPieOutput(sampleHTTPieOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Headers["Content-Type"] != "application/json" {
		t.Errorf("expected application/json, got %s", resp.Headers["Content-Type"])
	}
	if !strings.Contains(resp.Body, "vulnerable") {
		t.Errorf("expected body with 'vulnerable', got %s", resp.Body)
	}
}

func TestParseHTTPieOutput_NoResponse(t *testing.T) {
	_, _, err := ParseHTTPieOutput("just regular text output")
	if err == nil {
		t.Error("expected error for non-HTTPie output")
	}
}

// ---------------------------------------------------------------------------
// DetectAndParseHTTP tests
// ---------------------------------------------------------------------------

func TestDetectAndParseHTTP_CurlVerbose(t *testing.T) {
	evidence := DetectAndParseHTTP("curl -v http://target/api/users/1", sampleCurlVerbose)
	if evidence == nil {
		t.Fatal("expected evidence, got nil")
	}
	if evidence.Type != EvidenceTypeHTTP {
		t.Errorf("expected type http, got %s", evidence.Type)
	}
	if evidence.Request == nil {
		t.Error("expected request to be parsed")
	}
	if evidence.Response == nil {
		t.Error("expected response to be parsed")
	}
	if len(evidence.ReproSteps) == 0 {
		t.Error("expected repro steps")
	}
}

func TestDetectAndParseHTTP_CurlWithoutVerbose(t *testing.T) {
	evidence := DetectAndParseHTTP("curl http://target/api", "some output")
	if evidence != nil {
		t.Error("expected nil for non-verbose curl")
	}
}

func TestDetectAndParseHTTP_HTTPie(t *testing.T) {
	evidence := DetectAndParseHTTP("http GET http://target/api", sampleHTTPieOutput)
	if evidence == nil {
		t.Fatal("expected evidence, got nil")
	}
	if evidence.Type != EvidenceTypeHTTP {
		t.Errorf("expected type http, got %s", evidence.Type)
	}
}

func TestDetectAndParseHTTP_NonHTTPCommand(t *testing.T) {
	evidence := DetectAndParseHTTP("nmap -sV 192.168.1.1", "Nmap scan report...")
	if evidence != nil {
		t.Error("expected nil for non-HTTP command")
	}
}

func TestDetectAndParseHTTP_EmptyOutput(t *testing.T) {
	evidence := DetectAndParseHTTP("curl -v http://target", "")
	if evidence != nil {
		t.Error("expected nil for empty output")
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestIsCurlVerbose(t *testing.T) {
	tests := []struct {
		cmd    string
		expect bool
	}{
		{"curl -v http://target", true},
		{"curl --verbose http://target", true},
		{"curl -vvv http://target", true},
		{"curl -kv http://target", true},
		{"curl -sv http://target", true},
		{"curl http://target", false},
		{"curl -s http://target", false},
		{"wget http://target", false},
		{"curl -o /dev/null -v http://target", true},
	}

	for _, tt := range tests {
		result := isCurlVerbose(tt.cmd)
		if result != tt.expect {
			t.Errorf("isCurlVerbose(%q) = %v, want %v", tt.cmd, result, tt.expect)
		}
	}
}

func TestIsHTTPieCommand(t *testing.T) {
	tests := []struct {
		cmd    string
		expect bool
	}{
		{"http GET http://target", true},
		{"https GET http://target", true},
		{"httpie GET http://target", true},
		{"curl http://target", false},
		{"wget http://target", false},
	}

	for _, tt := range tests {
		result := isHTTPieCommand(tt.cmd)
		if result != tt.expect {
			t.Errorf("isHTTPieCommand(%q) = %v, want %v", tt.cmd, result, tt.expect)
		}
	}
}

func TestTruncateString(t *testing.T) {
	short := "hello"
	result := truncateString(short, 100)
	if result != short {
		t.Errorf("short string should not be truncated")
	}

	long := strings.Repeat("X", 5000)
	result = truncateString(long, 4096)
	if !strings.Contains(result, "[TRUNCATED:") {
		t.Error("truncated string should contain marker")
	}
	// The truncated portion should be exactly 4096 bytes before the marker
	if !strings.HasPrefix(result, strings.Repeat("X", 4096)) {
		t.Error("truncated content should preserve first 4096 bytes")
	}
}

func TestExtractURL(t *testing.T) {
	tests := []struct {
		cmd    string
		expect string
	}{
		{"curl -v http://target/api", "http://target/api"},
		{"curl -v https://target:8443/path", "https://target:8443/path"},
		{"curl -v -H 'Auth: Bearer x' http://target/api/users", "http://target/api/users"},
		{"nmap -sV 192.168.1.1", ""},
	}

	for _, tt := range tests {
		result := extractURL(tt.cmd)
		if result != tt.expect {
			t.Errorf("extractURL(%q) = %q, want %q", tt.cmd, result, tt.expect)
		}
	}
}
